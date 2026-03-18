package checks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	osvBatchURL   = "https://api.osv.dev/v1/querybatch"
	osvBatchSize  = 999 // OSV batch limit
	osvHTTPTimeout = 30 * time.Second
)

// ── OSV API types ─────────────────────────────────────────────────────────────

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Aliases  []string      `json:"aliases"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"` // CVSS vector string e.g. "CVSS:3.1/AV:N/..."
}

// ── Check ─────────────────────────────────────────────────────────────────────

type CVECheck struct{}

func (c *CVECheck) Name() string { return "cve" }

func (c *CVECheck) Run() ([]CheckResult, error) {
	pkgs := CollectInstalledPackages()
	if len(pkgs) == 0 {
		return []CheckResult{{
			Category:     "cve",
			CheckID:      "cve-scan",
			Title:        "CVE Scan (OSV.dev)",
			Description:  "No package manager detected — scan skipped",
			Severity:     "info",
			Status:       "skipped",
			CurrentValue: "no packages detected",
			CISControl:   "CIS 6.2",
		}}, nil
	}

	// Query OSV in chunks, accumulating per-package vuln lists
	vulnsByPkg := make([][]osvVuln, len(pkgs))
	client := &http.Client{Timeout: osvHTTPTimeout}

	for start := 0; start < len(pkgs); start += osvBatchSize {
		end := start + osvBatchSize
		if end > len(pkgs) {
			end = len(pkgs)
		}
		chunk := pkgs[start:end]

		queries := make([]osvQuery, len(chunk))
		for i, pkg := range chunk {
			queries[i] = osvQuery{
				Package: osvPackage{Name: pkg.Name, Ecosystem: pkg.Ecosystem},
				Version: pkg.Version,
			}
		}

		body, err := json.Marshal(osvBatchRequest{Queries: queries})
		if err != nil {
			continue
		}

		resp, err := client.Post(osvBatchURL, "application/json", bytes.NewReader(body))
		if err != nil {
			// Network unreachable — skip entirely rather than false-failing
			return []CheckResult{{
				Category:     "cve",
				CheckID:      "cve-scan",
				Title:        "CVE Scan (OSV.dev)",
				Description:  "Could not reach OSV.dev — check network connectivity",
				Severity:     "info",
				Status:       "skipped",
				CurrentValue: "OSV.dev unreachable",
				CISControl:   "CIS 6.2",
			}}, nil
		}

		var batchResp osvBatchResponse
		if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		for i, result := range batchResp.Results {
			if start+i < len(vulnsByPkg) {
				vulnsByPkg[start+i] = result.Vulns
			}
		}
	}

	// Build CheckResults — one per vulnerable package
	var results []CheckResult
	for i, vulns := range vulnsByPkg {
		if len(vulns) == 0 {
			continue
		}
		pkg := pkgs[i]

		// Determine highest severity across all vulns for this package
		severity := cveSeverityFromVulns(vulns)

		// Collect CVE IDs (prefer CVE-* aliases over OSV IDs)
		cveIDs := collectCVEIDs(vulns)

		// Truncate to 3 IDs in description to keep output readable
		displayIDs := cveIDs
		extra := ""
		if len(cveIDs) > 3 {
			displayIDs = cveIDs[:3]
			extra = fmt.Sprintf(" +%d more", len(cveIDs)-3)
		}
		description := fmt.Sprintf("%s%s", strings.Join(displayIDs, ", "), extra)

		fixCmd := fmt.Sprintf("apt-get install --only-upgrade -y %s", pkg.Name)
		if pkg.Ecosystem == "Alpine" {
			fixCmd = fmt.Sprintf("apk upgrade %s", pkg.Name)
		}

		results = append(results, CheckResult{
			Category:      "cve",
			CheckID:       fmt.Sprintf("cve-%s", pkg.Name),
			Title:         fmt.Sprintf("Vulnerable: %s", pkg.Name),
			Description:   description,
			Severity:      severity,
			Status:        "fail",
			CurrentValue:  fmt.Sprintf("%s %s", pkg.Name, pkg.Version),
			ExpectedValue: "patched version",
			FixCommand:    fixCmd,
			CISControl:    "CIS 6.2",
		})
	}

	// No vulnerabilities found
	if len(results) == 0 {
		return []CheckResult{{
			Category:      "cve",
			CheckID:       "cve-scan",
			Title:         "CVE Scan (OSV.dev)",
			Description:   fmt.Sprintf("%d packages scanned, no known vulnerabilities found", len(pkgs)),
			Severity:      "critical",
			Status:        "pass",
			CurrentValue:  fmt.Sprintf("%d packages, 0 CVEs", len(pkgs)),
			ExpectedValue: "0 vulnerabilities",
			CISControl:    "CIS 6.2",
		}}, nil
	}

	return results, nil
}

// cveSeverityFromVulns returns the highest severity across all vulns for a package.
// OSV severity.score is a CVSS vector string; we derive severity from the vector components.
func cveSeverityFromVulns(vulns []osvVuln) string {
	highest := "info"
	for _, v := range vulns {
		s := cvssVectorSeverity(v.Severity)
		if severityRank(s) > severityRank(highest) {
			highest = s
		}
	}
	return highest
}

// cvssVectorSeverity maps a CVSS v3 vector string to our severity levels.
// CVSS v3 base score tiers: Critical ≥9.0, High ≥7.0, Medium ≥4.0, Low <4.0
// We derive from vector components without a full CVSS library.
func cvssVectorSeverity(severities []osvSeverity) string {
	for _, s := range severities {
		v := s.Score
		// Network-accessible + high-impact combos → critical
		if strings.Contains(v, "AV:N") &&
			(strings.Contains(v, "C:H") || strings.Contains(v, "I:H") || strings.Contains(v, "A:H")) &&
			strings.Contains(v, "PR:N") {
			return "critical"
		}
		// Any network-accessible with elevated impact → warning
		if strings.Contains(v, "AV:N") &&
			(strings.Contains(v, "C:H") || strings.Contains(v, "I:H") || strings.Contains(v, "A:H")) {
			return "warning"
		}
		// Any CVSS data present without matching above → warning
		if v != "" {
			if severityRank("warning") > severityRank("info") {
				return "warning"
			}
		}
	}
	// Vuln exists but no CVSS data — treat as warning
	return "warning"
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	}
	return 0
}

// collectCVEIDs extracts CVE IDs from vulns, preferring CVE-* over OSV IDs.
func collectCVEIDs(vulns []osvVuln) []string {
	seen := make(map[string]bool)
	var ids []string
	// First pass: collect CVE-* from aliases
	for _, v := range vulns {
		for _, alias := range v.Aliases {
			if strings.HasPrefix(alias, "CVE-") && !seen[alias] {
				seen[alias] = true
				ids = append(ids, alias)
			}
		}
	}
	// Second pass: fall back to OSV IDs for vulns without a CVE alias
	for _, v := range vulns {
		hasCVE := false
		for _, alias := range v.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				hasCVE = true
				break
			}
		}
		if !hasCVE && !seen[v.ID] {
			seen[v.ID] = true
			ids = append(ids, v.ID)
		}
	}
	return ids
}
