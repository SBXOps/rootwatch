package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rootwatch/rootwatch/pkg/checks"
)

// Format options
const (
	FormatTable    = "table"
	FormatJSON     = "json"
	FormatMarkdown = "markdown"
	FormatSARIF    = "sarif"
)

// ScanReport is the structured output of a local scan.
type ScanReport struct {
	Hostname    string               `json:"hostname"`
	OS          string               `json:"os"`
	ScannedAt   time.Time            `json:"scanned_at"`
	DurationMs  int                  `json:"duration_ms"`
	Score       int                  `json:"score"`
	Summary     Summary              `json:"summary"`
	Results     []checks.CheckResult `json:"results"`
}

// Summary holds counts by status/severity.
type Summary struct {
	Total    int `json:"total"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`
	Critical int `json:"critical_failures"`
	Warning  int `json:"warning_failures"`
}

// BuildReport calculates score and summary from raw check results.
func BuildReport(hostname, osStr string, results []checks.CheckResult, durationMs int) ScanReport {
	s := Summary{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case "pass":
			s.Passed++
		case "fail":
			s.Failed++
			if r.Severity == "critical" {
				s.Critical++
			} else if r.Severity == "warning" {
				s.Warning++
			}
		case "skipped", "error":
			s.Skipped++
		}
	}

	score := calculateScore(results)

	return ScanReport{
		Hostname:   hostname,
		OS:         osStr,
		ScannedAt:  time.Now(),
		DurationMs: durationMs,
		Score:      score,
		Summary:    s,
		Results:    results,
	}
}

func calculateScore(results []checks.CheckResult) int {
	if len(results) == 0 {
		return 0
	}

	totalWeight := 0.0
	earned := 0.0

	weights := map[string]float64{
		"critical": 10.0,
		"warning":  3.0,
		"info":     1.0,
	}

	for _, r := range results {
		if r.Status == "skipped" || r.Status == "error" {
			continue
		}
		w := weights[r.Severity]
		if w == 0 {
			w = 1.0
		}
		totalWeight += w
		if r.Status == "pass" {
			earned += w
		}
	}

	if totalWeight == 0 {
		return 100
	}

	score := int((earned / totalWeight) * 100)

	// Hard caps based on critical failures
	criticalFails := 0
	for _, r := range results {
		if r.Status == "fail" && r.Severity == "critical" {
			criticalFails++
		}
	}
	if criticalFails >= 5 && score > 30 {
		score = 30
	} else if criticalFails >= 3 && score > 50 {
		score = 50
	} else if criticalFails >= 1 && score > 65 {
		score = 65
	}

	return score
}

// PrintTable prints a human-readable scan report to stdout.
func PrintTable(r ScanReport) {
	scoreColor := scoreColorCode(r.Score)
	reset := "\033[0m"
	bold := "\033[1m"
	dim := "\033[2m"
	red := "\033[31m"
	yellow := "\033[33m"
	green := "\033[32m"

	fmt.Printf("\n%s  rootwatch scan — %s%s\n", bold, r.Hostname, reset)
	fmt.Printf("%s  %s  ·  %s%s\n\n", dim, r.OS, r.ScannedAt.Format("02 Jan 2006 15:04 MST"), reset)

	// Score banner
	fmt.Printf("  Security Score:  %s%s%d / 100%s\n\n",
		bold, scoreColor, r.Score, reset)

	// Summary row
	fmt.Printf("  %s✓ Passed%s  %-4d   %s✗ Failed%s  %-4d   %sCritical%s  %-4d   %s⊘ Skipped%s  %d\n\n",
		green, reset, r.Summary.Passed,
		red, reset, r.Summary.Failed,
		red, reset, r.Summary.Critical,
		dim, reset, r.Summary.Skipped,
	)

	if r.Summary.Failed == 0 {
		fmt.Printf("  %s✓ All checks passed.%s\n\n", green, reset)
		return
	}

	// Failed checks table
	fmt.Printf("  %sFailed Checks%s\n", bold, reset)
	fmt.Println(strings.Repeat("  ─", 38))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  SEVERITY\tCHECK\tFIX\n")

	// Collect warnings to print after the table (tabwriter can't mid-stream)
	type warnEntry struct{ title, warning string }
	var warnings []warnEntry

	for _, result := range r.Results {
		if result.Status != "fail" {
			continue
		}
		sev := result.Severity
		var sevStr string
		switch sev {
		case "critical":
			sevStr = red + "CRITICAL" + reset
		case "warning":
			sevStr = yellow + "WARNING " + reset
		default:
			sevStr = dim + "INFO    " + reset
		}

		fix := result.FixCommand
		if len(fix) > 60 {
			fix = fix[:57] + "..."
		}
		if fix == "" {
			fix = dim + "see docs" + reset
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\n", sevStr, result.Title, fix)

		if result.FixWarning != "" {
			warnings = append(warnings, warnEntry{result.Title, result.FixWarning})
		}
	}
	w.Flush()

	for _, we := range warnings {
		fmt.Printf("  %s⚠  %s: %s%s\n", yellow, we.title, we.warning, reset)
	}

	fmt.Println()
	fmt.Printf("  %sTip:%s  run with --output json for full fix commands and expected values.\n", dim, reset)
	fmt.Printf("  %s  Continuous monitoring + audit-ready hardening reports → https://rootwatch.net%s\n\n", dim, reset)
}

// PrintJSON writes the full report as indented JSON.
func PrintJSON(r ScanReport) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(r) //nolint:errcheck
}

// PrintMarkdown writes the report in Markdown format.
func PrintMarkdown(r ScanReport) {
	fmt.Printf("# Rootwatch Security Scan — %s\n\n", r.Hostname)
	fmt.Printf("**OS:** %s  \n", r.OS)
	fmt.Printf("**Scanned:** %s  \n", r.ScannedAt.Format(time.RFC3339))
	fmt.Printf("**Score:** %d / 100  \n\n", r.Score)

	fmt.Printf("## Summary\n\n")
	fmt.Printf("| Passed | Failed | Critical Failures | Skipped |\n")
	fmt.Printf("|--------|--------|-------------------|---------|\n")
	fmt.Printf("| %d | %d | %d | %d |\n\n",
		r.Summary.Passed, r.Summary.Failed, r.Summary.Critical, r.Summary.Skipped)

	if r.Summary.Failed > 0 {
		fmt.Printf("## Failed Checks\n\n")
		fmt.Printf("| Severity | Check | Current | Expected | Fix |\n")
		fmt.Printf("|----------|-------|---------|----------|-----|\n")
		for _, result := range r.Results {
			if result.Status != "fail" {
				continue
			}
			fmt.Printf("| **%s** | %s | `%s` | `%s` | `%s` |\n",
				strings.ToUpper(result.Severity),
				result.Title,
				escapeMarkdown(result.CurrentValue),
				escapeMarkdown(result.ExpectedValue),
				escapeMarkdown(result.FixCommand),
			)
		}
		fmt.Println()
	}

	fmt.Printf("---\n_Generated by [Rootwatch](https://rootwatch.net)_\n")
}

// PrintStreamingHeader prints the scan header before results start streaming.
func PrintStreamingHeader(hostname, osStr string) {
	bold := "\033[1m"
	dim := "\033[2m"
	reset := "\033[0m"
	fmt.Printf("\n%s  rootwatch scan — %s%s\n", bold, hostname, reset)
	fmt.Printf("%s  %s  ·  %s%s\n\n", dim, osStr, time.Now().Format("02 Jan 2006 15:04 MST"), reset)
}

// PrintResultLive prints a single check result line as it arrives.
func PrintResultLive(r checks.CheckResult) {
	reset := "\033[0m"
	dim := "\033[2m"
	red := "\033[31m"
	yellow := "\033[33m"
	green := "\033[32m"

	switch r.Status {
	case "pass":
		fmt.Printf("  %s✓%s  %s%s%s\n", green, reset, dim, r.Title, reset)
	case "fail":
		var sevColor string
		switch r.Severity {
		case "critical":
			sevColor = red
		default:
			sevColor = yellow
		}
		fix := r.FixCommand
		if len(fix) > 55 {
			fix = fix[:52] + "..."
		}
		if fix != "" {
			fmt.Printf("  %s✗%s  %s%s%s  %s→  %s%s\n", red, reset, sevColor, r.Title, reset, dim, fix, reset)
		} else {
			fmt.Printf("  %s✗%s  %s%s%s\n", red, reset, sevColor, r.Title, reset)
		}
		if r.FixWarning != "" {
			fmt.Printf("     %s⚠  %s%s\n", yellow, r.FixWarning, reset)
		}
	case "skipped":
		fmt.Printf("  %s⊘  %s%s\n", dim, r.Title, reset)
	}
}

// PrintStreamingFooter prints the score bar and summary after all results have streamed.
func PrintStreamingFooter(score int, s Summary) {
	reset := "\033[0m"
	bold := "\033[1m"
	dim := "\033[2m"
	red := "\033[31m"
	green := "\033[32m"
	scoreColor := scoreColorCode(score)

	fmt.Println()
	fmt.Printf("  Security Score:  %s%s%d / 100%s\n\n", bold, scoreColor, score, reset)
	fmt.Printf("  %s✓ Passed%s  %-4d   %s✗ Failed%s  %-4d   %sCritical%s  %-4d   %s⊘ Skipped%s  %d\n\n",
		green, reset, s.Passed,
		red, reset, s.Failed,
		red, reset, s.Critical,
		dim, reset, s.Skipped,
	)
	if s.Failed == 0 {
		fmt.Printf("  %s✓ All checks passed.%s\n\n", green, reset)
		return
	}
	fmt.Printf("  %sTip:%s  run with --output json for full fix commands and expected values.\n", dim, reset)
	fmt.Printf("  %s  Continuous monitoring + audit-ready hardening reports → https://rootwatch.net%s\n\n", dim, reset)
}

// PrintSARIF writes the report in SARIF 2.1.0 format for GitHub Advanced Security.
func PrintSARIF(r ScanReport) {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifArtifactLocation struct {
		URI       string `json:"uri"`
		URIBaseID string `json:"uriBaseId"`
	}
	type sarifPhysicalLocation struct {
		ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMessage    `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}
	type sarifRule struct {
		ID               string       `json:"id"`
		Name             string       `json:"name"`
		ShortDescription sarifMessage `json:"shortDescription"`
		FullDescription  sarifMessage `json:"fullDescription"`
		HelpURI          string       `json:"helpUri,omitempty"`
		Properties       struct {
			Tags     []string `json:"tags,omitempty"`
			Severity string   `json:"security-severity,omitempty"`
		} `json:"properties,omitempty"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifRoot struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	// Map severity to SARIF level and numeric score for GitHub
	severityToLevel := map[string]string{
		"critical": "error",
		"warning":  "warning",
		"info":     "note",
	}
	severityToScore := map[string]string{
		"critical": "9.0",
		"warning":  "5.0",
		"info":     "2.0",
	}

	// Map check categories to a representative config file path
	categoryToPath := map[string]string{
		"ssh":        "etc/ssh/sshd_config",
		"firewall":   "etc/ufw/ufw.conf",
		"kernel":     "etc/sysctl.conf",
		"filesystem": "etc/fstab",
		"users":      "etc/passwd",
		"packages":   "etc/apt/sources.list",
		"network":    "etc/hosts",
		"ssl":        "etc/ssl/openssl.cnf",
		"docker":     "etc/docker/daemon.json",
		"cve":        "var/lib/dpkg/status",
	}

	// Build deduplicated rule list from failed results
	seenRules := map[string]bool{}
	var rules []sarifRule
	for _, res := range r.Results {
		if seenRules[res.CheckID] {
			continue
		}
		seenRules[res.CheckID] = true
		rule := sarifRule{
			ID:               res.CheckID,
			Name:             res.Title,
			ShortDescription: sarifMessage{Text: res.Title},
			FullDescription:  sarifMessage{Text: res.Description},
		}
		rule.Properties.Tags = []string{"security", res.Category}
		if s, ok := severityToScore[res.Severity]; ok {
			rule.Properties.Severity = s
		}
		rules = append(rules, rule)
	}

	// Build results — only include failures
	var sarifResults []sarifResult
	for _, res := range r.Results {
		if res.Status != "fail" {
			continue
		}
		level := severityToLevel[res.Severity]
		if level == "" {
			level = "note"
		}
		path, ok := categoryToPath[res.Category]
		if !ok {
			path = "etc/os-release"
		}
		msg := res.Description
		if res.CurrentValue != "" {
			msg += " — observed: " + res.CurrentValue
		}
		if res.ExpectedValue != "" {
			msg += ", expected: " + res.ExpectedValue
		}
		sarifResults = append(sarifResults, sarifResult{
			RuleID:  res.CheckID,
			Level:   level,
			Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{
				{PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{
						URI:       path,
						URIBaseID: "%SRCROOT%",
					},
				}},
			},
		})
	}

	out := sarifRoot{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "rootwatch",
						Version:        r.Hostname, // hostname in version field for traceability
						InformationURI: "https://rootwatch.net",
						Rules:          rules,
					},
				},
				Results: sarifResults,
			},
		},
	}
	// Use hostname as a property, not version — fix: embed it in a note instead
	out.Runs[0].Tool.Driver.Version = "0.1.0"

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out) //nolint:errcheck
}

// PrintFixDryRun prints a numbered remediation plan for all failed checks
// that have a fix command. Nothing is executed.
func PrintFixDryRun(hostname string, results []checks.CheckResult) {
	reset := "\033[0m"
	bold := "\033[1m"
	dim := "\033[2m"
	red := "\033[31m"
	yellow := "\033[33m"

	var failed []checks.CheckResult
	for _, r := range results {
		if r.Status == "fail" && r.FixCommand != "" {
			failed = append(failed, r)
		}
	}

	fmt.Printf("\n%s  rootwatch fix --dry-run — %s%s\n", bold, hostname, reset)
	fmt.Printf("%s  Showing %d fix command(s). Nothing has been executed.%s\n\n", dim, len(failed), reset)

	if len(failed) == 0 {
		fmt.Printf("  \033[32m✓ No actionable fixes found.%s\n\n", reset)
		return
	}

	for i, r := range failed {
		var sevColor string
		switch r.Severity {
		case "critical":
			sevColor = red
		default:
			sevColor = yellow
		}

		fmt.Printf("  %s%d. %s%s  %s[%s]%s\n",
			bold, i+1, r.Title, reset,
			sevColor, strings.ToUpper(r.Severity), reset,
		)
		fmt.Printf("     %s%s%s\n", dim, r.FixCommand, reset)
		if r.FixWarning != "" {
			fmt.Printf("     %s⚠  %s%s\n", yellow, r.FixWarning, reset)
		}
		fmt.Println()
	}

	fmt.Printf("  %sRun each command as root on the target server.%s\n", dim, reset)
	fmt.Printf("  %sTest in a staging environment before applying to production.%s\n\n", dim, reset)
}

func scoreColorCode(score int) string {
	if score >= 80 {
		return "\033[32m" // green
	} else if score >= 50 {
		return "\033[33m" // yellow
	}
	return "\033[31m" // red
}

func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "`", "'")
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}
