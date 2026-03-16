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
	}
	w.Flush()

	fmt.Println()
	fmt.Printf("  %sTip:%s  run with --output json for full fix commands and expected values.\n", dim, reset)
	fmt.Printf("  %s  Continuous monitoring + compliance reports → https://rootwatch.dev%s\n\n", dim, reset)
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

	fmt.Printf("---\n_Generated by [Rootwatch](https://rootwatch.dev)_\n")
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
