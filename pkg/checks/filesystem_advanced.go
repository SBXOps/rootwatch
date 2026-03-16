package checks

import (
	"fmt"
	"os/exec"
	"strings"
)

type FilesystemAdvancedChecks struct{}

func (f *FilesystemAdvancedChecks) Name() string { return "filesystem_advanced" }

func (f *FilesystemAdvancedChecks) Run() ([]CheckResult, error) {
	var results []CheckResult

	// Check 1: World-writable files in system paths (excluding /tmp, /proc, /sys, /dev)
	cmd := exec.Command("find", "/etc", "/usr", "/bin", "/sbin", "/lib",
		"-xdev", "-perm", "-0002", "-not", "-type", "l", "-maxdepth", "5")
	out, err := cmd.Output()

	wwFiles := []string{}
	if err == nil && len(out) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line != "" {
				wwFiles = append(wwFiles, line)
			}
		}
	}

	if len(wwFiles) > 0 {
		count := len(wwFiles)
		display := strings.Join(wwFiles[:minInt(count, 5)], ", ")
		if count > 5 {
			display += fmt.Sprintf(" (+%d more)", count-5)
		}
		results = append(results, CheckResult{
			Category:      "filesystem",
			CheckID:       "filesystem-world-writable",
			Title:         "World-Writable System Files",
			Description:   "Files in system directories writable by any user are a privilege escalation risk",
			Severity:      "critical",
			Status:        "fail",
			CurrentValue:  display,
			ExpectedValue: "No world-writable files in system paths",
			FixCommand:    "chmod o-w <file>  # Run for each file listed",
			CISControl:    "CIS 6.1.10",
		})
	} else {
		results = append(results, CheckResult{
			Category:    "filesystem",
			CheckID:     "filesystem-world-writable",
			Title:       "World-Writable System Files",
			Description: "No world-writable files found in system directories",
			Severity:    "critical",
			Status:      "pass",
			CISControl:  "CIS 6.1.10",
		})
	}

	// Check 2: SUID/SGID files in non-standard locations
	suidCmd := exec.Command("find", "/home", "/tmp", "/var/tmp",
		"-xdev", "-perm", "/6000", "-maxdepth", "5")
	suidOut, _ := suidCmd.Output()

	suidFiles := []string{}
	if len(suidOut) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(suidOut)), "\n") {
			if line != "" {
				suidFiles = append(suidFiles, line)
			}
		}
	}

	if len(suidFiles) > 0 {
		results = append(results, CheckResult{
			Category:      "filesystem",
			CheckID:       "filesystem-suid-suspicious",
			Title:         "Suspicious SUID/SGID Files",
			Description:   "SUID/SGID binaries in user-writable directories are a privilege escalation risk",
			Severity:      "critical",
			Status:        "fail",
			CurrentValue:  strings.Join(suidFiles, ", "),
			ExpectedValue: "No SUID/SGID files in user-writable directories",
			FixCommand:    "chmod u-s,g-s <file>  # Remove SUID/SGID from suspicious files",
			CISControl:    "CIS 6.1.13",
		})
	} else {
		results = append(results, CheckResult{
			Category:    "filesystem",
			CheckID:     "filesystem-suid-suspicious",
			Title:       "Suspicious SUID/SGID Files",
			Description: "No suspicious SUID/SGID files found",
			Severity:    "critical",
			Status:      "pass",
			CISControl:  "CIS 6.1.13",
		})
	}

	return results, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
