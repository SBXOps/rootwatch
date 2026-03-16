package checks

import (
	"os/exec"
	"strings"
)

type PackagesCheck struct{}

func (c *PackagesCheck) Name() string { return "packages" }

func (c *PackagesCheck) Run() ([]CheckResult, error) {
	var results []CheckResult

	// Check for apt layout (Debian/Ubuntu)
	_, err := exec.LookPath("apt")
	if err == nil {
		out, _ := exec.Command("apt", "list", "--upgradable").Output()
		lines := strings.Split(string(out), "\n")
		
		upgradable := 0
		for _, line := range lines {
			if strings.Contains(line, "upgradable") {
				upgradable++
			}
		}
		
		status := "pass"
		if upgradable > 0 {
			status = "fail"
		}

		results = append(results, CheckResult{
			Category:      "packages",
			CheckID:       "pkg-updates-available",
			Title:         "Security Updates Available",
			Description:   "apt list --upgradable",
			Severity:      "critical",
			Status:        status,
			CurrentValue:  string(upgradable) + " packages",
			ExpectedValue: "0 packages",
			FixCommand:    "apt-get update && apt-get upgrade -y",
			CISControl:    "CIS 1.9",
		})
	}

	return results, nil
}
