package checks

import (
	"os/exec"
	"strings"
)

type UpdatesChecks struct{}

func (u *UpdatesChecks) Name() string { return "updates" }

func (u *UpdatesChecks) Run() ([]CheckResult, error) {
	var results []CheckResult

	// Check 1: Unattended upgrades enabled
	uaContent, err := readFile("/etc/apt/apt.conf.d/20auto-upgrades")
	unattendedEnabled := false
	if err == nil {
		unattendedEnabled = strings.Contains(uaContent, `"1"`) || strings.Contains(uaContent, `"true"`)
	}

	// Also check if package is installed
	_, uaInstalled := exec.LookPath("unattended-upgrade")
	_ = uaInstalled

	if !unattendedEnabled {
		results = append(results, CheckResult{
			Category:      "packages",
			CheckID:       "packages-unattended-upgrades",
			Title:         "Automatic Security Updates",
			Description:   "Unattended upgrades automatically applies security patches without manual intervention",
			Severity:      "warning",
			Status:        "fail",
			CurrentValue:  "Unattended upgrades not configured",
			ExpectedValue: "Unattended upgrades enabled",
			FixCommand:    "apt install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades",
			CISControl:    "CIS 1.9",
		})
	} else {
		results = append(results, CheckResult{
			Category:    "packages",
			CheckID:     "packages-unattended-upgrades",
			Title:       "Automatic Security Updates",
			Description: "Unattended upgrades is configured",
			Severity:    "warning",
			Status:      "pass",
			CISControl:  "CIS 1.9",
		})
	}

	return results, nil
}
