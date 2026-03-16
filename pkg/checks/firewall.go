package checks

import (
	"os/exec"
	"strings"
)

type FirewallCheck struct{}

func (c *FirewallCheck) Name() string { return "firewall" }

func (c *FirewallCheck) Run() ([]CheckResult, error) {
	var results []CheckResult

	// Check for UFW
	out, err := exec.Command("ufw", "status").Output()
	if err == nil {
		status := "fail"
		if strings.Contains(string(out), "Status: active") {
			status = "pass"
		}
		
		results = append(results, CheckResult{
			Category:      "firewall",
			CheckID:       "fw-enabled",
			Title:         "Firewall Active",
			Description:   "Checks if ufw/iptables/nftables has active rules",
			Severity:      "critical",
			Status:        status,
			CurrentValue:  string(out),
			ExpectedValue: "Status: active",
			FixCommand:    "ufw enable",
			CISControl:    "CIS 3.5.1",
		})
	} else {
		results = append(results, CheckResult{
			Category:      "firewall",
			CheckID:       "fw-enabled",
			Title:         "Firewall Active",
			Description:   "Checks if ufw/iptables/nftables has active rules",
			Severity:      "critical",
			Status:        "fail",
			CurrentValue:  "Not Active / Not Installed",
			ExpectedValue: "Active",
			FixCommand:    "apt-get install ufw && ufw enable",
			CISControl:    "CIS 3.5.1",
		})
	}

	return results, nil
}
