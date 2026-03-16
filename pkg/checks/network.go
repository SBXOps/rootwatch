package checks

import (
	"os/exec"
	"strings"
)

type NetworkCheck struct{}

func (c *NetworkCheck) Name() string { return "network" }

func (c *NetworkCheck) Run() ([]CheckResult, error) {
	var results []CheckResult

	// Check IP forwarding
	out, err := exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output()
	if err == nil {
		val := strings.TrimSpace(string(out))
		status := "pass"
		if val != "0" {
			status = "fail"
		}
		
		results = append(results, CheckResult{
			Category:      "network",
			CheckID:       "net-ip-forwarding",
			Title:         "IP Forwarding Disabled",
			Description:   "net.ipv4.ip_forward should be 0",
			Severity:      "warning",
			Status:        status,
			CurrentValue:  val,
			ExpectedValue: "0",
			FixCommand:    "sysctl -w net.ipv4.ip_forward=0",
			CISControl:    "CIS 3.1.1",
		})
	}

	return results, nil
}
