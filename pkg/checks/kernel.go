package checks

import (
	"os/exec"
	"strings"
)

type KernelCheck struct{}

func (c *KernelCheck) Name() string { return "kernel" }

func (c *KernelCheck) Run() ([]CheckResult, error) {
	var results []CheckResult

	// ASLR
	out, err := exec.Command("sysctl", "-n", "kernel.randomize_va_space").Output()
	if err == nil {
		val := strings.TrimSpace(string(out))
		status := "fail"
		if val == "2" {
			status = "pass"
		}
		
		results = append(results, CheckResult{
			Category:      "kernel",
			CheckID:       "kern-aslr",
			Title:         "ASLR Enabled",
			Description:   "kernel.randomize_va_space should be 2",
			Severity:      "critical",
			Status:        status,
			CurrentValue:  val,
			ExpectedValue: "2",
			FixCommand:    "sysctl -w kernel.randomize_va_space=2",
			CISControl:    "CIS 1.6.2",
		})
	}

	// SysRq
	out, err = exec.Command("sysctl", "-n", "kernel.sysrq").Output()
	if err == nil {
		val := strings.TrimSpace(string(out))
		status := "pass"
		if val != "0" {
			status = "fail"
		}
		
		results = append(results, CheckResult{
			Category:      "kernel",
			CheckID:       "kern-sysrq",
			Title:         "SysRq Restricted",
			Description:   "kernel.sysrq should be 0",
			Severity:      "warning",
			Status:        status,
			CurrentValue:  val,
			ExpectedValue: "0",
			FixCommand:    "sysctl -w kernel.sysrq=0",
			CISControl:    "CIS 3.3.5",
		})
	}

	return results, nil
}
