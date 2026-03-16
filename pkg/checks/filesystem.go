package checks

import (
	"os/exec"
	"strings"
)

type FilesystemCheck struct{}

func (c *FilesystemCheck) Name() string { return "filesystem" }

func (c *FilesystemCheck) Run() ([]CheckResult, error) {
	var results []CheckResult

	// Check /tmp mount options
	out, err := exec.Command("mount").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		tmpOpts := ""
		for _, line := range lines {
			if strings.Contains(line, " on /tmp ") {
				tmpOpts = line
				break
			}
		}

		status := "fail"
		val := "not mounted / noexec not found"
		if tmpOpts != "" {
			if strings.Contains(tmpOpts, "noexec") {
				status = "pass"
				val = "noexec"
			} else {
				val = "mounted without noexec"
			}
		}

		results = append(results, CheckResult{
			Category:      "filesystem",
			CheckID:       "fs-tmp-noexec",
			Title:         "/tmp Mounted with noexec",
			Description:   "Check mount options for /tmp",
			Severity:      "warning",
			Status:        status,
			CurrentValue:  val,
			ExpectedValue: "noexec",
			FixCommand:    "mount -o remount,noexec /tmp",
			CISControl:    "CIS 1.1.3",
		})
	}

	return results, nil
}
