package checks

import (
	"fmt"
	"os/exec"
	"strings"
)

type UsersAdvancedChecks struct{}

func (u *UsersAdvancedChecks) Name() string { return "users_advanced" }

func (u *UsersAdvancedChecks) Run() ([]CheckResult, error) {
	var results []CheckResult

	// Check 1: Sudoers - check for NOPASSWD entries
	sudoersOutput, _ := exec.Command("grep", "-r", "NOPASSWD", "/etc/sudoers", "/etc/sudoers.d/").Output()
	// Filter out comments
	nopasswdLines := []string{}
	for _, line := range strings.Split(string(sudoersOutput), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			nopasswdLines = append(nopasswdLines, line)
		}
	}

	if len(nopasswdLines) > 0 {
		results = append(results, CheckResult{
			Category:      "users",
			CheckID:       "users-sudo-nopasswd",
			Title:         "Passwordless Sudo Entries",
			Description:   "NOPASSWD sudo entries allow privilege escalation without authentication",
			Severity:      "critical",
			Status:        "fail",
			CurrentValue:  strings.Join(nopasswdLines, "; "),
			ExpectedValue: "No NOPASSWD entries in sudoers",
			FixCommand:    "visudo  # Remove or restrict NOPASSWD entries",
			CISControl:    "CIS 5.3.7",
		})
	} else {
		results = append(results, CheckResult{
			Category:    "users",
			CheckID:     "users-sudo-nopasswd",
			Title:       "Passwordless Sudo Entries",
			Description: "No NOPASSWD entries found in sudoers configuration",
			Severity:    "critical",
			Status:      "pass",
			CISControl:  "CIS 5.3.7",
		})
	}

	// Check 2: Recent failed login attempts
	failedLogins := 0
	// Try lastb or journalctl
	lastbOut, err := exec.Command("lastb", "-n", "50").Output()
	if err == nil {
		lines := strings.Split(string(lastbOut), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" && !strings.Contains(line, "btmp begins") {
				failedLogins++
			}
		}
	} else {
		// Try journalctl
		jOut, _ := exec.Command("journalctl", "-u", "sshd", "--since", "24 hours ago", "--no-pager", "-q").Output()
		for _, line := range strings.Split(string(jOut), "\n") {
			if strings.Contains(line, "Failed password") || strings.Contains(line, "Invalid user") {
				failedLogins++
			}
		}
	}

	severity := "info"
	status := "pass"
	currentValue := fmt.Sprintf("%d failed attempts (last 24h)", failedLogins)
	var fixCommand string

	if failedLogins > 100 {
		severity = "critical"
		status = "fail"
		fixCommand = "apt install -y fail2ban && systemctl enable --now fail2ban"
	} else if failedLogins > 20 {
		severity = "warning"
		status = "fail"
		fixCommand = "Consider installing fail2ban: apt install -y fail2ban"
	}

	results = append(results, CheckResult{
		Category:      "users",
		CheckID:       "users-failed-logins",
		Title:         "Failed Login Attempts",
		Description:   "High number of failed login attempts may indicate a brute-force attack",
		Severity:      severity,
		Status:        status,
		CurrentValue:  currentValue,
		ExpectedValue: "< 20 failed attempts per 24h",
		FixCommand:    fixCommand,
		CISControl:    "CIS 6.2.7",
	})

	// Check 3: Check if fail2ban is installed and running
	_, fail2banErr := exec.LookPath("fail2ban-client")
	fail2banRunning := false
	if fail2banErr == nil {
		statusOut, _ := exec.Command("systemctl", "is-active", "fail2ban").Output()
		fail2banRunning = strings.TrimSpace(string(statusOut)) == "active"
	}

	if !fail2banRunning {
		results = append(results, CheckResult{
			Category:      "users",
			CheckID:       "users-fail2ban",
			Title:         "Brute-Force Protection (fail2ban)",
			Description:   "fail2ban protects against brute-force login attacks by banning IPs after repeated failures",
			Severity:      "warning",
			Status:        "fail",
			CurrentValue:  "fail2ban not running",
			ExpectedValue: "fail2ban active",
			FixCommand:    "apt install -y fail2ban && systemctl enable --now fail2ban",
			CISControl:    "CIS 5.3.3",
		})
	} else {
		results = append(results, CheckResult{
			Category:    "users",
			CheckID:     "users-fail2ban",
			Title:       "Brute-Force Protection (fail2ban)",
			Description: "fail2ban is installed and running",
			Severity:    "warning",
			Status:      "pass",
			CISControl:  "CIS 5.3.3",
		})
	}

	return results, nil
}
