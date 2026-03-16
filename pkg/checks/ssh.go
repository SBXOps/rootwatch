package checks

import (
	"os/exec"
	"strings"
)

type SSHCheck struct{}

func (c *SSHCheck) Name() string { return "ssh" }

func (c *SSHCheck) Run() ([]CheckResult, error) {
	var results []CheckResult

	// Get effective sshd config
	cmd := exec.Command("sshd", "-T")
	out, err := cmd.Output()
	if err != nil {
		// If sshd -T fails, try reading the file directly or fallback gracefully
		// For simplicity in this v1, if sshd not found, assume ssh is not installed/configured
		results = append(results, CheckResult{
			Category: "ssh",
			CheckID:  "ssh-installed",
			Status:   "skipped",
			Severity: "info",
			Title:    "SSH Daemon Config",
		})
		return results, nil
	}

	configLines := strings.Split(string(out), "\n")
	configMap := make(map[string]string)

	for _, line := range configLines {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 {
			configMap[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.ToLower(strings.TrimSpace(parts[1]))
		}
	}

	results = append(results, checkConfigCIS(configMap, "permitrootlogin", "no", "ssh-root-login", "Root SSH Login Disabled", "Checks whether root login via SSH is disabled", "critical", "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd", "CIS 5.2.8"))
	results = append(results, checkConfigCIS(configMap, "passwordauthentication", "no", "ssh-password-auth", "Password Authentication Disabled", "Password Authentication should be no", "warning", "", "CIS 5.2.11"))
	results = append(results, checkConfigCIS(configMap, "permitemptypasswords", "no", "ssh-empty-passwords", "Empty Passwords Denied", "PermitEmptyPasswords should be no", "critical", "", "CIS 5.2.9"))
	results = append(results, checkConfigCIS(configMap, "x11forwarding", "no", "ssh-x11-forwarding", "X11 Forwarding Disabled", "X11Forwarding should be no", "info", "", "CIS 5.2.6"))

	return results, nil
}

func checkConfigCIS(config map[string]string, key, expectedStr, id, title, description, severity, fixCmd, cisControl string) CheckResult {
	val, ok := config[key]
	if !ok {
		val = "not set (default)"
	}

	status := "fail"
	if val == expectedStr {
		status = "pass"
	}

	return CheckResult{
		Category:      "ssh",
		CheckID:       id,
		Title:         title,
		Description:   description,
		Severity:      severity,
		Status:        status,
		CurrentValue:  key + " " + val,
		ExpectedValue: key + " " + expectedStr,
		FixCommand:    fixCmd,
		CISControl:    cisControl,
	}
}

// checkConfig is kept for backward compatibility.
func checkConfig(config map[string]string, key, expectedStr, id, title, description, severity, fixCmd string) CheckResult {
	return checkConfigCIS(config, key, expectedStr, id, title, description, severity, fixCmd, "")
}
