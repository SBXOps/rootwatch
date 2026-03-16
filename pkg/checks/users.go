package checks

import (
	"os"
	"strings"
)

type UsersCheck struct{}

func (c *UsersCheck) Name() string { return "users" }

func (c *UsersCheck) Run() ([]CheckResult, error) {
	var results []CheckResult

	// Check UID 0
	passwdData, err := os.ReadFile("/etc/passwd")
	if err == nil {
		lines := strings.Split(string(passwdData), "\n")
		var uid0Users []string
		for _, line := range lines {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 && parts[2] == "0" {
				uid0Users = append(uid0Users, parts[0])
			}
		}
		
		status := "pass"
		if len(uid0Users) > 1 || (len(uid0Users) == 1 && uid0Users[0] != "root") {
			status = "fail"
		}
		
		results = append(results, CheckResult{
			Category:      "users",
			CheckID:       "user-root-only-uid0",
			Title:         "Only Root Has UID 0",
			Description:   "No other user has UID 0 in /etc/passwd",
			Severity:      "critical",
			Status:        status,
			CurrentValue:  strings.Join(uid0Users, ", "),
			ExpectedValue: "root",
			FixCommand:    "usermod -u <new_uid> <username>",
			CISControl:    "CIS 6.2.5",
		})
	}

	// Check empty passwords
	shadowData, err := os.ReadFile("/etc/shadow")
	if err == nil {
		lines := strings.Split(string(shadowData), "\n")
		var emptyUsers []string
		for _, line := range lines {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 && parts[1] == "" {
				emptyUsers = append(emptyUsers, parts[0])
			}
		}
		
		status := "pass"
		if len(emptyUsers) > 0 {
			status = "fail"
		}
		
		results = append(results, CheckResult{
			Category:      "users",
			CheckID:       "user-no-empty-passwords",
			Title:         "No Users with Empty Passwords",
			Description:   "Check /etc/shadow for empty password fields",
			Severity:      "critical",
			Status:        status,
			CurrentValue:  strings.Join(emptyUsers, ", "),
			ExpectedValue: "none",
			FixCommand:    "passwd -l <username>",
			CISControl:    "CIS 6.2.1",
		})
	}

	return results, nil
}
