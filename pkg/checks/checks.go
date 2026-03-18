package checks

import "os"

// readFile reads a file and returns its contents as a string.
func readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

type CheckResult struct {
	Category      string `json:"category"`
	CheckID       string `json:"check_id"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Severity      string `json:"severity"`      // critical, warning, info
	Status        string `json:"status"`        // pass, fail, error, skipped
	CurrentValue  string `json:"current_value"`
	ExpectedValue string `json:"expected_value"`
	FixCommand    string `json:"fix_command"`
	FixWarning    string `json:"fix_warning,omitempty"` // amber caution shown below fix command
	CISControl    string `json:"cis_control"`           // e.g. "CIS 5.2.1"
}

type Check interface {
	Run() ([]CheckResult, error)
	Name() string
}
