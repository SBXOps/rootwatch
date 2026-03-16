package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/rootwatch/rootwatch/pkg/checks"
	"github.com/rootwatch/rootwatch/internal/config"
)

type ScanSubmission struct {
	Hostname          string                    `json:"hostname"`
	IPAddress         string                    `json:"ip_address"`
	OS                string                    `json:"os"`
	AgentVersion      string                    `json:"agent_version"`
	ScanDurationMs    int                       `json:"scan_duration_ms"`
	StartedAt         time.Time                 `json:"started_at"`
	Results           []checks.CheckResult      `json:"results"`
	InstalledPackages []checks.InstalledPackage `json:"installed_packages,omitempty"`
}

type ScanResponse struct {
	Data struct {
		ScanID     string `json:"scan_id"`
		Score      int    `json:"score"`
		NextScanIn int    `json:"next_scan_in"`
	} `json:"data"`
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

func Submit(cfg *config.Config, submission ScanSubmission) (int, error) {
	payload, err := json.Marshal(submission)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal submission: %w", err)
	}

	req, err := http.NewRequest("POST", cfg.APIURL+"/api/v1/agent/scan", bytes.NewBuffer(payload))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", cfg.AgentToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var scanResp ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		return 0, fmt.Errorf("failed to decode response: %w", err)
	}

	if scanResp.Error.Message != "" {
		return 0, fmt.Errorf("api error: %s", scanResp.Error.Message)
	}

	return scanResp.Data.NextScanIn, nil
}

// SubmitWithToken submits scan results using a raw API URL and token,
// without requiring a Config struct. Used by the CLI --token flag.
func SubmitWithToken(apiURL, token string, submission ScanSubmission) (int, error) {
	cfg := &config.Config{APIURL: apiURL, AgentToken: token}
	return Submit(cfg, submission)
}

func GetHostname() string {
	name, _ := os.Hostname()
	return name
}

func GetOS() string {
	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		lines := bytes.Split(data, []byte("\n"))
		for _, line := range lines {
			if bytes.HasPrefix(line, []byte("PRETTY_NAME=")) {
				return string(bytes.Trim(line[12:], "\"'"))
			}
		}
	}
	return "Linux"
}
