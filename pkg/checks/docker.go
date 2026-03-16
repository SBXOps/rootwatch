package checks

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

type DockerCheck struct{}

func (c *DockerCheck) Name() string { return "docker" }

func (c *DockerCheck) Run() ([]CheckResult, error) {
	var results []CheckResult

	// Check if docker is installed
	_, err := exec.LookPath("docker")
	if err != nil {
		skipped := CheckResult{
			Category:   "docker",
			CheckID:    "docker-installed",
			Title:      "Docker Daemon Security",
			Description: "Docker is not installed",
			Severity:   "info",
			Status:     "skipped",
			CISControl: "CIS Docker 2.1",
		}
		return []CheckResult{skipped}, nil
	}

	// Check 1: Docker socket permissions (CIS Docker 2.1)
	sockPath := "/var/run/docker.sock"
	info, statErr := os.Stat(sockPath)
	if statErr != nil {
		results = append(results, CheckResult{
			Category:    "docker",
			CheckID:     "docker-socket-perms",
			Title:       "Docker Socket Permissions",
			Description: "Docker socket not found or inaccessible",
			Severity:    "info",
			Status:      "skipped",
			CISControl:  "CIS Docker 2.1",
		})
	} else {
		mode := info.Mode()
		// World-writable = 0002, world-readable = 0004
		worldWritable := mode&0002 != 0
		worldReadable := mode&0004 != 0
		insecure := worldWritable || worldReadable

		status := "pass"
		currentVal := mode.String()
		if insecure {
			status = "fail"
		}
		results = append(results, CheckResult{
			Category:      "docker",
			CheckID:       "docker-socket-perms",
			Title:         "Docker Socket Not World-Accessible",
			Description:   "The Docker daemon socket should not be world-readable or world-writable",
			Severity:      "critical",
			Status:        status,
			CurrentValue:  currentVal,
			ExpectedValue: "No world-read/write permissions (e.g. srw-rw---- or srw-r-----)",
			FixCommand:    "chmod 660 /var/run/docker.sock && chown root:docker /var/run/docker.sock",
			CISControl:    "CIS Docker 2.1",
		})
	}

	// Check 2: Containers running as root (CIS Docker 4.1)
	containerOut, containerErr := exec.Command("sh", "-c",
		"docker ps -q 2>/dev/null | xargs -r docker inspect --format='{{.Name}} {{.Config.User}}' 2>/dev/null",
	).Output()

	if containerErr == nil {
		var rootContainers []string
		for _, line := range strings.Split(strings.TrimSpace(string(containerOut)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			// If user field is empty or "root" or "0", the container runs as root
			if len(parts) == 1 || (len(parts) >= 2 && (parts[1] == "" || parts[1] == "root" || parts[1] == "0")) {
				rootContainers = append(rootContainers, parts[0])
			}
		}

		if len(rootContainers) > 0 {
			results = append(results, CheckResult{
				Category:      "docker",
				CheckID:       "docker-containers-root",
				Title:         "Containers Running as Root",
				Description:   "Containers should not run as root to limit privilege escalation risk",
				Severity:      "critical",
				Status:        "fail",
				CurrentValue:  strings.Join(rootContainers, ", "),
				ExpectedValue: "All containers run as non-root user",
				FixCommand:    "Add 'USER nonroot' to your Dockerfile or set user in docker-compose.yml",
				CISControl:    "CIS Docker 4.1",
			})
		} else {
			results = append(results, CheckResult{
				Category:      "docker",
				CheckID:       "docker-containers-root",
				Title:         "Containers Running as Root",
				Description:   "No running containers detected as running as root",
				Severity:      "critical",
				Status:        "pass",
				CISControl:    "CIS Docker 4.1",
			})
		}
	} else {
		results = append(results, CheckResult{
			Category:    "docker",
			CheckID:     "docker-containers-root",
			Title:       "Containers Running as Root",
			Description: "Could not inspect running containers",
			Severity:    "critical",
			Status:      "skipped",
			CISControl:  "CIS Docker 4.1",
		})
	}

	// Check 3: --no-new-privileges in daemon.json (CIS Docker 2.14)
	daemonJSONPath := "/etc/docker/daemon.json"
	daemonContent, daemonErr := os.ReadFile(daemonJSONPath)
	noNewPrivileges := false
	if daemonErr == nil {
		var daemonConfig map[string]interface{}
		if json.Unmarshal(daemonContent, &daemonConfig) == nil {
			if val, ok := daemonConfig["no-new-privileges"]; ok {
				if b, ok := val.(bool); ok && b {
					noNewPrivileges = true
				}
			}
		}
	}

	if !noNewPrivileges {
		results = append(results, CheckResult{
			Category:      "docker",
			CheckID:       "docker-no-new-privileges",
			Title:         "Docker no-new-privileges Enabled",
			Description:   "The --no-new-privileges flag prevents containers from gaining new privileges via setuid/setgid",
			Severity:      "warning",
			Status:        "fail",
			CurrentValue:  "no-new-privileges not set in daemon.json",
			ExpectedValue: "no-new-privileges: true in /etc/docker/daemon.json",
			FixCommand:    `echo '{"no-new-privileges": true}' > /etc/docker/daemon.json && systemctl restart docker`,
			CISControl:    "CIS Docker 2.14",
		})
	} else {
		results = append(results, CheckResult{
			Category:    "docker",
			CheckID:     "docker-no-new-privileges",
			Title:       "Docker no-new-privileges Enabled",
			Description: "no-new-privileges is enabled in Docker daemon configuration",
			Severity:    "warning",
			Status:      "pass",
			CISControl:  "CIS Docker 2.14",
		})
	}

	// Check 4: Docker Content Trust (CIS Docker 4.5)
	contentTrustEnabled := false

	// Check environment variable
	if os.Getenv("DOCKER_CONTENT_TRUST") == "1" {
		contentTrustEnabled = true
	}

	// Also check daemon.json for content-trust
	if !contentTrustEnabled && daemonErr == nil {
		var daemonConfig map[string]interface{}
		if json.Unmarshal(daemonContent, &daemonConfig) == nil {
			if val, ok := daemonConfig["content-trust"]; ok {
				if m, ok := val.(map[string]interface{}); ok {
					if mode, ok := m["mode"]; ok && mode == "enforced" {
						contentTrustEnabled = true
					}
				}
			}
		}
	}

	if !contentTrustEnabled {
		results = append(results, CheckResult{
			Category:      "docker",
			CheckID:       "docker-content-trust",
			Title:         "Docker Content Trust Enabled",
			Description:   "Docker Content Trust ensures only signed images are pulled and run",
			Severity:      "warning",
			Status:        "fail",
			CurrentValue:  "DOCKER_CONTENT_TRUST not set or not enforced",
			ExpectedValue: "DOCKER_CONTENT_TRUST=1 or enforced in daemon.json",
			FixCommand:    "export DOCKER_CONTENT_TRUST=1  # Add to /etc/environment for persistence",
			CISControl:    "CIS Docker 4.5",
		})
	} else {
		results = append(results, CheckResult{
			Category:    "docker",
			CheckID:     "docker-content-trust",
			Title:       "Docker Content Trust Enabled",
			Description: "Docker Content Trust is enabled",
			Severity:    "warning",
			Status:      "pass",
			CISControl:  "CIS Docker 4.5",
		})
	}

	return results, nil
}
