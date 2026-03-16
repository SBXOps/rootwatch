package checks

import (
	"fmt"
	"net"
	"strings"
)

type NetworkAdvancedChecks struct{}

func (n *NetworkAdvancedChecks) Name() string { return "network_advanced" }

func (n *NetworkAdvancedChecks) Run() ([]CheckResult, error) {
	var results []CheckResult

	// Check 1: Open ports scan - list publicly listening services
	// Get listening TCP ports
	listeningPorts := getListeningPorts()
	dangerousPorts := []int{21, 23, 25, 110, 143, 512, 513, 514, 1433, 3306, 5432, 6379, 27017}

	var exposedDangerous []string
	for _, port := range dangerousPorts {
		for _, p := range listeningPorts {
			if p == port {
				exposedDangerous = append(exposedDangerous, fmt.Sprintf("%d", port))
			}
		}
	}

	if len(exposedDangerous) > 0 {
		results = append(results, CheckResult{
			Category:      "network",
			CheckID:       "network-dangerous-ports",
			Title:         "Dangerous Ports Exposed",
			Description:   "Services listening on ports commonly associated with unencrypted or vulnerable protocols",
			Severity:      "warning",
			Status:        "fail",
			CurrentValue:  strings.Join(exposedDangerous, ", "),
			ExpectedValue: "No dangerous ports exposed",
			FixCommand:    "Review listening services with: ss -tlnp | grep -E '(21|23|25|3306|6379)'",
			CISControl:    "CIS 9.2",
		})
	} else {
		results = append(results, CheckResult{
			Category:      "network",
			CheckID:       "network-dangerous-ports",
			Title:         "Dangerous Ports Exposed",
			Description:   "No services listening on commonly dangerous ports",
			Severity:      "warning",
			Status:        "pass",
			CurrentValue:  "None",
			ExpectedValue: "No dangerous ports exposed",
			CISControl:    "CIS 9.2",
		})
	}

	return results, nil
}

func getListeningPorts() []int {
	// Read /proc/net/tcp and /proc/net/tcp6
	var ports []int
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		content, err := readFile(f)
		if err != nil {
			continue
		}
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			if i == 0 {
				continue // header
			}
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			// State 0A = LISTEN
			if fields[3] != "0A" {
				continue
			}
			// Local address is field[1]: addr:port in hex
			parts := strings.Split(fields[1], ":")
			if len(parts) < 2 {
				continue
			}
			var portHex string
			if len(parts) == 2 {
				portHex = parts[1]
			} else {
				portHex = parts[len(parts)-1]
			}
			var port int
			fmt.Sscanf(portHex, "%x", &port)
			if port > 0 {
				ports = append(ports, port)
			}
		}
	}
	return ports
}

// isPortListening checks if a port is accessible from localhost.
func isPortListening(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1e9)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
