package checks

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type SSLChecks struct{}

func (s *SSLChecks) Name() string { return "ssl" }

func checkCertExpiry(host string, port int) (daysUntilExpiry int, certHost string, err error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return 0, "", fmt.Errorf("no certificates")
	}

	cert := certs[0]
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	return days, cert.Subject.CommonName, nil
}

func (s *SSLChecks) Run() ([]CheckResult, error) {
	var results []CheckResult

	// Check common HTTPS ports
	ports := []int{443, 8443}
	hostname, _ := os.Hostname()
	hosts := []string{"localhost", "127.0.0.1"}
	if hostname != "" {
		hosts = append(hosts, hostname)
	}

	checked := make(map[string]bool)

	for _, port := range ports {
		for _, host := range hosts {
			key := fmt.Sprintf("%s:%d", host, port)
			if checked[key] {
				continue
			}

			days, certCN, err := checkCertExpiry(host, port)
			if err != nil {
				continue // Port not listening or no TLS
			}
			checked[key] = true

			status := "pass"
			severity := "info"
			currentValue := fmt.Sprintf("%d days remaining (CN: %s)", days, certCN)
			expectedValue := "Certificate valid for > 30 days"
			var fixCommand string

			if days < 0 {
				status = "fail"
				severity = "critical"
				currentValue = fmt.Sprintf("EXPIRED %d days ago (CN: %s)", -days, certCN)
				fixCommand = "certbot renew --force-renewal"
			} else if days < 7 {
				status = "fail"
				severity = "critical"
				fixCommand = "certbot renew --force-renewal"
			} else if days < 30 {
				status = "fail"
				severity = "warning"
				fixCommand = "certbot renew"
			}

			desc := fmt.Sprintf("SSL certificate on %s (port %d) expires in %d days", host, port, days)

			results = append(results, CheckResult{
				Category:      "ssl",
				CheckID:       fmt.Sprintf("ssl-cert-expiry-%s-%d", strings.ReplaceAll(host, ".", "-"), port),
				Title:         fmt.Sprintf("SSL Certificate Expiry (%s:%d)", host, port),
				Description:   desc,
				Severity:      severity,
				Status:        status,
				CurrentValue:  currentValue,
				ExpectedValue: expectedValue,
				FixCommand:    fixCommand,
				CISControl:    "CIS 14.4",
			})
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{
			Category:    "ssl",
			CheckID:     "ssl-cert-expiry",
			Title:       "SSL Certificate Expiry",
			Description: "No HTTPS services found on standard ports (443, 8443)",
			Severity:    "info",
			Status:      "skipped",
			CISControl:  "CIS 14.4",
		})
	}

	return results, nil
}

