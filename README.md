# RootWatch

Open source Linux security scanner. Run a CIS benchmark audit on any server in seconds — no account required.

```
  rootwatch scan — prod-web-01
  Ubuntu 22.04.3 LTS  ·  16 Mar 2026 09:41 UTC

  Security Score:  52 / 100

  ✓ Passed  38     ✗ Failed  14     Critical  3     ⊘ Skipped  2

  Failed Checks
  ────────────────────────────────────────────────────────────────────────────
  SEVERITY   CHECK                              FIX
  CRITICAL   Root SSH Login Disabled            sed -i 's/^#*PermitRootLogin.../...
  CRITICAL   Password Authentication Disabled   sed -i 's/^#*PasswordAuthentica...
  CRITICAL   Firewall Active                    ufw allow ssh && ufw --force en...
  WARNING    Unattended Upgrades Enabled        apt-get install -y unattended-u...

  ⚠  Root SSH Login Disabled: Verify you have a non-root sudo user before applying — you will not be able to log in as root afterwards.
  ⚠  Firewall Active: Allows SSH before enabling — verify any other required ports with 'ufw allow <port>' first.

  Tip: run with --output json for full fix commands and expected values.
```

## Quick start

```bash
# Install (Linux, amd64 or arm64)
curl -sSL https://rootwatch.net/install | bash

# Run a scan
rootwatch

# JSON output (CI-friendly)
rootwatch --output json

# Markdown report
rootwatch --output markdown > security-report.md

# SARIF output for GitHub Advanced Security
rootwatch --output sarif > results.sarif

# Print fix commands without executing anything
rootwatch fix --dry-run
```

## What it checks

| Category | Checks | CIS Controls |
|----------|--------|-------------|
| SSH | Root login, password auth, empty passwords, X11 forwarding, idle timeout | CIS 5.2.x |
| Firewall | ufw/iptables active status, open inbound ports | CIS 3.5.1 |
| Users | Root account lock, sudo config, password policies, shadow permissions, inactive accounts | CIS 5.x |
| Filesystem | SUID/SGID bits, world-writable files, /tmp noexec/nosuid | CIS 1.1.x |
| Packages | Available security updates, unattended upgrades, AIDE integrity checker | CIS 1.3.x |
| Kernel | Sysctl hardening, ASLR, core dumps, dmesg restriction, NX bit | CIS 3.x |
| Network | Listening services, IP forwarding, ICMP redirects, source routing | CIS 3.2.x |
| Docker | Daemon socket exposure, privileged containers, user namespaces | CIS Docker |
| SSL/TLS | Certificate expiry, weak cipher suites | — |
| CVE | Installed packages checked against OSV.dev vulnerability database | — |

All checks map to [CIS Benchmark](https://www.cisecurity.org/cis-benchmarks) controls.

---

## CLI reference

### `rootwatch` — run a security scan

```
USAGE
  rootwatch [flags]
  rootwatch fix --dry-run [flags]

SUBCOMMANDS
  fix --dry-run   Print remediation commands for all failed checks (no execution)

FLAGS
  --output, -o    Output format: table (default), json, markdown, sarif
  --token, -t     Rootwatch Cloud token (submit results to your dashboard)
  --api-url       Cloud API URL (default: https://rootwatch.net)
  --category, -c  Comma-separated list of check categories to run
                  Categories: ssh, firewall, users, packages, filesystem,
                              network, kernel, ssl, docker, cve
  --version, -v   Print version and exit
  --help, -h      Show this help

EXIT CODES
  0   All checks passed (or no critical failures)
  1   Scan error
  2   One or more critical failures found
```

### `rootwatch fix --dry-run` — print remediation plan

Runs all checks, then prints a numbered list of fix commands for every failed check. Nothing is executed. Safe to run anywhere.

```
USAGE
  rootwatch fix --dry-run [flags]

FLAGS
  --dry-run       Print fix commands without executing anything
  --category, -c  Limit to specific check categories (comma-separated)
  --help, -h      Show this help
```

Example output:

```
  rootwatch fix --dry-run — prod-web-01
  Showing 3 fix command(s). Nothing has been executed.

  1. Root SSH Login Disabled  [CRITICAL]
     sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sshd -t && systemctl reload sshd
     ⚠  Verify you have a non-root sudo user before applying.

  2. Firewall Active  [CRITICAL]
     ufw allow ssh && ufw --force enable
     ⚠  Allows SSH before enabling — verify other required ports first.

  3. Password Authentication Disabled  [WARNING]
     sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sshd -t && systemctl reload sshd
     ⚠  Ensure SSH key authentication is configured and tested before disabling passwords.

  Run each command as root on the target server.
  Test in a staging environment before applying to production.
```

---

## Output formats

### `--output table` (default)

ANSI-colored table streamed live as each check completes. Best for interactive use.

### `--output json`

Full structured report including all check results, observed/expected values, fix commands, CIS controls, and scan metadata. Best for automation and storage.

```bash
rootwatch --output json | jq '.summary'
rootwatch --output json | jq '[.results[] | select(.status == "fail")]'
```

### `--output markdown`

GitHub-flavoured Markdown table. Best for posting to PRs or wikis.

```bash
rootwatch --output markdown > security-report.md
```

### `--output sarif`

[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) format for GitHub Advanced Security. Each failed check becomes a code scanning alert.

```bash
# Generate and upload to GitHub Advanced Security
rootwatch --output sarif > results.sarif

gh api repos/{owner}/{repo}/code-scanning/sarifs \
  --field sarif=@results.sarif \
  --field ref=refs/heads/main \
  --field commit_sha=$(git rev-parse HEAD)
```

---

## Category filter

Run only specific check categories — useful in CI when you only care about SSH hardening or network exposure:

```bash
# SSH and firewall only
rootwatch --category ssh,firewall

# Just check for CVEs
rootwatch --category cve --output json

# Combine with fix dry-run
rootwatch fix --dry-run --category ssh,firewall
```

---

## CI/CD integration

### GitHub Actions

```yaml
- name: Security scan
  run: |
    curl -sSL https://rootwatch.net/install | bash
    rootwatch --output json | tee scan.json
    # Exit code 2 = critical failures found — fails the job
    rootwatch
```

Upload to GitHub Advanced Security:

```yaml
- name: Security scan (SARIF)
  run: |
    curl -sSL https://rootwatch.net/install | bash
    rootwatch --output sarif > results.sarif
- name: Upload to GitHub Advanced Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
    category: rootwatch
```

### GitLab CI

```yaml
security-scan:
  script:
    - curl -sSL https://rootwatch.net/install | bash
    - rootwatch --output json > gl-security-report.json
  artifacts:
    reports:
      security: gl-security-report.json
```

### Makefile target

```makefile
security:
	@rootwatch --output json | jq '.summary'
	@rootwatch  # exits 2 on critical failures

.PHONY: security
```

---

## Use as a Go library

The `pkg/checks` package is public. Import it directly to run checks from your own Go code.

### Run all checks

```go
import "github.com/rootwatch/rootwatch/pkg/checks"

runner := checks.NewRunner()

// Run all checks, no streaming
results, durationMs, err := runner.RunAll(nil, nil)

// Stream results as each check batch completes
results, durationMs, err := runner.RunAll(nil, func(batch []checks.CheckResult) {
    for _, r := range batch {
        fmt.Printf("%s: %s\n", r.Status, r.Title)
    }
})
```

### Filter by category

```go
import "github.com/rootwatch/rootwatch/pkg/checks"

categories := map[string]struct{}{
    "ssh":      {},
    "firewall": {},
}

runner := checks.NewRunner()
results, durationMs, err := runner.RunAll(categories, nil)
```

### Run a single check

```go
import "github.com/rootwatch/rootwatch/pkg/checks"

sshCheck := &checks.SSHCheck{}
results, err := sshCheck.Run()

for _, r := range results {
    fmt.Printf("[%s] %s — %s\n", r.Severity, r.Title, r.Status)
}
```

### CheckResult fields

```go
type CheckResult struct {
    Category      string // "ssh", "firewall", "kernel", etc.
    CheckID       string // unique slug, e.g. "ssh-root-login"
    Title         string // human-readable name
    Description   string // what this check tests
    Severity      string // "critical", "warning", "info"
    Status        string // "pass", "fail", "error", "skipped"
    CurrentValue  string // observed value on this system
    ExpectedValue string // value required to pass
    FixCommand    string // shell command to remediate
    FixWarning    string // amber caution shown before applying fix
    CISControl    string // e.g. "CIS 5.2.8"
}
```

### Build a custom report

```go
import (
    "github.com/rootwatch/rootwatch/pkg/checks"
    "github.com/rootwatch/rootwatch/internal/cli"
)

runner := checks.NewRunner()
results, durationMs, err := runner.RunAll(nil, nil)
if err != nil {
    log.Fatal(err)
}

report := cli.BuildReport("my-server", "Ubuntu 22.04", results, durationMs)

// Print as JSON
cli.PrintJSON(report)

// Print as SARIF
cli.PrintSARIF(report)

// Print as Markdown
cli.PrintMarkdown(report)
```

### Submit results to Rootwatch Cloud

```go
import (
    "github.com/rootwatch/rootwatch/internal/agent"
    "github.com/rootwatch/rootwatch/pkg/checks"
)

runner := checks.NewRunner()
results, durationMs, err := runner.RunAll(nil, nil)

submission := agent.ScanSubmission{
    Hostname:       "my-server",
    IPAddress:      "10.0.0.1",
    OS:             "Ubuntu 22.04",
    AgentVersion:   "0.1.0",
    ScanDurationMs: durationMs,
    Results:        results,
}

scanID, err := agent.SubmitWithToken("https://rootwatch.net", "rw_yourtoken", submission)
```

---

## Continuous monitoring (agent daemon)

For scheduled scans, trend tracking, and team dashboards, install the agent daemon via [Rootwatch Cloud](https://rootwatch.net):

```bash
curl -sSL https://rootwatch.net/install | bash -s -- --token rw_xxxxxxxxxxxxxxxx
```

The agent runs as a `systemd` service, scans on schedule, sends heartbeats, and responds to on-demand scan triggers from the dashboard.

---

## CLI vs Cloud

| Feature | CLI (free) | Cloud |
|---------|-----------|-------|
| Security scans | ✓ | ✓ |
| All 26+ check modules | ✓ | ✓ |
| JSON / Markdown / SARIF output | ✓ | ✓ |
| Fix command dry-run | ✓ | ✓ |
| Category filter | ✓ | ✓ |
| Continuous monitoring | — | ✓ |
| Score trend charts | — | ✓ |
| Scan diff (new/fixed since last scan) | — | ✓ |
| SOC 2 / ISO 27001 evidence reports | — | ✓ |
| Team & org management | — | ✓ |
| Email + Slack alerts | — | ✓ |
| CVE lookup (OSV.dev) | ✓ | ✓ |
| PDF scan reports | — | ✓ |

[Get started →](https://rootwatch.net)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
