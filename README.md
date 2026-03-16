# Rootwatch

Open source Linux security scanner. Run a CIS benchmark audit on any server in seconds — no account required.

```
rootwatch: running security checks...

  rootwatch scan — prod-web-01
  Ubuntu 22.04.3 LTS  ·  16 Mar 2024 09:41 UTC

  Security Score:  52 / 100

  ✓ Passed  38     ✗ Failed  14     Critical  3     ⊘ Skipped  2

  Failed Checks
  ────────────────────────────────────────────────────────────────────────────
  SEVERITY   CHECK                                  FIX
  CRITICAL   SSH root login is permitted             sed -i 's/PermitRootLogin.*/P...
  CRITICAL   Password authentication enabled         sed -i 's/PasswordAuthentica...
  CRITICAL   Firewall is inactive                    ufw enable
  WARNING    Unattended upgrades not configured      apt install unattended-upgrades
  ...
```

## Quick start

```bash
# Install
curl -sSL https://rootwatch.dev/install | bash

# Run a scan
rootwatch

# JSON output (CI-friendly)
rootwatch --output json

# Markdown report
rootwatch --output markdown > security-report.md
```

## What it checks

| Category | Checks |
|----------|--------|
| SSH | Root login, key auth, protocol version, idle timeout |
| Firewall | ufw/iptables status, default deny, open ports |
| Users | Root account, sudo config, password policies, shadow permissions |
| Filesystem | SUID/SGID bits, world-writable files, /tmp noexec |
| Packages | Security updates available, outdated packages |
| Kernel | Sysctl hardening, ASLR, core dumps, dmesg restriction |
| Network | Listening services, IP forwarding, ICMP redirects |
| Docker | Daemon socket exposure, privileged containers, user namespaces |
| SSL/TLS | Certificate expiry, weak cipher suites |

All checks map to [CIS Benchmark](https://www.cisecurity.org/cis-benchmarks) controls.

## CLI usage

```
rootwatch [flags]

FLAGS
  --output, -o    Output format: table (default), json, markdown
  --token, -t     Submit results to Rootwatch Cloud dashboard
  --api-url       Cloud API URL (default: https://api.rootwatch.dev)
  --version, -v   Print version
  --help, -h      Show help

EXIT CODES
  0   No critical failures
  1   Scan error
  2   One or more critical failures found
```

## CI/CD integration

GitHub Actions example:

```yaml
- name: Security scan
  run: |
    curl -sSL https://rootwatch.dev/install | bash
    rootwatch --output json | tee scan.json
    # Fail the pipeline if critical issues found (exit code 2)
    rootwatch
```

GitLab CI:

```yaml
security:
  script:
    - curl -sSL https://rootwatch.dev/install | bash
    - rootwatch --output json > gl-security-report.json
  artifacts:
    reports:
      security: gl-security-report.json
```

## Use as a Go library

The check modules are public — import them in your own tools:

```go
import "github.com/rootwatch/rootwatch/pkg/checks"

runner := checks.NewRunner()
results, durationMs, err := runner.RunAll()
```

Or run a specific category:

```go
import "github.com/rootwatch/rootwatch/pkg/checks"

sshResults := checks.RunSSH()
firewallResults := checks.RunFirewall()
```

## Install the agent daemon

For continuous monitoring and a full dashboard, create a free account at [rootwatch.dev](https://rootwatch.dev) and install the agent:

```bash
curl -sSL https://rootwatch.dev/install | bash -s -- --token rw_xxxxxxxxxxxxxxxx
```

The agent runs as a `systemd` service, scans on schedule, and submits results to your [Rootwatch Cloud](https://app.rootwatch.dev) dashboard for trend tracking, compliance reports, and team alerts.

## Rootwatch Cloud

| Feature | CLI (free) | Cloud |
|---------|-----------|-------|
| Security scans | ✓ | ✓ |
| All check modules | ✓ | ✓ |
| JSON/Markdown output | ✓ | ✓ |
| Continuous monitoring | — | ✓ |
| Score trend charts | — | ✓ |
| SOC 2 / ISO 27001 reports | — | ✓ |
| Team & org management | — | ✓ |
| Email + Slack alerts | — | ✓ |
| CVE lookup | — | ✓ |

[Get started →](https://rootwatch.dev)

## License

Apache 2.0 — see [LICENSE](LICENSE).
