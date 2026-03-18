package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/rootwatch/rootwatch/internal/agent"
	"github.com/rootwatch/rootwatch/internal/cli"
	"github.com/rootwatch/rootwatch/pkg/checks"
)

const version = "0.1.0"

func main() {
	// Detect subcommands before flag parsing
	if len(os.Args) > 1 && os.Args[1] == "fix" {
		runFix(os.Args[2:])
		return
	}

	args := parseArgs()

	if args.version {
		fmt.Printf("rootwatch v%s\n", version)
		os.Exit(0)
	}

	if args.help {
		printUsage()
		os.Exit(0)
	}

	runner := checks.NewRunner()
	hostname := agent.GetHostname()
	osStr := agent.GetOS()

	var results []checks.CheckResult
	var durationMs int
	var err error

	if args.output == cli.FormatTable {
		// Streaming mode: print header then each result live as it arrives.
		cli.PrintStreamingHeader(hostname, osStr)
		results, durationMs, err = runner.RunAll(args.categories, func(batch []checks.CheckResult) {
			for _, r := range batch {
				cli.PrintResultLive(r)
			}
		})
	} else {
		fmt.Fprintln(os.Stderr, "rootwatch: running security checks...")
		results, durationMs, err = runner.RunAll(args.categories, nil)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "rootwatch: scan failed: %v\n", err)
		os.Exit(1)
	}

	report := cli.BuildReport(hostname, osStr, results, durationMs)

	if args.token != "" {
		submitToCloud(args, results, durationMs, hostname, osStr)
	}

	switch args.output {
	case cli.FormatJSON:
		cli.PrintJSON(report)
	case cli.FormatMarkdown:
		cli.PrintMarkdown(report)
	case cli.FormatSARIF:
		cli.PrintSARIF(report)
	default:
		cli.PrintStreamingFooter(report.Score, report.Summary)
	}

	// Exit with non-zero if critical failures found
	if report.Summary.Critical > 0 {
		os.Exit(2)
	}
}

func runFix(argv []string) {
	dryRun := false
	var categories map[string]struct{}

	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "--dry-run":
			dryRun = true
		case "--category", "-c":
			if i+1 < len(argv) {
				i++
				categories = make(map[string]struct{})
				for _, cat := range strings.Split(argv[i], ",") {
					cat = strings.TrimSpace(cat)
					if cat != "" {
						categories[cat] = struct{}{}
					}
				}
			}
		case "--help", "-h":
			fmt.Printf(`rootwatch fix — print remediation commands for all failed checks

USAGE
  rootwatch fix [flags]

FLAGS
  --dry-run       Print fix commands without executing anything (default behaviour)
  --category, -c  Limit to specific check categories (comma-separated)
  --help, -h      Show this help

EXAMPLES
  # Print all fix commands
  rootwatch fix --dry-run

  # Print fix commands for SSH and firewall only
  rootwatch fix --dry-run --category ssh,firewall

NOTE
  No commands are executed. Copy-paste each fix and run it manually as root.
`)
			os.Exit(0)
		}
	}

	if !dryRun {
		fmt.Fprintln(os.Stderr, "rootwatch fix: use --dry-run to print fix commands (execution not yet supported)")
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "rootwatch: running security checks...")
	runner := checks.NewRunner()
	results, _, err := runner.RunAll(categories, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rootwatch: scan failed: %v\n", err)
		os.Exit(1)
	}

	hostname := agent.GetHostname()
	cli.PrintFixDryRun(hostname, results)
}

func submitToCloud(args cliArgs, results []checks.CheckResult, durationMs int, hostname, osStr string) {
	installedPkgs := checks.CollectInstalledPackages()

	submission := agent.ScanSubmission{
		Hostname:          hostname,
		IPAddress:         "0.0.0.0",
		OS:                osStr,
		AgentVersion:      version,
		ScanDurationMs:    durationMs,
		Results:           results,
		InstalledPackages: installedPkgs,
	}

	apiURL := args.apiURL
	if apiURL == "" {
		apiURL = "https://rootwatch.net"
	}

	fmt.Fprintln(os.Stderr, "rootwatch: submitting results to Rootwatch Cloud...")
	_, err := agent.SubmitWithToken(apiURL, args.token, submission)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rootwatch: cloud submission failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "rootwatch: showing local results only")
	} else {
		fmt.Fprintln(os.Stderr, "rootwatch: results submitted. View at https://rootwatch.net")
	}
}

type cliArgs struct {
	output     string
	token      string
	apiURL     string
	categories map[string]struct{}
	help       bool
	version    bool
}

func parseArgs() cliArgs {
	args := cliArgs{output: cli.FormatTable}
	argv := os.Args[1:]

	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "--output", "-o":
			if i+1 < len(argv) {
				i++
				args.output = argv[i]
			}
		case "--token", "-t":
			if i+1 < len(argv) {
				i++
				args.token = argv[i]
			}
		case "--api-url":
			if i+1 < len(argv) {
				i++
				args.apiURL = argv[i]
			}
		case "--category", "-c":
			if i+1 < len(argv) {
				i++
				args.categories = make(map[string]struct{})
				for _, cat := range strings.Split(argv[i], ",") {
					cat = strings.TrimSpace(cat)
					if cat != "" {
						args.categories[cat] = struct{}{}
					}
				}
			}
		case "--help", "-h":
			args.help = true
		case "--version", "-v":
			args.version = true
		default:
			// ignore unknown flags gracefully
		}
	}

	return args
}

func printUsage() {
	fmt.Printf(`rootwatch v%s — open source Linux security scanner

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

EXAMPLES
  # Run a local scan and print results
  rootwatch

  # Output as JSON (pipe-friendly)
  rootwatch --output json

  # Generate a markdown report
  rootwatch --output markdown > report.md

  # Run only SSH and firewall checks
  rootwatch --category ssh,firewall

  # Upload results to GitHub Advanced Security
  rootwatch --output sarif > results.sarif
  gh api repos/{owner}/{repo}/code-scanning/sarifs \
    --field sarif=@results.sarif --field ref=refs/heads/main \
    --field commit_sha=$(git rev-parse HEAD)

  # Print all fix commands (nothing is executed)
  rootwatch fix --dry-run

  # Submit results to Rootwatch Cloud
  rootwatch --token rw_xxxxxxxxxxxxxxxx

  # Use in CI (exits 2 if critical failures found)
  rootwatch --output json | jq '.summary'

UPGRADE
  Continuous monitoring, trends, audit-ready hardening reports, and team features
  are available at https://rootwatch.net

`, version)
}
