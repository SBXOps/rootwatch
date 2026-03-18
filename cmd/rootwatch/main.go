package main

import (
	"fmt"
	"os"

	"github.com/rootwatch/rootwatch/internal/agent"
	"github.com/rootwatch/rootwatch/internal/cli"
	"github.com/rootwatch/rootwatch/pkg/checks"
)

const version = "0.1.0"

func main() {
	args := parseArgs()

	if args.version {
		fmt.Printf("rootwatch v%s\n", version)
		os.Exit(0)
	}

	if args.help {
		printUsage()
		os.Exit(0)
	}

	// If a token is provided, submit results to the cloud API.
	// Otherwise run in pure local mode and print to stdout.
	runner := checks.NewRunner()

	fmt.Fprintln(os.Stderr, "rootwatch: running security checks...")
	results, durationMs, err := runner.RunAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "rootwatch: scan failed: %v\n", err)
		os.Exit(1)
	}

	hostname := agent.GetHostname()
	osStr := agent.GetOS()
	report := cli.BuildReport(hostname, osStr, results, durationMs)

	if args.token != "" {
		submitToCloud(args, results, durationMs, hostname, osStr)
	}

	switch args.output {
	case cli.FormatJSON:
		cli.PrintJSON(report)
	case cli.FormatMarkdown:
		cli.PrintMarkdown(report)
	default:
		cli.PrintTable(report)
	}

	// Exit with non-zero if critical failures found
	if report.Summary.Critical > 0 {
		os.Exit(2)
	}
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
	output string
	token  string
	apiURL string
	help   bool
	version bool
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

FLAGS
  --output, -o    Output format: table (default), json, markdown
  --token, -t     Rootwatch Cloud token (submit results to your dashboard)
  --api-url       Cloud API URL (default: https://rootwatch.net)
  --version, -v   Print version and exit
  --help, -h      Show this help

EXAMPLES
  # Run a local scan and print results
  rootwatch

  # Output as JSON (pipe-friendly)
  rootwatch --output json

  # Generate a markdown report
  rootwatch --output markdown > report.md

  # Submit results to Rootwatch Cloud
  rootwatch --token rw_xxxxxxxxxxxxxxxx

  # Use in CI (exits 2 if critical failures found)
  rootwatch --output json | jq '.summary'

UPGRADE
  Continuous monitoring, trends, compliance reports, and team features
  are available at https://rootwatch.net

`, version)
}
