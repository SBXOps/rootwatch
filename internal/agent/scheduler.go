package agent

import (
	"log"
	"time"

	"github.com/rootwatch/rootwatch/pkg/checks"
	"github.com/rootwatch/rootwatch/internal/config"
)

const AgentVersion = "0.1.0"

const heartbeatInterval = 60 * time.Second

func Start(cfg *config.Config) {
	log.Printf("Starting RootWatch Agent v%s", AgentVersion)

	runner := checks.NewRunner()

	// runScan executes a full scan, submits it, and returns the next scheduled interval.
	runScan := func() time.Duration {
		log.Println("Starting security scan...")
		startedAt := time.Now()
		results, duration, err := runner.RunAll(nil, nil)
		if err != nil {
			log.Printf("Scan failed: %v", err)
			return 5 * time.Minute // Retry shortly
		}

		log.Printf("Scan complete in %dms, found %d check results", duration, len(results))

		installedPkgs := checks.CollectInstalledPackages()

		submission := ScanSubmission{
			Hostname:          GetHostname(),
			IPAddress:         "0.0.0.0",
			OS:                GetOS(),
			AgentVersion:      AgentVersion,
			ScanDurationMs:    duration,
			StartedAt:         startedAt,
			Results:           results,
			InstalledPackages: installedPkgs,
		}

		scanInterval, err := Submit(cfg, submission)
		if err != nil {
			log.Printf("Failed to submit scan: %v", err)
			return 5 * time.Minute
		}

		if scanInterval > 0 {
			d := time.Duration(scanInterval) * time.Second
			log.Printf("Next scan scheduled in %v", d)
			return d
		}

		dur, _ := time.ParseDuration(cfg.ScanInterval)
		if dur == 0 {
			dur = 24 * time.Hour
		}
		log.Printf("Next scan scheduled in %v", dur)
		return dur
	}

	// Run a scan immediately on startup, then schedule the next one.
	nextScanIn := runScan()

	scanTimer := time.NewTimer(nextScanIn)
	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer scanTimer.Stop()
	defer heartbeatTicker.Stop()
	log.Printf("Healthcheck started (interval: %s)", heartbeatInterval)

	for {
		select {
		case <-scanTimer.C:
			nextScanIn = runScan()
			scanTimer.Reset(nextScanIn)

		case <-heartbeatTicker.C:
			scanNow, err := Heartbeat(cfg)
			if err != nil {
				log.Printf("Heartbeat failed: %v", err)
				continue
			}
			if scanNow {
				log.Println("On-demand scan requested via dashboard — running immediately")
				// Cancel the scheduled timer before running the unscheduled scan.
				if !scanTimer.Stop() {
					select {
					case <-scanTimer.C:
					default:
					}
				}
				nextScanIn = runScan()
				scanTimer.Reset(nextScanIn)
			}
		}
	}
}
