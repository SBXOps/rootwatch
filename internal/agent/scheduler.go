package agent

import (
	"log"
	"time"

	"github.com/rootwatch/rootwatch/pkg/checks"
	"github.com/rootwatch/rootwatch/internal/config"
)

const AgentVersion = "0.1.0"

func Start(cfg *config.Config) {
	log.Printf("Starting RootWatch Agent v%s", AgentVersion)

	runner := checks.NewRunner()
	nextScanIn := time.Second * 0 // Run immediately on start

	for {
		time.Sleep(nextScanIn)

		log.Println("Starting security scan...")
		startedAt := time.Now()
		results, duration, err := runner.RunAll()
		if err != nil {
			log.Printf("Scan failed: %v", err)
			nextScanIn = 5 * time.Minute // Retry shortly if completely failed
			continue
		}

		log.Printf("Scan complete in %dms, found %d check results", duration, len(results))

		installedPkgs := checks.CollectInstalledPackages()

		submission := ScanSubmission{
			Hostname:          GetHostname(),
			IPAddress:         "0.0.0.0", // Simplified for v1, actual IP often detected server-side or via outbound call logic
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
			nextScanIn = 5 * time.Minute // Retry submission slowly
			continue
		}

		if scanInterval > 0 {
			nextScanIn = time.Duration(scanInterval) * time.Second
		} else {
			// Fallback config interval
			dur, _ := time.ParseDuration(cfg.ScanInterval)
			if dur == 0 {
				dur = 24 * time.Hour
			}
			nextScanIn = dur
		}

		log.Printf("Next scan scheduled in %v", nextScanIn)
	}
}
