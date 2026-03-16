package checks

import (
	"fmt"
	"time"
)

type Runner struct {
	checks []Check
}

func NewRunner() *Runner {
	return &Runner{
		checks: []Check{
			&SSHCheck{},
			&FirewallCheck{},
			&UsersCheck{},
			&PackagesCheck{},
			&FilesystemCheck{},
			&NetworkCheck{},
			&KernelCheck{},
			&SSLChecks{},
			&DockerCheck{},
			&NetworkAdvancedChecks{},
			&FilesystemAdvancedChecks{},
			&UsersAdvancedChecks{},
			&UpdatesChecks{},
		},
	}
}

func (r *Runner) RunAll() ([]CheckResult, int, error) {
	start := time.Now()
	var allResults []CheckResult

	for _, check := range r.checks {
		results, err := check.Run()
		if err != nil {
			// In production, we'd log this and continue, but for simplicity:
			fmt.Printf("Error running check %s: %v\n", check.Name(), err)
			continue
		}
		allResults = append(allResults, results...)
	}

	durationMs := int(time.Since(start).Milliseconds())
	return allResults, durationMs, nil
}
