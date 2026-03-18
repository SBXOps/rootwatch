package checks

import (
	"fmt"
	"os"
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
			&CVECheck{},
		},
	}
}

// RunAll runs all checks sequentially. If onBatch is non-nil it is called
// after each check completes with that check's results, enabling live output.
// If categories is non-nil and non-empty, only checks whose Name() appears in
// the set are run (e.g. map[string]struct{}{"ssh": {}, "firewall": {}}).
func (r *Runner) RunAll(categories map[string]struct{}, onBatch func([]CheckResult)) ([]CheckResult, int, error) {
	start := time.Now()
	var allResults []CheckResult

	for _, check := range r.checks {
		if len(categories) > 0 {
			if _, ok := categories[check.Name()]; !ok {
				continue
			}
		}
		results, err := check.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error running check %s: %v\n", check.Name(), err)
			continue
		}
		if onBatch != nil {
			onBatch(results)
		}
		allResults = append(allResults, results...)
	}

	durationMs := int(time.Since(start).Milliseconds())
	return allResults, durationMs, nil
}
