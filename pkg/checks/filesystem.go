package checks

import (
	"strings"
)

type FilesystemCheck struct{}

func (c *FilesystemCheck) Name() string { return "filesystem" }

func (c *FilesystemCheck) Run() ([]CheckResult, error) {
	var results []CheckResult

	// Read /proc/mounts directly — more reliable than running `mount` on cloud VMs
	procMounts, err := readFile("/proc/mounts")
	if err != nil {
		return results, nil
	}

	lines := strings.Split(procMounts, "\n")
	tmpEntry := ""
	for _, line := range lines {
		fields := strings.Fields(line)
		// /proc/mounts format: device mountpoint fstype options dump pass
		if len(fields) >= 4 && fields[1] == "/tmp" {
			tmpEntry = line
			break
		}
	}

	if tmpEntry == "" {
		// /tmp is not a separate mount — common on cloud VMs using rootfs for /tmp.
		// This is not a failure; flag as informational so users know they could harden further.
		results = append(results, CheckResult{
			Category:      "filesystem",
			CheckID:       "fs-tmp-noexec",
			Title:         "/tmp Mounted with noexec",
			Description:   "Check mount options for /tmp",
			Severity:      "info",
			Status:        "skipped",
			CurrentValue:  "/tmp has no separate mount entry (shares rootfs)",
			ExpectedValue: "noexec mount option present",
			FixCommand:    "echo 'tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab && mount -o remount /tmp",
			FixWarning:    "Remounting /tmp can interrupt processes actively writing temp files. Test during a maintenance window.",
			CISControl:    "CIS 1.1.3",
		})
		return results, nil
	}

	// /tmp is separately mounted — check for noexec
	fields := strings.Fields(tmpEntry)
	opts := ""
	if len(fields) >= 4 {
		opts = fields[3]
	}

	status := "fail"
	val := "mounted without noexec"
	if strings.Contains(opts, "noexec") {
		status = "pass"
		val = "noexec"
	}

	results = append(results, CheckResult{
		Category:      "filesystem",
		CheckID:       "fs-tmp-noexec",
		Title:         "/tmp Mounted with noexec",
		Description:   "Check mount options for /tmp",
		Severity:      "warning",
		Status:        status,
		CurrentValue:  val,
		ExpectedValue: "noexec",
		FixCommand:    "echo 'tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab && mount -o remount /tmp",
		FixWarning:    "Remounting /tmp can interrupt processes actively writing temp files. Test during a maintenance window.",
		CISControl:    "CIS 1.1.3",
	})

	return results, nil
}
