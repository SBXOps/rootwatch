package checks

import (
	"bytes"
	"os/exec"
	"strings"
)

// InstalledPackage holds the name, version, and ecosystem of a package for CVE lookup.
type InstalledPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

// CollectInstalledPackages returns a list of installed packages with versions.
// Supports Debian/Ubuntu (dpkg) and Alpine (apk).
func CollectInstalledPackages() []InstalledPackage {
	// Try dpkg (Debian/Ubuntu)
	if out, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output(); err == nil {
		return parseDebianPackages(out)
	}
	// Try apk (Alpine)
	if out, err := exec.Command("apk", "info", "-v").Output(); err == nil {
		return parseAlpinePackages(out)
	}
	return nil
}

func parseDebianPackages(out []byte) []InstalledPackage {
	// Detect ecosystem from /etc/os-release
	ecosystem := "Debian"
	if osRelease, err := exec.Command("sh", "-c", "grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '\"'").Output(); err == nil {
		id := strings.TrimSpace(string(osRelease))
		if id == "ubuntu" {
			ecosystem = "Ubuntu"
		}
	}

	var pkgs []InstalledPackage
	for _, line := range bytes.Split(out, []byte("\n")) {
		parts := strings.SplitN(string(line), "\t", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		if name == "" || version == "" {
			continue
		}
		// Strip epoch prefix (e.g. "2:1.2.3" → "1.2.3")
		if idx := strings.Index(version, ":"); idx != -1 {
			version = version[idx+1:]
		}
		// Strip Debian revision suffix (e.g. "1.2.3-4ubuntu1" → keep full; OSV handles this)
		pkgs = append(pkgs, InstalledPackage{
			Name:      name,
			Version:   version,
			Ecosystem: ecosystem,
		})
	}
	return pkgs
}

func parseAlpinePackages(out []byte) []InstalledPackage {
	var pkgs []InstalledPackage
	for _, line := range bytes.Split(out, []byte("\n")) {
		// apk info -v output: "package-name-1.2.3-r0"
		s := strings.TrimSpace(string(line))
		if s == "" {
			continue
		}
		// Split on last two hyphens to get name and version
		// e.g. "openssl-3.1.4-r2" → name="openssl", version="3.1.4-r2"
		lastHyphen := strings.LastIndex(s, "-")
		if lastHyphen == -1 {
			continue
		}
		versionPart := s[lastHyphen+1:]
		rest := s[:lastHyphen]
		secondLastHyphen := strings.LastIndex(rest, "-")
		if secondLastHyphen == -1 {
			continue
		}
		name := rest[:secondLastHyphen]
		version := rest[secondLastHyphen+1:] + "-" + versionPart
		pkgs = append(pkgs, InstalledPackage{
			Name:      name,
			Version:   version,
			Ecosystem: "Alpine",
		})
	}
	return pkgs
}
