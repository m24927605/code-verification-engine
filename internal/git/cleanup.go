package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// WorkspacePrefix identifies engine-managed workspace directories.
	WorkspacePrefix = "cve-"

	// DefaultRetention is the stale workspace retention window.
	DefaultRetention = 24 * time.Hour
)

// PruneStaleWorkspaces removes engine-managed workspace directories under
// tmpRoot that are older than the retention duration. Only directories
// prefixed with "cve-" are considered. Returns the number of pruned directories.
func PruneStaleWorkspaces(tmpRoot string, retention time.Duration) (int, error) {
	entries, err := os.ReadDir(tmpRoot)
	if err != nil {
		return 0, fmt.Errorf("read tmpRoot: %w", err)
	}

	cutoff := time.Now().Add(-retention)
	pruned := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !strings.HasPrefix(entry.Name(), WorkspacePrefix) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			wsPath := filepath.Join(tmpRoot, entry.Name())
			if err := os.RemoveAll(wsPath); err != nil {
				continue // best-effort
			}
			pruned++
		}
	}
	return pruned, nil
}
