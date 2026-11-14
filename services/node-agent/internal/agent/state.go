package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// persisted is what survives an agent restart: the generation applied to
// each workload. Everything else is re-observed from the host.
type persisted struct {
	Applied map[string]int64 `json:"applied"`
}

func loadState(path string) (persisted, error) {
	st := persisted{Applied: map[string]int64{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("read agent state: %w", err)
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		// A corrupt file only costs re-applying generations, which is
		// idempotent; start fresh rather than refuse to run.
		return persisted{Applied: map[string]int64{}}, nil
	}
	if st.Applied == nil {
		st.Applied = map[string]int64{}
	}
	return st, nil
}

// saveState writes atomically: a crash leaves the old or the new file.
func saveState(path string, st persisted) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write agent state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("write agent state: %w", err)
	}
	return nil
}

func statePath(dataDir string) string { return filepath.Join(dataDir, "agent-state.json") }
