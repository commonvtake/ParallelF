// Package tail reads a growing log file from a persisted offset. It
// notices rotation (a new inode) and truncation, and only advances the
// stored offset when the caller commits, so a crash re-delivers lines
// instead of losing them.
package tail

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// State is the persisted position.
type State struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
	// Head is the file's first bytes (up to 64): a truncated file rewritten
	// to the same length keeps its inode and size but not its head.
	Head []byte `json:"head"`
}

const headSize = 64

// Tailer follows one file.
type Tailer struct {
	Path      string
	StatePath string
	MaxLine   int

	state   State
	pending State
}

// Open loads the stored position.
func Open(path, statePath string, maxLine int) (*Tailer, error) {
	t := &Tailer{Path: path, StatePath: statePath, MaxLine: maxLine}
	raw, err := os.ReadFile(statePath)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		_ = json.Unmarshal(raw, &t.state)
	}
	t.pending = t.state
	return t, nil
}

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// Read returns up to max complete lines after the committed position
// (overlong lines are skipped and counted). Call Commit once they are
// safely delivered.
func (t *Tailer) Read(max int) (lines [][]byte, skipped int, err error) {
	f, err := os.Open(t.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	head := make([]byte, headSize)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	start := t.state
	common := min(len(head), len(start.Head))
	if ino := inode(fi); ino != start.Inode || fi.Size() < start.Offset || string(head[:common]) != string(start.Head[:common]) {
		start = State{Inode: ino} // rotated or truncated: begin the new file
	}
	if _, err := f.Seek(start.Offset, io.SeekStart); err != nil {
		return nil, 0, err
	}
	r := bufio.NewReaderSize(f, 64<<10)
	offset := start.Offset
	for len(lines) < max {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// Skip the rest of an overlong line.
			n := int64(len(line))
			for errors.Is(err, bufio.ErrBufferFull) {
				line, err = r.ReadSlice('\n')
				n += int64(len(line))
			}
			if err != nil {
				break // incomplete: wait for the rest
			}
			offset += n
			skipped++
			continue
		}
		if err != nil {
			break // EOF without a newline: an incomplete line
		}
		offset += int64(len(line))
		if len(line) > t.MaxLine {
			skipped++
			continue
		}
		lines = append(lines, append([]byte(nil), line[:len(line)-1]...))
	}
	t.pending = State{Inode: start.Inode, Offset: offset, Head: head}
	return lines, skipped, nil
}

// Commit persists the position reached by the last Read.
func (t *Tailer) Commit() error {
	t.state = t.pending
	raw, _ := json.Marshal(t.state)
	if err := os.MkdirAll(filepath.Dir(t.StatePath), 0o700); err != nil {
		return err
	}
	tmp := t.StatePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, t.StatePath)
}
