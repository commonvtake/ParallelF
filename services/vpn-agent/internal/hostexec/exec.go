// Package hostexec runs host programs (ip, wg, nft, conntrack) without a
// shell, so no argument is ever interpreted as shell syntax.
package hostexec

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner executes name with args, feeding stdin when it is not nil.
type Runner interface {
	Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
}

// Exec runs real processes with a per-command timeout.
type Exec struct{ Timeout time.Duration }

// Run implements Runner. The error includes the program's stderr.
func (r Exec) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.Bytes(), fmt.Errorf("%s %s: %s", name, strings.Join(firstWords(args, 3), " "), msg)
	}
	return stdout.Bytes(), nil
}

func firstWords(args []string, n int) []string {
	if len(args) > n {
		return args[:n]
	}
	return args
}
