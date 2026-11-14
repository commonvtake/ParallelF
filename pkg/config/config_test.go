package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoaderReadsTypedValues(t *testing.T) {
	l := FromMap(map[string]string{
		"PF_NAME":    "  core ",
		"PF_PORT":    "9001",
		"PF_DEBUG":   "true",
		"PF_TIMEOUT": "1500ms",
		"PF_URL":     "http://keycloak:8080/realms/parallelf/",
		"PF_LEVEL":   "DEBUG",
	})

	if got := l.String("PF_NAME", "x"); got != "core" {
		t.Errorf("String = %q, want trimmed value", got)
	}
	if got := l.String("PF_MISSING", "fallback"); got != "fallback" {
		t.Errorf("String default = %q", got)
	}
	if got := l.Int("PF_PORT", 1, 1, 65535); got != 9001 {
		t.Errorf("Int = %d", got)
	}
	if !l.Bool("PF_DEBUG", false) {
		t.Error("Bool = false, want true")
	}
	if got := l.Duration("PF_TIMEOUT", time.Second); got != 1500*time.Millisecond {
		t.Errorf("Duration = %v", got)
	}
	if got := l.URL("PF_URL").String(); got != "http://keycloak:8080/realms/parallelf" {
		t.Errorf("URL = %q, want trailing slash removed", got)
	}
	if got := l.OneOf("PF_LEVEL", "info", "debug", "info"); got != "debug" {
		t.Errorf("OneOf = %q, want canonical lower-case value", got)
	}
	if err := l.Err(); err != nil {
		t.Fatalf("Err = %v, want nil", err)
	}
}

func TestLoaderCollectsEveryError(t *testing.T) {
	l := FromMap(map[string]string{
		"PF_PORT":    "70000",
		"PF_DEBUG":   "maybe",
		"PF_TIMEOUT": "-1s",
		"PF_URL":     "keycloak:8080",
		"PF_LEVEL":   "loud",
		"PF_EMPTY":   "   ",
	})
	l.Required("PF_EMPTY")
	l.Int("PF_PORT", 1, 1, 65535)
	l.Bool("PF_DEBUG", false)
	l.Duration("PF_TIMEOUT", time.Second)
	l.URL("PF_URL")
	l.OneOf("PF_LEVEL", "info", "debug", "info")
	l.Secret("PF_SECRET")

	err := l.Err()
	if err == nil {
		t.Fatal("Err = nil, want errors")
	}
	for _, key := range []string{"PF_EMPTY", "PF_PORT", "PF_DEBUG", "PF_TIMEOUT", "PF_URL", "PF_LEVEL", "PF_SECRET"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q does not mention %s", err, key)
		}
	}
}

func TestSecretPrefersEnvThenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	l := FromMap(map[string]string{"PF_A": "from-env", "PF_A_FILE": path, "PF_B_FILE": path})
	if got := l.Secret("PF_A"); got != "from-env" {
		t.Errorf("Secret(PF_A) = %q, want env value", got)
	}
	if got := l.Secret("PF_B"); got != "from-file" {
		t.Errorf("Secret(PF_B) = %q, want trimmed file content", got)
	}
	if err := l.Err(); err != nil {
		t.Fatalf("Err = %v", err)
	}

	missing := FromMap(map[string]string{"PF_C_FILE": filepath.Join(t.TempDir(), "nope")})
	missing.Secret("PF_C")
	if missing.Err() == nil {
		t.Error("Err = nil for unreadable secret file")
	}
}

func TestInvalidIsReported(t *testing.T) {
	l := FromMap(map[string]string{})
	l.Invalid("PF_X", "must be %d characters", 24)
	if err := l.Err(); err == nil || !strings.Contains(err.Error(), "PF_X: must be 24 characters") {
		t.Fatalf("got %v", err)
	}
}
