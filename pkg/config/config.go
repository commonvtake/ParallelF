// Package config loads typed service configuration from environment
// variables. All lookups are collected so a service reports every
// configuration problem at startup instead of failing on the first one.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Loader reads configuration values and accumulates validation errors.
type Loader struct {
	lookup   func(string) (string, bool)
	readFile func(string) ([]byte, error)
	errs     []error
}

// FromEnv returns a Loader backed by the process environment.
func FromEnv() *Loader {
	return &Loader{lookup: os.LookupEnv, readFile: os.ReadFile}
}

// FromMap returns a Loader backed by a fixed map. It is intended for tests.
func FromMap(values map[string]string) *Loader {
	return &Loader{
		lookup: func(key string) (string, bool) {
			v, ok := values[key]
			return v, ok
		},
		readFile: os.ReadFile,
	}
}

func (l *Loader) get(key string) (string, bool) {
	v, ok := l.lookup(key)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	return v, v != ""
}

func (l *Loader) fail(key, format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf("%s: %s", key, fmt.Sprintf(format, args...)))
}

// Invalid records a problem with key found by the caller's own validation.
func (l *Loader) Invalid(key, format string, args ...any) {
	l.fail(key, format, args...)
}

// String returns the value of key, or def when it is unset or empty.
func (l *Loader) String(key, def string) string {
	if v, ok := l.get(key); ok {
		return v
	}
	return def
}

// Required returns the value of key and records an error when it is missing.
func (l *Loader) Required(key string) string {
	v, ok := l.get(key)
	if !ok {
		l.fail(key, "is required")
	}
	return v
}

// Secret returns a required secret. The value is read from KEY, or from the
// file named by KEY_FILE (the Docker and Kubernetes secrets convention).
func (l *Loader) Secret(key string) string {
	if v, ok := l.get(key); ok {
		return v
	}
	path, ok := l.get(key + "_FILE")
	if !ok {
		l.fail(key, "is required (set %s or %s_FILE)", key, key)
		return ""
	}
	raw, err := l.readFile(path)
	if err != nil {
		l.fail(key+"_FILE", "cannot read secret file: %v", err)
		return ""
	}
	v := strings.TrimSpace(string(raw))
	if v == "" {
		l.fail(key+"_FILE", "secret file is empty")
	}
	return v
}

// Int returns key parsed as an integer within [minValue, maxValue].
func (l *Loader) Int(key string, def, minValue, maxValue int) int {
	v, ok := l.get(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		l.fail(key, "must be an integer")
		return def
	}
	if n < minValue || n > maxValue {
		l.fail(key, "must be between %d and %d", minValue, maxValue)
		return def
	}
	return n
}

// Bool returns key parsed as a boolean.
func (l *Loader) Bool(key string, def bool) bool {
	v, ok := l.get(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		l.fail(key, "must be true or false")
		return def
	}
	return b
}

// Duration returns key parsed with time.ParseDuration. It must be positive.
func (l *Loader) Duration(key string, def time.Duration) time.Duration {
	v, ok := l.get(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		l.fail(key, "must be a positive duration such as 5s or 2m")
		return def
	}
	return d
}

// URL returns a required absolute http(s) URL without a trailing slash.
func (l *Loader) URL(key string) *url.URL {
	v, ok := l.get(key)
	if !ok {
		l.fail(key, "is required")
		return &url.URL{}
	}
	u, err := url.Parse(strings.TrimRight(v, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		l.fail(key, "must be an absolute http(s) URL")
		return &url.URL{}
	}
	return u
}

// OneOf returns key when it is one of allowed, otherwise def.
func (l *Loader) OneOf(key, def string, allowed ...string) string {
	v, ok := l.get(key)
	if !ok {
		return def
	}
	for _, a := range allowed {
		if strings.EqualFold(v, a) {
			return a
		}
	}
	l.fail(key, "must be one of %s", strings.Join(allowed, ", "))
	return def
}

// Err returns every recorded problem joined into one error, or nil.
func (l *Loader) Err() error {
	if len(l.errs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration: %w", errors.Join(l.errs...))
}
