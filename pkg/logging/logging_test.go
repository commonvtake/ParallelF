package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestLoggerWritesStructuredJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, Options{Service: "pf-core", Version: "1.2.3", Level: "info"})

	ctx := With(context.Background(), slog.String("request_id", "req-1"))
	ctx = With(ctx, slog.String("subject", "user-1"))
	logger.InfoContext(ctx, "project created", slog.String("project_id", "p-1"))

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, buf.String())
	}
	want := map[string]string{
		"service":    "pf-core",
		"version":    "1.2.3",
		"level":      "INFO",
		"msg":        "project created",
		"request_id": "req-1",
		"subject":    "user-1",
		"project_id": "p-1",
	}
	for key, value := range want {
		if rec[key] != value {
			t.Errorf("%s = %v, want %q", key, rec[key], value)
		}
	}
	if _, ok := rec["ts"]; !ok {
		t.Error("record has no ts field")
	}
}

func TestLoggerRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, Options{Service: "s", Version: "v", Level: "warn"})
	logger.Info("hidden")
	if buf.Len() != 0 {
		t.Errorf("info record written at warn level: %s", buf.String())
	}
	logger.Warn("shown")
	if buf.Len() == 0 {
		t.Error("warn record not written")
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug, "INFO": slog.LevelInfo, " warn ": slog.LevelWarn,
		"warning": slog.LevelWarn, "error": slog.LevelError, "": slog.LevelInfo, "nope": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}
