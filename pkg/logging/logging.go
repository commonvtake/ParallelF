// Package logging configures structured JSON logging on top of log/slog.
//
// Every record carries the service name and version. Request-scoped
// attributes (request_id, subject, ...) are attached to a context with
// With and are added to each record logged with that context.
package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

type ctxKey struct{}

// Options configures a logger.
type Options struct {
	Service string
	Version string
	Level   string // debug, info, warn or error
}

// New returns a JSON logger that writes one object per line to w.
func New(w io.Writer, opts Options) *slog.Logger {
	base := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: ParseLevel(opts.Level),
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				a.Key = "ts"
			}
			return a
		},
	})
	return slog.New(&contextHandler{Handler: base}).With(
		slog.String("service", opts.Service),
		slog.String("version", opts.Version),
	)
}

// ParseLevel converts a level name to a slog.Level. Unknown names map to info.
func ParseLevel(name string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// With returns a context whose log records also carry attrs.
func With(ctx context.Context, attrs ...slog.Attr) context.Context {
	existing, _ := ctx.Value(ctxKey{}).([]slog.Attr)
	merged := make([]slog.Attr, 0, len(existing)+len(attrs))
	merged = append(merged, existing...)
	merged = append(merged, attrs...)
	return context.WithValue(ctx, ctxKey{}, merged)
}

type contextHandler struct {
	slog.Handler
}

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if attrs, ok := ctx.Value(ctxKey{}).([]slog.Attr); ok {
		r.AddAttrs(attrs...)
	}
	return h.Handler.Handle(ctx, r)
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{Handler: h.Handler.WithGroup(name)}
}
