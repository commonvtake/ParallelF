// Package httpx contains the HTTP building blocks shared by ParallelF Go
// services: RFC 9457 problem responses, middleware, health endpoints and a
// server runner with graceful shutdown.
package httpx

import (
	"encoding/json"
	"net/http"
)

// ProblemTypeBase is the prefix of every problem "type" URI.
const ProblemTypeBase = "https://parallelf.dev/problems/"

// FieldError describes one invalid request field.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// Problem is an RFC 9457 problem details object.
type Problem struct {
	Type      string       `json:"type"`
	Title     string       `json:"title"`
	Status    int          `json:"status"`
	Detail    string       `json:"detail,omitempty"`
	Instance  string       `json:"instance,omitempty"`
	RequestID string       `json:"request_id,omitempty"`
	Errors    []FieldError `json:"errors,omitempty"`
}

// NewProblem builds a problem with the given slug, status and detail.
func NewProblem(slug string, status int, title, detail string) Problem {
	return Problem{Type: ProblemTypeBase + slug, Title: title, Status: status, Detail: detail}
}

// Common problems. Details must never contain internal error text.
func BadRequest(detail string) Problem {
	return NewProblem("bad-request", http.StatusBadRequest, "Bad request", detail)
}

func Unauthorized(detail string) Problem {
	return NewProblem("unauthorized", http.StatusUnauthorized, "Authentication required", detail)
}

func Forbidden(detail string) Problem {
	return NewProblem("forbidden", http.StatusForbidden, "Permission denied", detail)
}

func NotFound(detail string) Problem {
	return NewProblem("not-found", http.StatusNotFound, "Resource not found", detail)
}

func Conflict(detail string) Problem {
	return NewProblem("conflict", http.StatusConflict, "Conflict", detail)
}

func Unprocessable(detail string, errs ...FieldError) Problem {
	p := NewProblem("validation", http.StatusUnprocessableEntity, "Validation failed", detail)
	p.Errors = errs
	return p
}

func Internal() Problem {
	return NewProblem("internal", http.StatusInternalServerError, "Internal server error",
		"The request could not be completed. Quote the request_id when reporting this.")
}

func BadGateway(detail string) Problem {
	return NewProblem("upstream-unavailable", http.StatusBadGateway, "Upstream service unavailable", detail)
}

// WriteProblem writes p as application/problem+json, filling instance and
// request_id from the request.
func WriteProblem(w http.ResponseWriter, r *http.Request, p Problem) {
	if p.Instance == "" {
		p.Instance = r.URL.Path
	}
	if p.RequestID == "" {
		p.RequestID = RequestIDFrom(r.Context())
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// WriteJSON writes v as a JSON response with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
