package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

// DecodeJSON strictly decodes a single JSON object from the request body
// into dst. Unknown fields, trailing data and non-JSON content types are
// rejected. It returns a Problem describing the failure, or nil.
func DecodeJSON(r *http.Request, dst any) *Problem {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		p := NewProblem("unsupported-media-type", http.StatusUnsupportedMediaType,
			"Unsupported media type", "Content-Type must be application/json.")
		return &p
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			p := NewProblem("payload-too-large", http.StatusRequestEntityTooLarge,
				"Payload too large", "The request body exceeds the allowed size.")
			return &p
		}
		p := BadRequest("The request body is not valid JSON for this endpoint.")
		return &p
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		p := BadRequest("The request body must contain a single JSON object.")
		return &p
	}
	return nil
}
