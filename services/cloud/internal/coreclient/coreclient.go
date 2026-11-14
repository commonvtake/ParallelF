// Package coreclient asks pf-core whether a project exists.
//
// Projects belong to pf-core; pf-cloudd never reads its schema. The
// caller's own access token is forwarded, so pf-core applies the caller's
// permissions and nothing here needs a service credential.
package coreclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client calls pf-core.
type Client struct {
	base *url.URL
	http *http.Client
}

// New returns a client for pf-core at base (e.g. http://core:9001).
func New(base *url.URL, transport http.RoundTripper) *Client {
	return &Client{base: base, http: &http.Client{Transport: transport, Timeout: 5 * time.Second}}
}

// ProjectExists reports whether the project exists and is visible to the
// caller whose Authorization header is passed.
func (c *Client) ProjectExists(ctx context.Context, authorization, projectID string) (bool, error) {
	u := c.base.JoinPath("/api/v1/core/projects", projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("pf-core: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("pf-core answered %d", resp.StatusCode)
	}
}
