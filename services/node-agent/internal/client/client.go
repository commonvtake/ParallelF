// Package client talks to pf-cloudd's agent endpoint and keeps the node
// credential on disk.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
)

// ErrUnauthorized means the control plane rejected the credential.
var ErrUnauthorized = errors.New("control plane rejected the credential")

// Credentials identify this node to the control plane.
type Credentials struct {
	NodeID   string `json:"node_id"`
	Token    string `json:"token"`
	Name     string `json:"name"`
	CloudURL string `json:"cloud_url"`
}

// LoadCredentials reads the credential file; ok is false if there is none.
func LoadCredentials(path string) (Credentials, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Credentials{}, false, nil
	}
	if err != nil {
		return Credentials{}, false, err
	}
	var c Credentials
	if err := json.Unmarshal(raw, &c); err != nil || c.Token == "" {
		return Credentials{}, false, nil
	}
	return c, true, nil
}

// SaveCredentials writes the credential file readable by its owner only.
func SaveCredentials(path string, c Credentials) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Client calls the agent API.
type Client struct {
	base string
	http *http.Client
}

// New returns a client for the agent endpoint at base.
func New(base string) *Client {
	return &Client{base: base, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) post(ctx context.Context, path, token string, in, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(cloudagent.VersionHeader, cloudagent.Version)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		var p struct {
			Title  string `json:"title"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(body, &p)
		return fmt.Errorf("control plane answered %d: %s %s", resp.StatusCode, p.Title, p.Detail)
	}
	return json.Unmarshal(body, out)
}

// Register joins the node with the cluster join token.
func (c *Client) Register(ctx context.Context, joinToken string, req cloudagent.RegisterRequest) (cloudagent.RegisterResponse, error) {
	var resp cloudagent.RegisterResponse
	err := c.post(ctx, "/agent/v1/register", joinToken, req, &resp)
	return resp, err
}

// Sync reports observations and returns the desired state.
func (c *Client) Sync(ctx context.Context, token string, req cloudagent.SyncRequest) (cloudagent.SyncResponse, error) {
	var resp cloudagent.SyncResponse
	err := c.post(ctx, "/agent/v1/sync", token, req, &resp)
	return resp, err
}
