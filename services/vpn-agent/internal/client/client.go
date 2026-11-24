// Package client talks to pf-vpnd's agent endpoint and keeps the gateway
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

	"github.com/commonvtake/parallelf/pkg/vpnagent"
)

// ErrUnauthorized means the control plane rejected the credential.
var ErrUnauthorized = errors.New("control plane rejected the credential")

// Credentials identify this gateway to the control plane.
type Credentials struct {
	GatewayID string `json:"gateway_id"`
	Token     string `json:"token"`
	Name      string `json:"name"`
	VPNURL    string `json:"vpn_url"`
}

// Load reads the credential file; ok is false if there is none.
func Load(path string) (Credentials, bool, error) {
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

// Save writes the credential file readable by its owner only.
func Save(path string, c Credentials) error {
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

// New returns a client for the agent endpoint at base. Its timeout covers
// the longest long-poll.
func New(base string) *Client {
	return &Client{base: base, http: &http.Client{Timeout: vpnagent.MaxWait + 15*time.Second}}
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
	req.Header.Set(vpnagent.VersionHeader, vpnagent.Version)
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

// Register joins the gateway with the join token.
func (c *Client) Register(ctx context.Context, joinToken string, req vpnagent.RegisterRequest) (vpnagent.RegisterResponse, error) {
	var resp vpnagent.RegisterResponse
	err := c.post(ctx, vpnagent.PathRegister, joinToken, req, &resp)
	return resp, err
}

// Sync reports observations and returns the desired state.
func (c *Client) Sync(ctx context.Context, token string, req vpnagent.SyncRequest) (vpnagent.SyncResponse, error) {
	var resp vpnagent.SyncResponse
	err := c.post(ctx, vpnagent.PathSync, token, req, &resp)
	return resp, err
}
