// Package client talks to pf-netguardd's sensor endpoint and keeps the
// sensor credential (and the pinned scope-signing key) on disk.
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

	"github.com/commonvtake/parallelf/pkg/ngsensor"
)

// ErrUnauthorized means pf-netguardd rejected the credential.
var ErrUnauthorized = errors.New("netguard rejected the credential")

// Credentials identify this sensor. ScopePublicKey is pinned at
// registration: scopes signed with any other key are refused.
type Credentials struct {
	SensorID       string `json:"sensor_id"`
	Token          string `json:"token"`
	Name           string `json:"name"`
	NetGuardURL    string `json:"netguard_url"`
	ScopePublicKey string `json:"scope_public_key"`
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

// Client calls the sensor API.
type Client struct {
	base string
	http *http.Client
}

// New returns a client for the sensor endpoint at base.
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
	req.Header.Set(ngsensor.VersionHeader, ngsensor.Version)
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
		return fmt.Errorf("netguard answered %d: %s %s", resp.StatusCode, p.Title, p.Detail)
	}
	return json.Unmarshal(body, out)
}

// Register joins the sensor with the join token.
func (c *Client) Register(ctx context.Context, joinToken string, req ngsensor.RegisterRequest) (ngsensor.RegisterResponse, error) {
	var resp ngsensor.RegisterResponse
	err := c.post(ctx, ngsensor.PathRegister, joinToken, req, &resp)
	return resp, err
}

// Ingest delivers a batch.
func (c *Client) Ingest(ctx context.Context, token string, req ngsensor.IngestRequest) (ngsensor.IngestResponse, error) {
	var resp ngsensor.IngestResponse
	err := c.post(ctx, ngsensor.PathIngest, token, req, &resp)
	return resp, err
}
