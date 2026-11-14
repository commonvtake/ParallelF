package libvirt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
	"github.com/commonvtake/parallelf/services/node-agent/internal/runtime"
)

// MaxImageBytes bounds a base image download.
const MaxImageBytes = 10 << 30

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// imageInfo is the subset of `qemu-img info --output=json` the agent checks.
type imageInfo struct {
	Format          string `json:"format"`
	VirtualSize     int64  `json:"virtual-size"`
	BackingFilename string `json:"backing-filename"`
}

// ensureImage returns the path of the verified base image, downloading it
// on first use. The file is named by its digest, written to a temporary
// name, hashed while streaming and renamed only when the digest matches,
// so a partial or tampered download can never be used.
func (d *Driver) ensureImage(ctx context.Context, img cloudagent.Image, progress runtime.Progress) (string, imageInfo, error) {
	if !sha256Pattern.MatchString(img.SHA256) {
		return "", imageInfo{}, errors.New("VM images must be pinned by SHA-256")
	}
	u, err := url.Parse(img.Source)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", imageInfo{}, errors.New("VM images must be downloaded over https")
	}
	path := filepath.Join(d.dataDir, "images", img.SHA256+".qcow2")

	d.imageMu.Lock()
	defer d.imageMu.Unlock()

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := d.download(ctx, img, path, progress); err != nil {
			return "", imageInfo{}, err
		}
	} else if err != nil {
		return "", imageInfo{}, err
	}
	info, err := d.inspectImage(ctx, path)
	if err != nil {
		return "", imageInfo{}, err
	}
	return path, info, nil
}

func (d *Driver) download(ctx context.Context, img cloudagent.Image, path string, progress runtime.Progress) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".partial"
	defer func() { _ = os.Remove(tmp) }()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, img.Source, nil)
	if err != nil {
		return err
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return fmt.Errorf("download image: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download image: HTTP %d from %s", resp.StatusCode, u(img.Source))
	}
	if resp.ContentLength > MaxImageBytes {
		return fmt.Errorf("image is larger than %d GiB", MaxImageBytes>>30)
	}

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	hash := sha256.New()
	counter := &progressWriter{total: resp.ContentLength, report: progress, last: time.Now()}
	n, err := io.Copy(io.MultiWriter(f, hash, counter), io.LimitReader(resp.Body, MaxImageBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("download image: %w", err)
	}
	if n > MaxImageBytes {
		return fmt.Errorf("image is larger than %d GiB", MaxImageBytes>>30)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != img.SHA256 {
		return fmt.Errorf("image checksum mismatch: expected %s, got %s", img.SHA256, got)
	}
	return os.Rename(tmp, path)
}

// u strips credentials and queries from a URL for messages.
func u(raw string) string {
	p, err := url.Parse(raw)
	if err != nil {
		return "the image URL"
	}
	return p.Scheme + "://" + p.Host + p.Path
}

// inspectImage refuses anything but a self-contained qcow2: a backing-file
// reference inside a downloaded image could point QEMU at any host file.
func (d *Driver) inspectImage(ctx context.Context, path string) (imageInfo, error) {
	out, err := d.run.Run(ctx, "qemu-img", "info", "--output=json", path)
	if err != nil {
		return imageInfo{}, err
	}
	var info imageInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return imageInfo{}, fmt.Errorf("qemu-img info: %w", err)
	}
	if info.Format != "qcow2" {
		return imageInfo{}, fmt.Errorf("image format is %q; only qcow2 is supported", info.Format)
	}
	if info.BackingFilename != "" {
		return imageInfo{}, errors.New("image references a backing file; refusing to use it")
	}
	return info, nil
}

type progressWriter struct {
	total, written int64
	report         runtime.Progress
	last           time.Time
}

func (p *progressWriter) Write(b []byte) (int, error) {
	p.written += int64(len(b))
	if time.Since(p.last) >= 3*time.Second {
		p.last = time.Now()
		if p.total > 0 {
			p.report(fmt.Sprintf("downloading image %d%%", p.written*100/p.total))
		} else {
			p.report(fmt.Sprintf("downloading image %d MiB", p.written>>20))
		}
	}
	return len(b), nil
}

// sizeArg is the overlay size: the flavor's disk, or the image's virtual
// size if that is larger (a smaller overlay would truncate the guest disk).
func sizeArg(flavorGiB int, virtualBytes int64) string {
	want := int64(flavorGiB) << 30
	if virtualBytes > want {
		want = virtualBytes
	}
	gib := (want + (1 << 30) - 1) >> 30
	return fmt.Sprintf("%dG", gib)
}

// cleanName keeps a file name free of path separators.
func cleanName(id string) (string, error) {
	if id == "" || strings.ContainsAny(id, `/\.`) {
		return "", fmt.Errorf("invalid workload id %q", id)
	}
	return id, nil
}
