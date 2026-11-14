package domain

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/commonvtake/parallelf/pkg/httpx"
)

// NamePattern is shared by networks and workloads: it becomes part of a
// hostname and of container names, so it is DNS-label safe.
var NamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// Limits on user-supplied workload settings.
const (
	MaxSSHKeys      = 10
	MaxSSHKeyLength = 4096
	MaxEnvVars      = 32
	MaxEnvValue     = 4096
)

// NetworkInput is a request to create a network.
type NetworkInput struct {
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	CIDR      string `json:"cidr"`
}

// WorkloadInput is a request to create a workload.
type WorkloadInput struct {
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	// Template is a template name; the newest version that is not
	// deprecated is used unless TemplateVersion is set.
	Template        string `json:"template"`
	TemplateVersion int    `json:"template_version,omitempty"`
	// Flavor defaults to the template's default flavor.
	Flavor            string            `json:"flavor,omitempty"`
	NetworkID         string            `json:"network_id"`
	SSHAuthorizedKeys []string          `json:"ssh_authorized_keys,omitempty"`
	Env               map[string]string `json:"env,omitempty"`
}

// Validate normalises the input and returns one FieldError per problem.
func (in *WorkloadInput) Validate() []httpx.FieldError {
	in.Name = strings.TrimSpace(in.Name)
	in.Template = strings.TrimSpace(in.Template)
	in.Flavor = strings.TrimSpace(in.Flavor)

	var errs []httpx.FieldError
	if !NamePattern.MatchString(in.Name) {
		errs = append(errs, httpx.FieldError{Field: "name", Code: "format",
			Message: "3-40 characters: lower-case letters, digits and hyphens; starts with a letter."})
	}
	if in.Template == "" {
		errs = append(errs, httpx.FieldError{Field: "template", Code: "required", Message: "A template is required."})
	}
	if in.TemplateVersion < 0 {
		errs = append(errs, httpx.FieldError{Field: "template_version", Code: "range", Message: "Version must be positive."})
	}
	if len(in.SSHAuthorizedKeys) > MaxSSHKeys {
		errs = append(errs, httpx.FieldError{Field: "ssh_authorized_keys", Code: "too_many",
			Message: fmt.Sprintf("At most %d keys.", MaxSSHKeys)})
	}
	for i, key := range in.SSHAuthorizedKeys {
		key = strings.TrimSpace(key)
		in.SSHAuthorizedKeys[i] = key
		if !validSSHKey(key) {
			errs = append(errs, httpx.FieldError{Field: fmt.Sprintf("ssh_authorized_keys[%d]", i), Code: "format",
				Message: "Must be one OpenSSH public key line, e.g. ssh-ed25519 AAAA... comment."})
		}
	}
	if len(in.Env) > MaxEnvVars {
		errs = append(errs, httpx.FieldError{Field: "env", Code: "too_many", Message: fmt.Sprintf("At most %d variables.", MaxEnvVars)})
	}
	for k, v := range in.Env {
		if !envKeyPattern.MatchString(k) || len(v) > MaxEnvValue || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			errs = append(errs, httpx.FieldError{Field: "env." + k, Code: "format",
				Message: "Names are letters, digits and underscores; values are at most 4096 bytes of text."})
		}
	}
	return errs
}

func validSSHKey(key string) bool {
	if key == "" || len(key) > MaxSSHKeyLength || strings.ContainsAny(key, "\r\n\x00") {
		return false
	}
	fields := strings.Fields(key)
	if len(fields) < 2 {
		return false
	}
	switch fields[0] {
	case "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
		return true
	}
	return false
}

// Operation is a change of a workload's desired state requested by a user.
type Operation string

// Operations.
const (
	OpStart  Operation = "start"
	OpStop   Operation = "stop"
	OpRetry  Operation = "retry"
	OpDelete Operation = "delete"
)

// WorkloadFilter narrows a workload listing.
type WorkloadFilter struct {
	ProjectID string
	NodeID    string
	State     string
}

// AuditFilter narrows an audit listing. Entries are returned newest first.
type AuditFilter struct {
	ResourceType string
	ResourceID   string
	BeforeSeq    int64
	Limit        int
}

// NodeRegistration is what a joining agent tells the control plane.
type NodeRegistration struct {
	Name         string
	AgentVersion string
	TokenHash    []byte
	KVM          bool
	Docker       bool
	Hypervisor   string
	CPUCount     int
	MemoryMiB    int64
	DiskGiB      int64
	ReservedCPUs int
	ReservedMiB  int64
	ReservedGiB  int64
}

// DesiredWorkload is a workload assigned to a node, with everything needed
// to tell the node what to run.
type DesiredWorkload struct {
	Workload Workload
	Template Template
	Network  Network
}

// HostDesiredState is the complete desired state of one node.
type HostDesiredState struct {
	Workloads []DesiredWorkload
	// Converging is true while any workload on the node is not settled; the
	// agent is then asked to sync more often.
	Converging bool
}

// MetricWindows are the windows the API accepts.
var MetricWindows = map[string]time.Duration{
	"15m": 15 * time.Minute,
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
}

// AuditVerification is the result of recomputing the audit hash chain.
type AuditVerification struct {
	Valid   bool  `json:"valid"`
	Entries int64 `json:"entries"`
	// FirstInvalidSeq is the first entry whose hash does not match.
	FirstInvalidSeq int64     `json:"first_invalid_seq,omitempty"`
	CheckedAt       time.Time `json:"checked_at"`
}

// ValidationError is a store-level rejection that maps to HTTP 422.
type ValidationError struct {
	Field   string
	Code    string
	Message string
}

func (e *ValidationError) Error() string { return e.Field + ": " + e.Message }

// QuotaError reports which project limits a request would exceed.
type QuotaError struct {
	Exceeded []string
	Quota    Quota
	Usage    Usage
}

func (e *QuotaError) Error() string { return fmt.Sprintf("%s: %v", ErrQuotaExceeded, e.Exceeded) }

// Unwrap lets errors.Is match ErrQuotaExceeded.
func (e *QuotaError) Unwrap() error { return ErrQuotaExceeded }
