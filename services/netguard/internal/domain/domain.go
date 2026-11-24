// Package domain holds pf-netguardd's resource model and the rules that do
// not need the database: validation of analyst input, scope issuing, alert
// and incident state transitions.
package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/commonvtake/parallelf/pkg/ngsensor"
)

// Errors the API maps to problems.
var (
	ErrNotFound         = errors.New("not found")
	ErrNameTaken        = errors.New("name already used")
	ErrInvalidState     = errors.New("invalid state for this operation")
	ErrUnauthorizedSens = errors.New("unknown sensor credential")
	ErrSensorActive     = errors.New("sensor still reporting")
)

// Severities, lowest first.
var Severities = []string{"info", "low", "medium", "high", "critical"}

// SeverityRank orders severities; unknown values rank lowest.
func SeverityRank(s string) int { return slices.Index(Severities, s) }

// Alert statuses.
const (
	AlertOpen         = "open"
	AlertAcknowledged = "acknowledged"
	AlertClosed       = "closed"
	AlertSuppressed   = "suppressed"
)

// Incident statuses.
const (
	IncidentOpen          = "open"
	IncidentInvestigating = "investigating"
	IncidentResolved      = "resolved"
)

// Actor performs an audited change.
type Actor struct {
	Type      string
	ID        string
	Name      string
	RequestID string
}

// Label is how an actor appears in timelines and events.
func (a Actor) Label() string {
	if a.Name != "" {
		return a.Name
	}
	return a.ID
}

// Overview counts what the dashboard shows first.
type Overview struct {
	Sensors          int            `json:"sensors"`
	SensorsReporting int            `json:"sensors_reporting"`
	Events24h        int64          `json:"events_24h"`
	EventsByKind     map[string]int `json:"events_by_kind_1h"`
	OpenAlerts       map[string]int `json:"open_alerts_by_severity"`
	OpenIncidents    int            `json:"open_incidents"`
	Assets           int            `json:"assets"`
	Unattributed     int            `json:"unattributed_assets"`
	ActiveScopes     int            `json:"active_scopes"`
}

// Sensor is a registered pf-ng-sensor.
type Sensor struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Status       string    `json:"status"` // reporting, silent
	AgentVersion string    `json:"agent_version"`
	Engine       string    `json:"engine"`
	Interfaces   []string  `json:"interfaces"`
	EngineError  string    `json:"engine_error"`
	EventsTotal  int64     `json:"events_total"`
	RegisteredAt time.Time `json:"registered_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

// SensorSilentAfter marks a sensor silent when it has not delivered a batch.
const SensorSilentAfter = 30 * time.Second

// SensorRegistration is what registration stores.
type SensorRegistration struct {
	ngsensor.RegisterRequest
	TokenHash []byte
}

// Party is an address and what NetGuard knows about it.
type Party struct {
	IP           string `json:"ip"`
	Kind         string `json:"kind"` // workload, vpn_device, network_gateway, infrastructure, unknown
	EntityID     string `json:"entity_id,omitempty"`
	Name         string `json:"name,omitempty"`
	ProjectID    string `json:"project_id,omitempty"`
	OwnerSubject string `json:"owner_subject,omitempty"`
}

// Attribution of both ends of an alert.
type Attribution struct {
	Source      *Party `json:"source,omitempty"`
	Destination *Party `json:"destination,omitempty"`
}

// Event is a stored telemetry record.
type Event struct {
	ID          int64             `json:"id"`
	SensorID    string            `json:"sensor_id"`
	Time        time.Time         `json:"ts"`
	Kind        string            `json:"kind"`
	Interface   string            `json:"iface"`
	SrcIP       string            `json:"src_ip,omitempty"`
	SrcPort     int               `json:"src_port,omitempty"`
	DstIP       string            `json:"dst_ip,omitempty"`
	DstPort     int               `json:"dst_port,omitempty"`
	Proto       string            `json:"proto,omitempty"`
	CommunityID string            `json:"community_id,omitempty"`
	AppProto    string            `json:"app_proto,omitempty"`
	Details     map[string]string `json:"details"`
	RawSHA256   string            `json:"raw_sha256"`
}

// EventFilter selects events.
type EventFilter struct {
	IP     string
	Kind   string
	Since  time.Time
	Before int64
	Limit  int
}

// Alert is a detection.
type Alert struct {
	ID              string            `json:"id"`
	Detector        string            `json:"detector"`
	RuleID          string            `json:"rule_id"`
	Severity        string            `json:"severity"`
	Title           string            `json:"title"`
	SrcIP           string            `json:"src_ip,omitempty"`
	DstIP           string            `json:"dst_ip,omitempty"`
	Status          string            `json:"status"`
	Count           int64             `json:"count"`
	FirstSeenAt     time.Time         `json:"first_seen_at"`
	LastSeenAt      time.Time         `json:"last_seen_at"`
	FirstEventID    int64             `json:"first_event_id,omitempty"`
	LastEventID     int64             `json:"last_event_id,omitempty"`
	Details         map[string]string `json:"details"`
	Attribution     Attribution       `json:"attribution"`
	IncidentID      string            `json:"incident_id,omitempty"`
	StatusReason    string            `json:"status_reason,omitempty"`
	StatusBy        string            `json:"status_by,omitempty"`
	SuppressedUntil *time.Time        `json:"suppressed_until,omitempty"`
}

// AlertFilter selects alerts.
type AlertFilter struct {
	Status   string
	Detector string
	Severity string // minimum
	IP       string
	Limit    int
}

// AlertChange is an analyst's decision on an alert.
type AlertChange struct {
	Status          string
	Reason          string
	SuppressFor     time.Duration
	SuppressedUntil time.Time // computed
}

// Allowed alert transitions: open -> acknowledged/closed/suppressed;
// acknowledged -> closed/suppressed; suppressed -> open (lifted) or closed.
var alertTransitions = map[string][]string{
	AlertOpen:         {AlertAcknowledged, AlertClosed, AlertSuppressed},
	AlertAcknowledged: {AlertClosed, AlertSuppressed},
	AlertSuppressed:   {AlertOpen, AlertClosed},
}

// CanTransitionAlert reports whether an alert may move from one status to
// another.
func CanTransitionAlert(from, to string) bool { return slices.Contains(alertTransitions[from], to) }

// MaxSuppression bounds how long an alert can be muted.
const MaxSuppression = 30 * 24 * time.Hour

// ValidateAlertChange checks an analyst's input.
func ValidateAlertChange(c AlertChange) error {
	v := &ValidationError{}
	if !slices.Contains([]string{AlertAcknowledged, AlertClosed, AlertSuppressed, AlertOpen}, c.Status) {
		v.add("status", "enum", "One of acknowledged, closed, suppressed or open.")
	}
	if utf8.RuneCountInString(c.Reason) > 1000 {
		v.add("reason", "length", "At most 1000 characters.")
	}
	if c.Status == AlertSuppressed {
		if c.SuppressFor < time.Minute || c.SuppressFor > MaxSuppression {
			v.add("suppress_for", "range", "Between 1m and 720h.")
		}
		if strings.TrimSpace(c.Reason) == "" {
			v.add("reason", "required", "Say why this alert is suppressed.")
		}
	}
	return v.orNil()
}

// Incident groups alerts and evidence.
type Incident struct {
	ID         string     `json:"id"`
	Title      string     `json:"title"`
	Severity   string     `json:"severity"`
	Status     string     `json:"status"`
	Summary    string     `json:"summary"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	AlertCount int        `json:"alert_count"`
}

// IncidentInput opens an incident.
type IncidentInput struct {
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Summary  string   `json:"summary"`
	AlertIDs []string `json:"alert_ids"`
}

// IncidentUpdate changes an incident.
type IncidentUpdate struct {
	Status   string   `json:"status,omitempty"`
	Note     string   `json:"note,omitempty"`
	AlertIDs []string `json:"alert_ids,omitempty"` // alerts to link
}

// TimelineEntry is one line of an incident's history.
type TimelineEntry struct {
	ID    int64     `json:"id"`
	Time  time.Time `json:"ts"`
	Actor string    `json:"actor"`
	Kind  string    `json:"kind"`
	Body  string    `json:"body"`
	Ref   string    `json:"ref,omitempty"`
}

// IncidentDetail is an incident with its alerts, timeline and evidence.
type IncidentDetail struct {
	Incident
	Alerts   []Alert         `json:"alerts"`
	Timeline []TimelineEntry `json:"timeline"`
	Evidence []Evidence      `json:"evidence"`
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidateIncident checks a new incident.
func ValidateIncident(in IncidentInput) error {
	v := &ValidationError{}
	if n := utf8.RuneCountInString(strings.TrimSpace(in.Title)); n < 3 || n > 200 {
		v.add("title", "length", "3 to 200 characters.")
	}
	if SeverityRank(in.Severity) < 0 {
		v.add("severity", "enum", "One of info, low, medium, high or critical.")
	}
	if utf8.RuneCountInString(in.Summary) > 5000 {
		v.add("summary", "length", "At most 5000 characters.")
	}
	validateIDs(v, in.AlertIDs)
	return v.orNil()
}

func validateIDs(v *ValidationError, ids []string) {
	if len(ids) > 100 {
		v.add("alert_ids", "too_many", "At most 100 alerts at a time.")
	}
	for _, id := range ids {
		if !uuidPattern.MatchString(id) {
			v.add("alert_ids", "format", fmt.Sprintf("%q is not an alert id.", id))
			return
		}
	}
}

// Incident transitions: open -> investigating/resolved; investigating ->
// resolved; resolved -> investigating (reopened).
var incidentTransitions = map[string][]string{
	IncidentOpen:          {IncidentInvestigating, IncidentResolved},
	IncidentInvestigating: {IncidentResolved},
	IncidentResolved:      {IncidentInvestigating},
}

// CanTransitionIncident reports whether an incident may change status.
func CanTransitionIncident(from, to string) bool {
	return slices.Contains(incidentTransitions[from], to)
}

// ValidateIncidentUpdate checks an incident change.
func ValidateIncidentUpdate(u IncidentUpdate) error {
	v := &ValidationError{}
	if u.Status != "" && !slices.Contains([]string{IncidentOpen, IncidentInvestigating, IncidentResolved}, u.Status) {
		v.add("status", "enum", "One of investigating or resolved.")
	}
	if utf8.RuneCountInString(u.Note) > 5000 {
		v.add("note", "length", "At most 5000 characters.")
	}
	validateIDs(v, u.AlertIDs)
	if u.Status == "" && strings.TrimSpace(u.Note) == "" && len(u.AlertIDs) == 0 {
		v.add("status", "required", "Change the status, add a note or link alerts.")
	}
	return v.orNil()
}

// Evidence is an immutable item attached to an incident.
type Evidence struct {
	ID         string    `json:"id"`
	IncidentID string    `json:"incident_id"`
	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	MediaType  string    `json:"media_type"`
	Size       int       `json:"size"`
	SHA256     string    `json:"sha256"`
	Ref        string    `json:"ref,omitempty"`
	AddedBy    string    `json:"added_by"`
	AddedAt    time.Time `json:"added_at"`
}

// EvidenceInput adds evidence. For kind event or alert, Ref names the
// record and the server captures its current content; for note and file,
// Content is what the analyst supplies.
type EvidenceInput struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Ref       string `json:"ref"`
	MediaType string `json:"media_type"`
	Content   []byte `json:"content"` // base64 in JSON
}

// MaxEvidenceBytes bounds one evidence item.
const MaxEvidenceBytes = 1 << 20

var mediaTypePattern = regexp.MustCompile(`^[a-z]+/[a-z0-9.+-]{1,60}$`)

// ValidateEvidence checks an evidence item.
func ValidateEvidence(in EvidenceInput) error {
	v := &ValidationError{}
	if n := utf8.RuneCountInString(in.Name); n < 1 || n > 200 {
		v.add("name", "length", "1 to 200 characters.")
	}
	switch in.Kind {
	case "event", "alert":
		if in.Ref == "" {
			v.add("ref", "required", "The id of the "+in.Kind+".")
		}
		if len(in.Content) > 0 {
			v.add("content", "forbidden", "The server captures the "+in.Kind+" itself.")
		}
	case "note", "file":
		if len(in.Content) == 0 {
			v.add("content", "required", "The evidence content.")
		}
		if len(in.Content) > MaxEvidenceBytes {
			v.add("content", "size", "At most 1 MiB.")
		}
		if in.Kind == "file" && !mediaTypePattern.MatchString(in.MediaType) {
			v.add("media_type", "format", "A media type such as application/vnd.tcpdump.pcap or text/plain.")
		}
	default:
		v.add("kind", "enum", "One of event, alert, note or file.")
	}
	return v.orNil()
}

// EvidenceVerification is the result of recomputing digests.
type EvidenceVerification struct {
	Checked  int      `json:"checked"`
	Valid    bool     `json:"valid"`
	Mismatch []string `json:"mismatch"`
}

// Asset is an address seen on a monitored network.
type Asset struct {
	IP          string    `json:"ip"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	FirstIface  string    `json:"first_iface"`
	Events      int64     `json:"events"`
	OpenPorts   []int     `json:"open_ports"`
	Party       Party     `json:"attribution"`
}

// Scope is an issued discovery scope.
type Scope struct {
	ngsensor.Scope
	AuthorizationNote string               `json:"authorization_note"`
	CreatedBy         string               `json:"created_by"`
	RevokedAt         *time.Time           `json:"revoked_at,omitempty"`
	RevokedBy         string               `json:"revoked_by,omitempty"`
	Status            string               `json:"status"` // active, expired, revoked
	Signed            ngsensor.SignedScope `json:"-"`
}

// ScopeInput asks for a discovery scope.
type ScopeInput struct {
	Name              string   `json:"name"`
	CIDRs             []string `json:"cidrs"`
	Techniques        []string `json:"techniques"`
	Ports             []int    `json:"ports"`
	RatePPS           int      `json:"rate_pps"`
	Duration          string   `json:"duration"`
	AuthorizationNote string   `json:"authorization_note"`
}

// MaxScopeDuration bounds how long a scope stays valid.
const MaxScopeDuration = 24 * time.Hour

// NamePattern is the format of scope names.
var NamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)

// BuildScope validates input and returns the scope to sign. allowed lists
// the networks this platform owns; every CIDR must lie inside one of them.
func BuildScope(in ScopeInput, id string, now time.Time, allowed []netip.Prefix) (ngsensor.Scope, error) {
	v := &ValidationError{}
	if !NamePattern.MatchString(in.Name) {
		v.add("name", "format", "3-40 characters: lower-case letters, digits and hyphens; starts with a letter.")
	}
	if n := utf8.RuneCountInString(strings.TrimSpace(in.AuthorizationNote)); n < 10 || n > 1000 {
		v.add("authorization_note", "length", "10 to 1000 characters: who authorised this discovery, and why.")
	}
	d, err := time.ParseDuration(in.Duration)
	if in.Duration == "" {
		d, err = time.Hour, nil
	}
	if err != nil || d < time.Minute || d > MaxScopeDuration {
		v.add("duration", "range", "Between 1m and 24h.")
	}
	rate := in.RatePPS
	if rate == 0 {
		rate = 20
	}
	cidrs := make([]string, 0, len(in.CIDRs))
	for _, c := range in.CIDRs {
		p, perr := netip.ParsePrefix(strings.TrimSpace(c))
		if perr != nil {
			v.add("cidrs", "format", fmt.Sprintf("%q is not a CIDR.", c))
			continue
		}
		p = p.Masked()
		inside := false
		for _, a := range allowed {
			if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
				inside = true
			}
		}
		if !inside {
			v.add("cidrs", "not_owned", fmt.Sprintf("%s is not inside a ParallelF network (the VPN tunnel or a Cloud network).", p))
		}
		cidrs = append(cidrs, p.String())
	}
	ports := slices.Clone(in.Ports)
	slices.Sort(ports)
	ports = slices.Compact(ports)
	s := ngsensor.Scope{
		ID: id, Name: in.Name, CIDRs: cidrs, Techniques: in.Techniques, Ports: ports, RatePPS: rate,
		IssuedAt: now.UTC(), ValidUntil: now.UTC().Add(d),
	}
	if len(v.Errors) == 0 {
		if gerr := ngsensor.CheckGuards(s); gerr != nil {
			v.add("cidrs", "guard", gerr.Error())
		}
	}
	return s, v.orNil()
}

// FieldError describes one invalid input field.
type FieldError struct {
	Field, Code, Message string
}

// ValidationError carries the field errors of a request.
type ValidationError struct{ Errors []FieldError }

func (e *ValidationError) Error() string {
	if len(e.Errors) == 0 {
		return "invalid request"
	}
	return e.Errors[0].Field + ": " + e.Errors[0].Message
}

func (e *ValidationError) add(field, code, msg string) {
	e.Errors = append(e.Errors, FieldError{field, code, msg})
}

func (e *ValidationError) orNil() error {
	if len(e.Errors) == 0 {
		return nil
	}
	return e
}
