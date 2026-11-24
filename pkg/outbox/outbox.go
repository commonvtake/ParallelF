// Package outbox encodes domain events as CloudEvents with Protobuf
// (protojson) payloads and writes them to a service's transactional outbox
// table, in the same transaction as the change they describe.
package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// SchemaVersion is the ce-pfschemaversion of every event.
const SchemaVersion = "1"

// Event is one outbox row.
type Event struct {
	ID      string
	Subject string // NATS subject, e.g. pf.vpn.evt.device.revoked
	Type    string // fully qualified message name
	Payload []byte
	Headers map[string]string
}

// Encoder builds events for one producing service.
type Encoder struct {
	source string
	newID  func() string
	now    func() time.Time
}

// NewEncoder returns an encoder whose events carry ce-source = source.
func NewEncoder(source string, newID func() string, now func() time.Time) *Encoder {
	return &Encoder{source: source, newID: newID, now: now}
}

// Encode wraps msg. entity is the ce-subject ("device/<id>"); project, when
// set, becomes ce-pfproject.
func (e *Encoder) Encode(subject, entity, project string, msg proto.Message) (Event, error) {
	payload, err := protojson.Marshal(msg)
	if err != nil {
		return Event{}, fmt.Errorf("encode %s: %w", subject, err)
	}
	id := e.newID()
	eventType := string(msg.ProtoReflect().Descriptor().FullName())
	headers := map[string]string{
		"ce-specversion":     "1.0",
		"ce-id":              id,
		"ce-source":          e.source,
		"ce-type":            eventType,
		"ce-time":            e.now().UTC().Format(time.RFC3339Nano),
		"ce-subject":         entity,
		"ce-pfschemaversion": SchemaVersion,
		"content-type":       "application/json",
	}
	if project != "" {
		headers["ce-pfproject"] = project
	}
	return Event{ID: id, Subject: subject, Type: eventType, Payload: payload, Headers: headers}, nil
}

var schemaPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// Insert writes evt to <schema>.outbox.
func Insert(ctx context.Context, tx pgx.Tx, schema string, evt Event) error {
	if !schemaPattern.MatchString(schema) {
		return fmt.Errorf("outbox: invalid schema %q", schema)
	}
	headers, err := json.Marshal(evt.Headers)
	if err != nil {
		return fmt.Errorf("encode event headers: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO `+schema+`.outbox (id, subject, event_type, payload, headers)
		VALUES ($1::text::uuid, $2, $3, $4, $5)`, evt.ID, evt.Subject, evt.Type, evt.Payload, headers)
	if err != nil {
		return fmt.Errorf("insert outbox event: %w", err)
	}
	return nil
}
