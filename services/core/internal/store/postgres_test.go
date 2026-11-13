package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/pkg/ids"
	"github.com/commonvtake/parallelf/services/core/internal/projects"
)

// These are integration tests. They need a migrated database and run when
// PF_TEST_DATABASE_URL is set (see `make test-integration-go`).
func openTestStore(t *testing.T) *Postgres {
	t.Helper()
	url := os.Getenv("PF_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PF_TEST_DATABASE_URL is not set; skipping PostgreSQL integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	return s
}

func newProject(slug string) projects.Project {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return projects.Project{
		ID: ids.NewV7(), Slug: slug, Name: "Integration " + slug, Description: "created by a test",
		CreatedBy: "test-user", CreatedAt: now, UpdatedAt: now,
	}
}

func newEvent(eventType string) projects.OutboxEvent {
	id := ids.NewV7()
	return projects.OutboxEvent{
		ID: id, Subject: "pf.core.evt.test", Type: eventType,
		Payload: []byte(`{"projectId":"x"}`),
		Headers: map[string]string{"ce-id": id, "ce-type": eventType},
	}
}

func uniqueSlug(prefix string) string {
	// The random tail of a UUIDv7 keeps slugs unique across test runs.
	id := ids.NewV7()
	return prefix + "-" + id[len(id)-12:]
}

type outboxRow struct {
	subject, eventType string
	payload            []byte
	headers            map[string]string
	published          bool
}

func readOutbox(t *testing.T, s *Postgres, id string) (outboxRow, bool) {
	t.Helper()
	var (
		row         outboxRow
		rawHeaders  string
		publishedAt *time.Time
	)
	err := s.pool.QueryRow(context.Background(),
		`SELECT subject, event_type, payload, headers::text, published_at FROM core.outbox WHERE id = $1::text::uuid`, id).
		Scan(&row.subject, &row.eventType, &row.payload, &rawHeaders, &publishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return outboxRow{}, false
	}
	if err != nil {
		t.Fatalf("read outbox row: %v", err)
	}
	if err := json.Unmarshal([]byte(rawHeaders), &row.headers); err != nil {
		t.Fatalf("outbox headers are not JSON: %v", err)
	}
	row.published = publishedAt != nil
	return row, true
}

func TestCreateGetDeleteRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	p := newProject(uniqueSlug("roundtrip"))
	created := newEvent("parallelf.core.v1.ProjectCreated")
	if err := s.Create(ctx, p, created); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.CreatedAt.Equal(p.CreatedAt) || !got.UpdatedAt.Equal(p.UpdatedAt) {
		t.Errorf("timestamps changed in the round trip: got %v / %v, want %v", got.CreatedAt, got.UpdatedAt, p.CreatedAt)
	}
	got.CreatedAt, got.UpdatedAt = p.CreatedAt, p.UpdatedAt
	if got != p {
		t.Errorf("Get = %+v, want %+v", got, p)
	}

	row, ok := readOutbox(t, s, created.ID)
	if !ok {
		t.Fatal("no outbox row was written for the create")
	}
	if row.subject != created.Subject || row.eventType != created.Type || string(row.payload) != string(created.Payload) ||
		row.headers["ce-id"] != created.ID || row.published {
		t.Errorf("unexpected outbox row: %+v", row)
	}

	deleted := newEvent("parallelf.core.v1.ProjectDeleted")
	if err := s.Delete(ctx, p.ID, deleted); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, p.ID); !errors.Is(err, projects.ErrNotFound) {
		t.Errorf("Get after delete = %v, want ErrNotFound", err)
	}
	if _, ok := readOutbox(t, s, deleted.ID); !ok {
		t.Error("no outbox row was written for the delete")
	}
}

func TestCreateDuplicateSlugIsAtomic(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	slug := uniqueSlug("dup")
	first := newProject(slug)
	if err := s.Create(ctx, first, newEvent("first")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(context.Background(), first.ID, newEvent("cleanup")) })

	second := newProject(slug)
	evt := newEvent("second")
	if err := s.Create(ctx, second, evt); !errors.Is(err, projects.ErrSlugTaken) {
		t.Fatalf("Create duplicate = %v, want ErrSlugTaken", err)
	}
	if _, ok := readOutbox(t, s, evt.ID); ok {
		t.Error("an outbox row exists for a project that was not created")
	}
	if _, err := s.Get(ctx, second.ID); !errors.Is(err, projects.ErrNotFound) {
		t.Errorf("rejected project is readable: %v", err)
	}
}

func TestOutboxFailureRollsBackTheProject(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	existing := newProject(uniqueSlug("evt"))
	evt := newEvent("first")
	if err := s.Create(ctx, existing, evt); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(context.Background(), existing.ID, newEvent("cleanup")) })

	// Reusing the event id makes the outbox insert fail after the project
	// insert succeeded; the whole transaction must roll back.
	p := newProject(uniqueSlug("rollback"))
	if err := s.Create(ctx, p, evt); err == nil {
		t.Fatal("Create succeeded with a duplicate event id")
	}
	if _, err := s.Get(ctx, p.ID); !errors.Is(err, projects.ErrNotFound) {
		t.Errorf("project was committed without its event: %v", err)
	}
}

func TestDeleteMissingProject(t *testing.T) {
	s := openTestStore(t)
	evt := newEvent("never")
	if err := s.Delete(context.Background(), ids.NewV7(), evt); !errors.Is(err, projects.ErrNotFound) {
		t.Fatalf("Delete = %v, want ErrNotFound", err)
	}
	if _, ok := readOutbox(t, s, evt.ID); ok {
		t.Error("an outbox row exists for a delete that did not happen")
	}
}

func TestListOrdersByIDAndPages(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	var created []projects.Project
	for range 3 {
		p := newProject(uniqueSlug("list"))
		if err := s.Create(ctx, p, newEvent("list")); err != nil {
			t.Fatalf("Create: %v", err)
		}
		created = append(created, p)
		t.Cleanup(func() { _ = s.Delete(context.Background(), p.ID, newEvent("cleanup")) })
	}

	// Page from just before the first project created here so rows left by
	// other tests do not matter.
	firstPage, err := s.List(ctx, "", 1000)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for i := 1; i < len(firstPage); i++ {
		if firstPage[i-1].ID >= firstPage[i].ID {
			t.Fatalf("list is not ordered by id at index %d", i)
		}
	}

	after, err := s.List(ctx, created[0].ID, 2)
	if err != nil {
		t.Fatalf("List after cursor: %v", err)
	}
	if len(after) != 2 || after[0].ID != created[1].ID || after[1].ID != created[2].ID {
		t.Errorf("List after %s = %+v, want the two later projects", created[0].ID, after)
	}
}

func TestOpenRejectsInvalidURLWithoutLeakingIt(t *testing.T) {
	_, err := Open(context.Background(), "postgres://user:s3cret@host:notaport/db")
	if err == nil {
		t.Fatal("Open accepted an invalid URL")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("error leaks the connection string: %q", err)
	}
}
