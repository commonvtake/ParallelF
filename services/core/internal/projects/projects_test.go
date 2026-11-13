package projects

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type stubEncoder struct{ fail bool }

func (s stubEncoder) ProjectCreated(p Project) (OutboxEvent, error) {
	if s.fail {
		return OutboxEvent{}, errors.New("encode failed")
	}
	return OutboxEvent{ID: "evt-" + p.ID, Type: "created", Subject: "project/" + p.ID}, nil
}

func (s stubEncoder) ProjectDeleted(p Project, deletedBy string, _ time.Time) (OutboxEvent, error) {
	return OutboxEvent{ID: "evt-del-" + p.ID, Type: "deleted", Subject: deletedBy}, nil
}

func newTestService(store Store, enc EventEncoder) *Service {
	n := 0
	newID := func() string {
		n++
		return fmt.Sprintf("00000000-0000-7000-8000-%012d", n)
	}
	now := func() time.Time { return time.Date(2026, 11, 13, 18, 0, 0, 123456789, time.UTC) }
	return NewService(store, enc, newID, now)
}

func TestValidate(t *testing.T) {
	valid := []string{"lab", "demo-lab", "a1b", "team-42-prod", "a" + strings.Repeat("b", 39)}
	for _, slug := range valid {
		in := CreateInput{Slug: slug, Name: "Demo"}
		if errs := in.Validate(); len(errs) != 0 {
			t.Errorf("slug %q rejected: %+v", slug, errs)
		}
	}
	invalid := []string{"", "ab", "Demo", "1lab", "lab-", "-lab", "my_lab", "my lab", "a" + strings.Repeat("b", 40), "läb"}
	for _, slug := range invalid {
		in := CreateInput{Slug: slug, Name: "Demo"}
		errs := in.Validate()
		if len(errs) != 1 || errs[0].Field != "slug" {
			t.Errorf("slug %q: errors = %+v, want one slug error", slug, errs)
		}
	}

	in := CreateInput{Slug: "  demo-lab ", Name: "  ", Description: strings.Repeat("d", MaxDescriptionLength+1)}
	errs := in.Validate()
	if len(errs) != 2 || errs[0].Field != "name" || errs[1].Field != "description" {
		t.Errorf("errors = %+v, want name and description", errs)
	}
	if in.Slug != "demo-lab" {
		t.Errorf("slug not trimmed: %q", in.Slug)
	}

	long := CreateInput{Slug: "demo", Name: strings.Repeat("é", MaxNameLength)}
	if errs := long.Validate(); len(errs) != 0 {
		t.Errorf("name of exactly %d runes rejected: %+v", MaxNameLength, errs)
	}
	long.Name += "é"
	if errs := long.Validate(); len(errs) != 1 {
		t.Errorf("name of %d runes accepted", MaxNameLength+1)
	}
}

func TestCreateStoresProjectAndEvent(t *testing.T) {
	store := NewMemoryStore()
	svc := newTestService(store, stubEncoder{})

	p, err := svc.Create(context.Background(), "user-1", CreateInput{Slug: "demo-lab", Name: "Demo lab", Description: "d"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if p.ID == "" || p.CreatedBy != "user-1" || !p.CreatedAt.Equal(p.UpdatedAt) {
		t.Errorf("unexpected project: %+v", p)
	}
	if p.CreatedAt.Nanosecond()%1000 != 0 {
		t.Errorf("created_at %v keeps sub-microsecond precision the database would drop", p.CreatedAt)
	}
	if len(store.Outbox) != 1 || store.Outbox[0].ID != "evt-"+p.ID {
		t.Errorf("outbox = %+v, want one event for the project", store.Outbox)
	}

	got, err := svc.Get(context.Background(), p.ID)
	if err != nil || got != p {
		t.Errorf("Get = %+v, %v", got, err)
	}
}

func TestCreateRejectsDuplicateSlugWithoutEvent(t *testing.T) {
	store := NewMemoryStore()
	svc := newTestService(store, stubEncoder{})
	if _, err := svc.Create(context.Background(), "u", CreateInput{Slug: "demo", Name: "A"}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.Create(context.Background(), "u", CreateInput{Slug: "demo", Name: "B"})
	if !errors.Is(err, ErrSlugTaken) {
		t.Fatalf("error = %v, want ErrSlugTaken", err)
	}
	if len(store.Outbox) != 1 {
		t.Errorf("outbox has %d events, want 1", len(store.Outbox))
	}
}

func TestCreateFailsWhenEventCannotBeEncoded(t *testing.T) {
	store := NewMemoryStore()
	svc := newTestService(store, stubEncoder{fail: true})
	if _, err := svc.Create(context.Background(), "u", CreateInput{Slug: "demo", Name: "A"}); err == nil {
		t.Fatal("Create succeeded although the event could not be encoded")
	}
	if page, _ := svc.List(context.Background(), "", 10); len(page.Items) != 0 {
		t.Error("project stored without its event")
	}
}

func TestListPaginates(t *testing.T) {
	svc := newTestService(NewMemoryStore(), stubEncoder{})
	for i := range 5 {
		if _, err := svc.Create(context.Background(), "u", CreateInput{Slug: fmt.Sprintf("proj-%d", i), Name: "P"}); err != nil {
			t.Fatal(err)
		}
	}

	var slugs []string
	cursor := ""
	for pageNo := 0; ; pageNo++ {
		if pageNo > 5 {
			t.Fatal("pagination does not terminate")
		}
		page, err := svc.List(context.Background(), cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) > 2 {
			t.Fatalf("page has %d items, limit is 2", len(page.Items))
		}
		for _, p := range page.Items {
			slugs = append(slugs, p.Slug)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if got := strings.Join(slugs, ","); got != "proj-0,proj-1,proj-2,proj-3,proj-4" {
		t.Errorf("listed %q, want creation order without gaps or repeats", got)
	}

	empty, err := newTestService(NewMemoryStore(), stubEncoder{}).List(context.Background(), "", 0)
	if err != nil || empty.Items == nil || len(empty.Items) != 0 || empty.NextCursor != "" {
		t.Errorf("empty list = %+v, %v; want non-nil empty items", empty, err)
	}
}

func TestDelete(t *testing.T) {
	store := NewMemoryStore()
	svc := newTestService(store, stubEncoder{})
	p, err := svc.Create(context.Background(), "u", CreateInput{Slug: "demo", Name: "A"})
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.Delete(context.Background(), p.ID, "admin-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := svc.Get(context.Background(), p.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after delete = %v, want ErrNotFound", err)
	}
	if len(store.Outbox) != 2 || store.Outbox[1].Type != "deleted" || store.Outbox[1].Subject != "admin-1" {
		t.Errorf("outbox = %+v, want a deleted event recording the actor", store.Outbox)
	}
	if err := svc.Delete(context.Background(), p.ID, "admin-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete = %v, want ErrNotFound", err)
	}
}
