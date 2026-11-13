// Package projects implements the project domain: validation, lifecycle
// and the events each change produces. A project is the tenancy unit that
// later subsystems (Cloud, VPN, NetGuard, ...) attach their resources to.
package projects

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/commonvtake/parallelf/pkg/httpx"
)

// Domain errors returned by Service and Store.
var (
	ErrNotFound  = errors.New("project not found")
	ErrSlugTaken = errors.New("project slug already in use")
)

// Limits shared with the database CHECK constraints and the OpenAPI schema.
const (
	MaxNameLength        = 100
	MaxDescriptionLength = 500
	DefaultPageSize      = 50
	MaxPageSize          = 200
)

var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)

// Project is a tenancy unit.
type Project struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateInput is the client-supplied part of a new project.
type CreateInput struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Validate normalises the input and returns one FieldError per problem.
func (in *CreateInput) Validate() []httpx.FieldError {
	in.Slug = strings.TrimSpace(in.Slug)
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)

	var errs []httpx.FieldError
	if !slugPattern.MatchString(in.Slug) {
		errs = append(errs, httpx.FieldError{
			Field: "slug", Code: "format",
			Message: "3-40 characters: lower-case letters, digits and hyphens; starts with a letter and ends with a letter or digit.",
		})
	}
	switch n := utf8.RuneCountInString(in.Name); {
	case n == 0:
		errs = append(errs, httpx.FieldError{Field: "name", Code: "required", Message: "Name is required."})
	case n > MaxNameLength:
		errs = append(errs, httpx.FieldError{Field: "name", Code: "too_long", Message: "Name is limited to 100 characters."})
	}
	if utf8.RuneCountInString(in.Description) > MaxDescriptionLength {
		errs = append(errs, httpx.FieldError{Field: "description", Code: "too_long", Message: "Description is limited to 500 characters."})
	}
	return errs
}

// OutboxEvent is a domain event ready to be stored in the outbox table.
type OutboxEvent struct {
	ID      string
	Subject string
	Type    string
	Payload []byte
	Headers map[string]string
}

// EventEncoder turns domain changes into versioned event payloads.
type EventEncoder interface {
	ProjectCreated(p Project) (OutboxEvent, error)
	ProjectDeleted(p Project, deletedBy string, deletedAt time.Time) (OutboxEvent, error)
}

// Store persists projects. Create and Delete must write the event in the
// same transaction as the change.
type Store interface {
	Create(ctx context.Context, p Project, evt OutboxEvent) error
	Get(ctx context.Context, id string) (Project, error)
	// List returns up to limit projects with id greater than after, ordered
	// by id (creation order for UUIDv7).
	List(ctx context.Context, after string, limit int) ([]Project, error)
	Delete(ctx context.Context, id string, evt OutboxEvent) error
}

// Service implements project use cases.
type Service struct {
	store   Store
	encoder EventEncoder
	newID   func() string
	now     func() time.Time
}

// NewService wires a Service.
func NewService(store Store, encoder EventEncoder, newID func() string, now func() time.Time) *Service {
	return &Service{store: store, encoder: encoder, newID: newID, now: now}
}

// Create stores a new project owned by the subject createdBy. The input
// must already be validated.
func (s *Service) Create(ctx context.Context, createdBy string, in CreateInput) (Project, error) {
	now := s.now().UTC().Truncate(time.Microsecond) // Postgres timestamptz precision
	p := Project{
		ID:          s.newID(),
		Slug:        in.Slug,
		Name:        in.Name,
		Description: in.Description,
		CreatedBy:   createdBy,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	evt, err := s.encoder.ProjectCreated(p)
	if err != nil {
		return Project{}, err
	}
	if err := s.store.Create(ctx, p, evt); err != nil {
		return Project{}, err
	}
	return p, nil
}

// Get returns one project.
func (s *Service) Get(ctx context.Context, id string) (Project, error) {
	return s.store.Get(ctx, id)
}

// Page is one page of a project listing.
type Page struct {
	Items      []Project `json:"items"`
	NextCursor string    `json:"next_cursor,omitempty"`
}

// List returns a page of projects. NextCursor is set when more exist.
func (s *Service) List(ctx context.Context, cursor string, limit int) (Page, error) {
	if limit <= 0 {
		limit = DefaultPageSize
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}
	items, err := s.store.List(ctx, cursor, limit+1)
	if err != nil {
		return Page{}, err
	}
	page := Page{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = page.Items[limit-1].ID
	}
	if page.Items == nil {
		page.Items = []Project{}
	}
	return page, nil
}

// Delete removes a project and records who removed it.
func (s *Service) Delete(ctx context.Context, id, deletedBy string) error {
	p, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	evt, err := s.encoder.ProjectDeleted(p, deletedBy, s.now().UTC())
	if err != nil {
		return err
	}
	return s.store.Delete(ctx, id, evt)
}
