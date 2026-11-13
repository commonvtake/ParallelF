package projects

import (
	"context"
	"sort"
	"sync"
)

// MemoryStore is an in-memory Store for unit tests. It mirrors the
// behaviour the PostgreSQL store guarantees: unique slugs, id ordering and
// an outbox entry per successful change.
type MemoryStore struct {
	mu       sync.Mutex
	projects map[string]Project
	Outbox   []OutboxEvent
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{projects: make(map[string]Project)}
}

// Create implements Store.
func (m *MemoryStore) Create(_ context.Context, p Project, evt OutboxEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.projects {
		if existing.Slug == p.Slug {
			return ErrSlugTaken
		}
	}
	m.projects[p.ID] = p
	m.Outbox = append(m.Outbox, evt)
	return nil
}

// Get implements Store.
func (m *MemoryStore) Get(_ context.Context, id string) (Project, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.projects[id]
	if !ok {
		return Project{}, ErrNotFound
	}
	return p, nil
}

// List implements Store.
func (m *MemoryStore) List(_ context.Context, after string, limit int) ([]Project, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Project
	for _, p := range m.projects {
		if p.ID > after {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Delete implements Store.
func (m *MemoryStore) Delete(_ context.Context, id string, evt OutboxEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.projects[id]; !ok {
		return ErrNotFound
	}
	delete(m.projects, id)
	m.Outbox = append(m.Outbox, evt)
	return nil
}
