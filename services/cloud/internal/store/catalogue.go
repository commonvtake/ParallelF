package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
)

const flavorColumns = `f.id::text, f.name, f.vcpus, f.memory_mib, f.disk_gib`

func scanFlavor(row pgx.Row) (domain.Flavor, error) {
	var f domain.Flavor
	if err := row.Scan(&f.ID, &f.Name, &f.VCPUs, &f.MemoryMiB, &f.DiskGiB); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Flavor{}, domain.ErrNotFound
		}
		return domain.Flavor{}, fmt.Errorf("scan flavor: %w", err)
	}
	return f, nil
}

// ListFlavors returns every flavor, smallest first.
func (s *Postgres) ListFlavors(ctx context.Context) ([]domain.Flavor, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+flavorColumns+` FROM cloud.flavors f ORDER BY f.memory_mib, f.vcpus, f.name`)
	if err != nil {
		return nil, fmt.Errorf("list flavors: %w", err)
	}
	defer rows.Close()
	out := []domain.Flavor{}
	for rows.Next() {
		f, err := scanFlavor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Postgres) flavorByName(ctx context.Context, tx pgx.Tx, name string) (domain.Flavor, error) {
	f, err := scanFlavor(tx.QueryRow(ctx, `SELECT `+flavorColumns+` FROM cloud.flavors f WHERE f.name = $1`, name))
	if errors.Is(err, domain.ErrNotFound) {
		return domain.Flavor{}, &domain.ValidationError{Field: "flavor", Code: "not_found", Message: "No flavor has this name."}
	}
	return f, err
}

const templateSelect = `
	SELECT t.id::text, t.name, t.version, t.kind, t.description,
	       i.id::text, i.name, i.kind, i.source, COALESCE(i.sha256, ''), i.os,
	       ` + flavorColumns + `,
	       t.cloud_config, t.static_network, t.command, t.cap_add, t.deprecated
	FROM cloud.templates t
	JOIN cloud.images i ON i.id = t.image_id
	JOIN cloud.flavors f ON f.id = t.default_flavor_id`

func scanTemplate(row pgx.Row) (domain.Template, error) {
	var (
		t                       domain.Template
		config, command, capAdd []byte
	)
	err := row.Scan(&t.ID, &t.Name, &t.Version, &t.Kind, &t.Description,
		&t.Image.ID, &t.Image.Name, &t.Image.Kind, &t.Image.Source, &t.Image.SHA256, &t.Image.OS,
		&t.DefaultFlavor.ID, &t.DefaultFlavor.Name, &t.DefaultFlavor.VCPUs, &t.DefaultFlavor.MemoryMiB, &t.DefaultFlavor.DiskGiB,
		&config, &t.StaticNetwork, &command, &capAdd, &t.Deprecated)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Template{}, domain.ErrNotFound
		}
		return domain.Template{}, fmt.Errorf("scan template: %w", err)
	}
	for _, f := range []struct {
		raw []byte
		dst any
	}{{config, &t.CloudConfig}, {command, &t.Command}, {capAdd, &t.CapAdd}} {
		if err := json.Unmarshal(f.raw, f.dst); err != nil {
			return domain.Template{}, fmt.Errorf("decode template %s: %w", t.Name, err)
		}
	}
	return t, nil
}

// ListTemplates returns every template version, newest version first.
func (s *Postgres) ListTemplates(ctx context.Context) ([]domain.Template, error) {
	rows, err := s.pool.Query(ctx, templateSelect+` ORDER BY t.kind DESC, t.name, t.version DESC`)
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}
	defer rows.Close()
	out := []domain.Template{}
	for rows.Next() {
		t, err := scanTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// resolveTemplate finds a template by name: a given version, or else the
// newest version that is not deprecated.
func (s *Postgres) resolveTemplate(ctx context.Context, q querier, name string, version int) (domain.Template, error) {
	t, err := scanTemplate(q.QueryRow(ctx, templateSelect+`
		WHERE t.name = $1 AND (($2 = 0 AND NOT t.deprecated) OR t.version = $2)
		ORDER BY t.version DESC LIMIT 1`, name, version))
	if errors.Is(err, domain.ErrNotFound) {
		return domain.Template{}, &domain.ValidationError{Field: "template", Code: "not_found", Message: "No such template or version."}
	}
	return t, err
}

// templatesByID loads the given templates.
func (s *Postgres) templatesByID(ctx context.Context, tx pgx.Tx, ids []string) (map[string]domain.Template, error) {
	out := map[string]domain.Template{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, templateSelect+` WHERE t.id::text = ANY($1)`, ids)
	if err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		t, err := scanTemplate(rows)
		if err != nil {
			return nil, err
		}
		out[t.ID] = t
	}
	return out, rows.Err()
}
