## What changed and why

## How it was verified

- [ ] `make lint` and `make test`
- [ ] `make up && make verify` (when services, contracts or deployment changed)
- [ ] `make test-integration` / `make test-e2e` (when API or dashboard behaviour changed)

## Checklist

- [ ] API or event changes were made in `api/` first and generated code was refreshed (`make gen`)
- [ ] Database changes are a new migration; existing migrations are untouched
- [ ] Docs or an ADR were updated if behaviour or a decision changed
