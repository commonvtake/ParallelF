"""Projects: gateway -> pf-core -> PostgreSQL, including the event outbox."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any

import httpx
import psycopg

ContractCheck = Callable[[str, object], None]
ProjectFactory = Callable[..., dict[str, Any]]

PROJECTS = "/api/v1/core/projects"


def _outbox_events(
    database: psycopg.Connection[tuple[Any, ...]], project_id: str
) -> list[tuple[str, str, dict[str, Any], dict[str, Any]]]:
    rows = database.execute(
        """
        SELECT event_type, subject, convert_from(payload, 'UTF8'), headers
        FROM core.outbox
        WHERE headers->>'ce-subject' = %s
        ORDER BY created_at, id
        """,
        (f"project/{project_id}",),
    ).fetchall()
    return [
        (event_type, subject, json.loads(payload), headers)
        for event_type, subject, payload, headers in rows
    ]


def test_project_lifecycle_and_events(
    gateway: httpx.Client,
    owner_headers: dict[str, str],
    contract: ContractCheck,
    database: psycopg.Connection[tuple[Any, ...]],
) -> None:
    me = gateway.get("/api/v1/core/me", headers=owner_headers).json()

    slug = f"it-lifecycle-{os.urandom(4).hex()}"

    created = gateway.post(
        PROJECTS,
        json={"slug": slug, "name": "Lifecycle", "description": "Created by a test"},
        headers=owner_headers,
    )
    try:
        assert created.status_code == 201, created.text
        project = created.json()
        contract("Project", project)
        assert created.headers["location"] == f"{PROJECTS}/{project['id']}"
        assert project["slug"] == slug
        assert project["description"] == "Created by a test"
        assert project["created_by"] == me["subject"]

        fetched = gateway.get(f"{PROJECTS}/{project['id']}", headers=owner_headers)
        assert fetched.status_code == 200
        assert fetched.json() == project

        # The event was stored in the same transaction as the project.
        events = _outbox_events(database, project["id"])
        assert [event[0] for event in events] == ["parallelf.core.v1.ProjectCreated"]
        event_type, subject, payload, headers = events[0]
        assert subject == "pf.core.evt.project.created"
        assert payload["projectId"] == project["id"]
        assert payload["slug"] == slug
        assert payload["createdBy"] == me["subject"]
        assert headers["ce-specversion"] == "1.0"
        assert headers["ce-type"] == event_type
        assert headers["ce-source"] == "/parallelf/core/pf-core"
    finally:
        if created.status_code == 201:
            deleted = gateway.delete(f"{PROJECTS}/{created.json()['id']}", headers=owner_headers)
            assert deleted.status_code == 204

    assert gateway.get(f"{PROJECTS}/{project['id']}", headers=owner_headers).status_code == 404
    events = _outbox_events(database, project["id"])
    assert [event[0] for event in events] == [
        "parallelf.core.v1.ProjectCreated",
        "parallelf.core.v1.ProjectDeleted",
    ]
    assert events[1][2]["deletedBy"] == me["subject"]


def test_duplicate_slug_is_a_conflict(
    gateway: httpx.Client,
    owner_headers: dict[str, str],
    contract: ContractCheck,
    make_project: ProjectFactory,
) -> None:
    existing = make_project()

    response = gateway.post(
        PROJECTS, json={"slug": existing["slug"], "name": "Again"}, headers=owner_headers
    )

    assert response.status_code == 409
    contract("Problem", response.json())
    assert response.json()["type"] == "https://parallelf.dev/problems/conflict"


def test_invalid_project_lists_every_field_error(
    gateway: httpx.Client, owner_headers: dict[str, str], contract: ContractCheck
) -> None:
    response = gateway.post(
        PROJECTS, json={"slug": "Not A Slug", "name": ""}, headers=owner_headers
    )

    assert response.status_code == 422
    body = response.json()
    contract("Problem", body)
    assert {error["field"] for error in body["errors"]} == {"slug", "name"}


def test_malformed_json_is_a_bad_request(
    gateway: httpx.Client, owner_headers: dict[str, str]
) -> None:
    response = gateway.post(
        PROJECTS,
        content=b'{"slug": ',
        headers={**owner_headers, "Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert response.headers["content-type"] == "application/problem+json"


def test_viewer_can_read_but_not_write(
    gateway: httpx.Client,
    viewer_headers: dict[str, str],
    contract: ContractCheck,
    make_project: ProjectFactory,
) -> None:
    project = make_project()

    assert gateway.get(PROJECTS, headers=viewer_headers).status_code == 200
    assert gateway.get(f"{PROJECTS}/{project['id']}", headers=viewer_headers).status_code == 200

    create = gateway.post(
        PROJECTS, json={"slug": "it-viewer", "name": "Viewer"}, headers=viewer_headers
    )
    assert create.status_code == 403
    contract("Problem", create.json())
    assert create.json()["type"] == "https://parallelf.dev/problems/forbidden"

    delete = gateway.delete(f"{PROJECTS}/{project['id']}", headers=viewer_headers)
    assert delete.status_code == 403


def test_unknown_and_malformed_ids_are_not_found(
    gateway: httpx.Client, owner_headers: dict[str, str]
) -> None:
    unknown = gateway.get(f"{PROJECTS}/01900000-0000-7000-8000-000000000000", headers=owner_headers)
    assert unknown.status_code == 404

    malformed = gateway.get(f"{PROJECTS}/not-a-uuid", headers=owner_headers)
    assert malformed.status_code == 404


def test_listing_pages_through_projects_in_creation_order(
    gateway: httpx.Client,
    owner_headers: dict[str, str],
    contract: ContractCheck,
    make_project: ProjectFactory,
) -> None:
    expected = [make_project()["id"] for _ in range(3)]

    seen: list[str] = []
    cursor: str | None = None
    for _ in range(500):
        params: dict[str, str | int] = {"limit": 2}
        if cursor:
            params["cursor"] = cursor
        response = gateway.get(PROJECTS, params=params, headers=owner_headers)
        assert response.status_code == 200
        page = response.json()
        contract("ProjectPage", page)
        assert len(page["items"]) <= 2
        seen.extend(item["id"] for item in page["items"])
        cursor = page.get("next_cursor")
        if not cursor:
            break

    assert len(seen) == len(set(seen)), "a project appeared on two pages"
    assert [project_id for project_id in seen if project_id in expected] == expected


def test_invalid_page_size_is_rejected(
    gateway: httpx.Client, owner_headers: dict[str, str]
) -> None:
    response = gateway.get(PROJECTS, params={"limit": 0}, headers=owner_headers)

    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "limit"
