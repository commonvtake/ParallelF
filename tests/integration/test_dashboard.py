"""The dashboard server's HTTP behaviour without a browser.

Signing in through the identity provider's login page is covered by the
Playwright suite in web/dashboard/e2e.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx


def test_liveness(dashboard: httpx.Client) -> None:
    response = dashboard.get("/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "pf-dashboard"


def test_anonymous_visitor_is_redirected_to_login(dashboard: httpx.Client) -> None:
    for path in ("/", "/cloud", "/settings"):
        response = dashboard.get(path)

        assert response.status_code == 307, path
        assert urlsplit(response.headers["location"]).path == "/login"


def test_login_page_renders_with_security_headers(dashboard: httpx.Client) -> None:
    response = dashboard.get("/login")

    assert response.status_code == 200
    assert "Sign in" in response.text
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "x-powered-by" not in response.headers


def test_login_starts_authorization_code_flow_with_pkce(
    dashboard: httpx.Client, dashboard_url: str, keycloak_url: str
) -> None:
    response = dashboard.get("/auth/login")

    assert response.status_code == 303
    location = urlsplit(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}" == keycloak_url
    assert location.path == "/realms/parallelf/protocol/openid-connect/auth"
    query = parse_qs(location.query)
    assert query["response_type"] == ["code"]
    assert query["client_id"] == ["parallelf-dashboard"]
    assert query["redirect_uri"] == [f"{dashboard_url}/auth/callback"]
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["code_challenge"][0]) >= 43
    assert "openid" in query["scope"][0].split()
    assert query["state"][0] and query["nonce"][0]

    cookie = response.headers["set-cookie"]
    assert cookie.startswith("pf_login=")
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie or "SameSite=Lax" in cookie


def test_callback_rejects_a_state_the_browser_was_never_given(
    dashboard: httpx.Client, dashboard_url: str
) -> None:
    response = dashboard.get("/auth/callback", params={"state": "forged", "code": "abc"})

    assert response.status_code == 303
    assert response.headers["location"] == f"{dashboard_url}/login?error=invalid_state"
    assert "pf_sid" not in response.headers.get("set-cookie", "")


def test_api_proxy_requires_a_session(dashboard: httpx.Client) -> None:
    response = dashboard.get("/bff/api/core/me")

    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["type"] == "https://parallelf.dev/problems/unauthorized"


def test_state_changing_requests_from_other_origins_are_refused(dashboard: httpx.Client) -> None:
    for path in ("/bff/api/core/projects", "/auth/logout"):
        for headers in ({}, {"Origin": "http://evil.example"}):
            response = dashboard.post(path, json={}, headers=headers)

            assert response.status_code == 403, (path, headers)
