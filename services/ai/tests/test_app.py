from fastapi.testclient import TestClient

from pf_aid.app import build_app
from pf_aid.config import Settings
from pf_common.auth import InvalidTokenError, Principal
from pf_common.settings import load_settings

ENV = {
    "PF_OIDC_ISSUER": "http://localhost:8080/realms/parallelf",
    "PF_OIDC_JWKS_URL": "http://keycloak:8080/realms/parallelf/protocol/openid-connect/certs",
    "PF_VERSION": "1.2.3",
}


class FakeVerifier:
    def verify(self, token: str) -> Principal:
        if token != "good":
            raise InvalidTokenError("rejected")
        return Principal(subject="user-1", username="analyst", roles=("analyst",))


def client() -> TestClient:
    return TestClient(build_app(load_settings(Settings, ENV), FakeVerifier()))


def test_settings_defaults() -> None:
    settings = load_settings(Settings, ENV)

    assert settings.http_port == 9006
    assert settings.oidc_audience == "parallelf-api"


def test_health_endpoints_identify_the_service() -> None:
    for path in ("/healthz", "/readyz"):
        response = client().get(path)

        assert response.status_code == 200
        assert response.json() == {"status": "ok", "service": "pf-aid", "version": "1.2.3"}


def test_info_requires_a_valid_token() -> None:
    assert client().get("/api/v1/ai/info").status_code == 401
    assert (
        client().get("/api/v1/ai/info", headers={"Authorization": "Bearer bad"}).status_code == 401
    )


def test_info_reports_capabilities_as_not_implemented() -> None:
    response = client().get("/api/v1/ai/info", headers={"Authorization": "Bearer good"})

    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "pf-aid"
    assert body["version"] == "1.2.3"
    names = [capability["name"] for capability in body["capabilities"]]
    assert names == ["investigations", "evidence-tools", "citation-validation"]
    assert {capability["status"] for capability in body["capabilities"]} == {"not_implemented"}


def test_build_app_uses_oidc_verifier_by_default() -> None:
    # No network call happens here: signing keys are fetched on first use.
    app = build_app(load_settings(Settings, ENV))

    assert type(app.state.verifier).__name__ == "OIDCTokenVerifier"
