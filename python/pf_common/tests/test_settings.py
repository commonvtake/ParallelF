from pathlib import Path

import pytest

from pf_common.settings import ServiceSettings, SettingsError, load_settings

VALID = {
    "PF_OIDC_ISSUER": "http://localhost:8080/realms/parallelf/",
    "PF_OIDC_JWKS_URL": "http://keycloak:8080/realms/parallelf/protocol/openid-connect/certs",
}


def test_defaults_and_normalisation() -> None:
    settings = load_settings(ServiceSettings, VALID)

    assert settings.oidc_issuer == "http://localhost:8080/realms/parallelf"
    assert settings.oidc_audience == "parallelf-api"
    assert settings.http_port == 8000
    assert settings.log_level == "info"
    assert settings.version == "dev"


def test_values_are_read_from_prefixed_variables() -> None:
    env = {
        **VALID,
        "PF_HTTP_PORT": "9006",
        "PF_LOG_LEVEL": "debug",
        "PF_VERSION": "1.2.3",
        "HOME": "/x",
    }
    settings = load_settings(ServiceSettings, env)

    assert (settings.http_port, settings.log_level, settings.version) == (9006, "debug", "1.2.3")


def test_every_problem_is_reported_by_variable_name() -> None:
    env = {"PF_OIDC_ISSUER": "keycloak:8080", "PF_HTTP_PORT": "70000", "PF_LOG_LEVEL": "loud"}

    with pytest.raises(SettingsError) as excinfo:
        load_settings(ServiceSettings, env)

    message = str(excinfo.value)
    for name in ("PF_OIDC_ISSUER", "PF_OIDC_JWKS_URL: is required", "PF_HTTP_PORT", "PF_LOG_LEVEL"):
        assert name in message


def test_error_message_does_not_echo_values() -> None:
    env = {**VALID, "PF_OIDC_ISSUER": "ftp://user:hunter2@example.test"}

    with pytest.raises(SettingsError) as excinfo:
        load_settings(ServiceSettings, env)

    assert "hunter2" not in str(excinfo.value)


def test_secret_file_is_used_when_variable_is_unset(tmp_path: Path) -> None:
    secret = tmp_path / "audience"
    secret.write_text("from-file\n", encoding="utf-8")

    from_file = load_settings(ServiceSettings, {**VALID, "PF_OIDC_AUDIENCE_FILE": str(secret)})
    assert from_file.oidc_audience == "from-file"

    env_wins = load_settings(
        ServiceSettings,
        {**VALID, "PF_OIDC_AUDIENCE": "from-env", "PF_OIDC_AUDIENCE_FILE": str(secret)},
    )
    assert env_wins.oidc_audience == "from-env"


def test_unreadable_or_empty_secret_file_is_an_error(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.write_text("  \n", encoding="utf-8")

    for path in (str(tmp_path / "missing"), str(empty)):
        with pytest.raises(SettingsError, match="PF_OIDC_AUDIENCE_FILE"):
            load_settings(ServiceSettings, {**VALID, "PF_OIDC_AUDIENCE_FILE": path})


def test_settings_are_immutable() -> None:
    settings = load_settings(ServiceSettings, VALID)
    with pytest.raises(Exception, match="frozen"):
        settings.http_port = 1  # type: ignore[misc]
