import pytest

from schwab_refresh.config import ConfigError, default_state_dir, load_settings, mask

BASE_ENV = {
    "SCHWAB_API_KEY": "my-client-id",
    "SCHWAB_APP_SECRET": "my-secret",
    "SCHWAB_CALLBACK_URL": "https://127.0.0.1:8182/",
}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for key in (
        "SCHWAB_API_KEY",
        "SCHWAB_APP_SECRET",
        "SCHWAB_CALLBACK_URL",
        "SCHWAB_APP_KEY",
        "SCHWAB_CLIENT_ID",
        "SCHWAB_REDIRECT_URI",
        "SCHWAB_USERNAME",
        "SCHWAB_PASSWORD",
        "SCHWAB_LOGIN_ID",
        "SCHWAB_LOGIN_PASSWORD",
        "SCHWAB_TOKEN_PATH",
        "SCHWAB_REFRESH_STATE_DIR",
        "SCHWAB_REFRESH_HEADLESS",
        "SCHWAB_REFRESH_MFA_TIMEOUT",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)


def test_missing_required_settings():
    with pytest.raises(ConfigError) as exc:
        load_settings()
    assert "SCHWAB_API_KEY" in str(exc.value)


def test_aliases_and_derived_values(monkeypatch):
    monkeypatch.setenv("SCHWAB_APP_KEY", "k")
    monkeypatch.setenv("SCHWAB_APP_SECRET", "s")
    monkeypatch.setenv("SCHWAB_REDIRECT_URI", "http://localhost:9000/cb")
    monkeypatch.setenv("SCHWAB_LOGIN_ID", "user")
    monkeypatch.setenv("SCHWAB_LOGIN_PASSWORD", "pass")

    cfg = load_settings()
    assert cfg.client_id == "k"
    assert cfg.callback_port == 9000
    assert cfg.is_loopback
    assert cfg.require_credentials() == ("user", "pass")
    assert cfg.headless is True


def test_rejects_non_loopback_callback(monkeypatch):
    monkeypatch.setenv("SCHWAB_API_KEY", "k")
    monkeypatch.setenv("SCHWAB_APP_SECRET", "s")
    monkeypatch.setenv("SCHWAB_CALLBACK_URL", "https://example.com/cb")
    with pytest.raises(ConfigError):
        load_settings()


def test_credentials_required_when_asked(monkeypatch):
    for key, value in BASE_ENV.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ConfigError):
        load_settings(require_credentials=True)


def test_env_overrides(monkeypatch, tmp_path):
    for key, value in BASE_ENV.items():
        monkeypatch.setenv(key, value)
    cfg = load_settings(
        headless=False,
        token_path=tmp_path / "t.json",
        state_dir=tmp_path / "state",
        mfa_timeout_s=42,
    )
    assert cfg.headless is False
    assert cfg.token_path == tmp_path / "t.json"
    assert cfg.profile_dir == tmp_path / "state" / "chrome-profile"
    assert cfg.mfa_timeout_s == 42


def test_mask_never_leaks_short_secrets():
    assert mask("abcd") == "****"
    assert mask("abcdefghij") == "abcd...ghij"


def test_default_state_dir_exists_shape():
    assert default_state_dir().name == "schwab-refresh"
