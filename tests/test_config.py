import os

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


def test_plaintext_env_password_is_encrypted_in_place(monkeypatch, tmp_path):
    for key, value in BASE_ENV.items():
        monkeypatch.setenv(key, value)
    env = tmp_path / ".env"
    env.write_text("SCHWAB_USERNAME=alice\nSCHWAB_PASSWORD=hunter2\n", encoding="utf-8")

    cfg = load_settings(state_dir=tmp_path / "state", require_credentials=True)

    assert cfg.password == "hunter2"
    assert cfg.password_encrypted_now is True
    text = env.read_text(encoding="utf-8")
    assert "hunter2" not in text
    assert "SCHWAB_PASSWORD=$$dpapi:" in text or "SCHWAB_PASSWORD=$$aes:" in text

    again = load_settings(state_dir=tmp_path / "state", require_credentials=True)
    assert again.password == "hunter2"
    assert again.password_encrypted_now is False
    assert env.read_text(encoding="utf-8") == text


def test_shadowed_env_password_is_encrypted_but_process_env_wins(monkeypatch, tmp_path):
    for key, value in BASE_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SCHWAB_PASSWORD", "from-process-env")
    env = tmp_path / ".env"
    env.write_text("SCHWAB_PASSWORD=from-file\n", encoding="utf-8")

    cfg = load_settings(state_dir=tmp_path / "state")

    assert cfg.password == "from-process-env"
    assert cfg.secrets_encrypted_now == ("SCHWAB_PASSWORD",)
    text = env.read_text(encoding="utf-8")
    assert "from-file" not in text
    assert "SCHWAB_PASSWORD=$$" in text


def test_plaintext_env_key_and_secret_are_encrypted_in_place(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "SCHWAB_API_KEY=plain-client-id\n"
        "SCHWAB_APP_SECRET=plain-app-secret\n"
        "SCHWAB_CALLBACK_URL=https://127.0.0.1:8182/\n",
        encoding="utf-8",
    )

    cfg = load_settings(state_dir=tmp_path / "state")

    assert (cfg.client_id, cfg.client_secret) == ("plain-client-id", "plain-app-secret")
    assert cfg.secrets_encrypted_now == ("SCHWAB_API_KEY", "SCHWAB_APP_SECRET")
    text = env.read_text(encoding="utf-8")
    assert "plain-client-id" not in text
    assert "plain-app-secret" not in text
    assert "SCHWAB_API_KEY=$$dpapi:" in text or "SCHWAB_API_KEY=$$aes:" in text
    assert "SCHWAB_APP_SECRET=$$dpapi:" in text or "SCHWAB_APP_SECRET=$$aes:" in text

    again = load_settings(state_dir=tmp_path / "state")
    assert (again.client_id, again.client_secret) == ("plain-client-id", "plain-app-secret")
    assert again.secrets_encrypted_now == ()
    assert env.read_text(encoding="utf-8") == text


def test_env_file_aliases_are_encrypted_too(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "SCHWAB_APP_KEY=alias-key\n"
        "SCHWAB_CLIENT_SECRET=alias-secret\n"
        "SCHWAB_REDIRECT_URI=https://127.0.0.1:8182/\n",
        encoding="utf-8",
    )

    cfg = load_settings(state_dir=tmp_path / "state")

    assert (cfg.client_id, cfg.client_secret) == ("alias-key", "alias-secret")
    assert cfg.secrets_encrypted_now == ("SCHWAB_APP_KEY", "SCHWAB_CLIENT_SECRET")
    text = env.read_text(encoding="utf-8")
    assert "alias-key" not in text
    assert "alias-secret" not in text


def test_shadowed_env_secrets_are_encrypted_but_process_env_wins(monkeypatch, tmp_path):
    for key, value in BASE_ENV.items():
        monkeypatch.setenv(key, value)
    env = tmp_path / ".env"
    env.write_text("SCHWAB_API_KEY=from-file\nSCHWAB_APP_SECRET=file-secret\n", encoding="utf-8")

    cfg = load_settings(state_dir=tmp_path / "state")

    assert (cfg.client_id, cfg.client_secret) == ("my-client-id", "my-secret")
    assert cfg.secrets_encrypted_now == ("SCHWAB_API_KEY", "SCHWAB_APP_SECRET")
    text = env.read_text(encoding="utf-8")
    assert "from-file" not in text and "file-secret" not in text
    # The environment still holds the values the process supplied.
    assert os.environ["SCHWAB_API_KEY"] == "my-client-id"

    again = load_settings(state_dir=tmp_path / "state")
    assert again.secrets_encrypted_now == ()
    assert env.read_text(encoding="utf-8") == text


def test_undecryptable_client_id_is_a_config_error(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "SCHWAB_API_KEY=$$aes:AAAAAAAAAAAAAAAAAAAAAAAAAAAA$$\n"
        "SCHWAB_CALLBACK_URL=https://127.0.0.1:8182/\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as exc:
        load_settings(state_dir=tmp_path / "state")
    assert "SCHWAB_API_KEY is encrypted" in str(exc.value)


def test_undecryptable_envelope_is_a_config_error(monkeypatch, tmp_path):
    for key, value in BASE_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SCHWAB_PASSWORD", "$$aes:AAAAAAAAAAAAAAAAAAAAAAAAAAAA$$")
    with pytest.raises(ConfigError) as exc:
        load_settings(state_dir=tmp_path / "state")
    assert "cannot be opened here" in str(exc.value)


def test_mask_never_leaks_short_secrets():
    assert mask("abcd") == "****"
    assert mask("abcdefghij") == "abcd...ghij"


def test_default_state_dir_exists_shape():
    assert default_state_dir().name == "schwab-refresh"
