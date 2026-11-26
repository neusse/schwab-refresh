"""Runtime settings, loaded from the environment (and an optional .env file).

Naming mirrors the schwab-py / schwab-pi contract already used across the
machine, with aliases so this tool drops into existing setups:

    client id      SCHWAB_API_KEY | SCHWAB_APP_KEY | SCHWAB_CLIENT_ID
    client secret  SCHWAB_APP_SECRET | SCHWAB_CLIENT_SECRET
    redirect uri   SCHWAB_CALLBACK_URL | SCHWAB_REDIRECT_URI
    login id       SCHWAB_USERNAME | SCHWAB_LOGIN_ID
    password       SCHWAB_PASSWORD | SCHWAB_LOGIN_PASSWORD
    token file     SCHWAB_TOKEN_PATH | SCHWAB_TOKEN_FILE | SCHWAB_TOKEN_JSON
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

_ALIASES = {
    "client_id": ("SCHWAB_API_KEY", "SCHWAB_APP_KEY", "SCHWAB_CLIENT_ID"),
    "client_secret": ("SCHWAB_APP_SECRET", "SCHWAB_CLIENT_SECRET"),
    "redirect_uri": ("SCHWAB_CALLBACK_URL", "SCHWAB_REDIRECT_URI", "SCHWAB_REDIRECT_URL"),
    "username": ("SCHWAB_USERNAME", "SCHWAB_LOGIN_ID", "SCHWAB_USER"),
    "password": ("SCHWAB_PASSWORD", "SCHWAB_LOGIN_PASSWORD"),
    "token_path": ("SCHWAB_TOKEN_PATH", "SCHWAB_TOKEN_FILE", "SCHWAB_TOKEN_JSON"),
}


class ConfigError(Exception):
    """Required settings are missing or malformed."""


def _env(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip():
            return value.strip()
    return None


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def default_state_dir() -> Path:
    """Per-user state directory (browser profile, logs, screenshots, TLS)."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "schwab-refresh"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "schwab-refresh"


@dataclass(frozen=True)
class Settings:
    client_id: str
    client_secret: str
    redirect_uri: str
    username: str | None
    password: str | None
    token_path: Path | None
    state_dir: Path
    profile_dir: Path
    headless: bool = True
    ignore_cert_errors: bool = True
    login_timeout_s: int = 600
    mfa_timeout_s: int = 180

    # -- derived ----------------------------------------------------------
    @property
    def redirect(self):
        return urlparse(self.redirect_uri)

    @property
    def is_loopback(self) -> bool:
        return self.redirect.hostname in {"127.0.0.1", "localhost", "::1"}

    @property
    def callback_port(self) -> int:
        port = self.redirect.port
        if port is None:
            port = 443 if self.redirect.scheme == "https" else 80
        return port

    def require_credentials(self) -> tuple[str, str]:
        if not self.username or not self.password:
            raise ConfigError(
                "Saved login credentials are required for unattended login. "
                "Set SCHWAB_USERNAME and SCHWAB_PASSWORD (env or .env)."
            )
        return self.username, self.password

    def require_token_path(self) -> Path:
        if self.token_path is None:
            raise ConfigError(
                "No token output file configured. Set SCHWAB_TOKEN_PATH (or pass --token-path)."
            )
        return self.token_path


def load_settings(
    *,
    env_file: str | Path | None = None,
    token_path: str | Path | None = None,
    state_dir: str | Path | None = None,
    headless: bool | None = None,
    login_timeout_s: int | None = None,
    mfa_timeout_s: int | None = None,
    require_credentials: bool = False,
) -> Settings:
    """Build settings from env (+ optional .env), then apply overrides."""
    if env_file is not None:
        load_dotenv(Path(env_file), override=False)
    else:
        # Explicit cwd lookup: the console-script entry point lives in
        # site-packages, so python-dotenv's caller-relative search would walk
        # the wrong tree. Scheduled tasks run with cwd = project root.
        candidate = Path.cwd() / ".env"
        if candidate.exists():
            load_dotenv(candidate, override=False)

    client_id = _env(*_ALIASES["client_id"])
    client_secret = _env(*_ALIASES["client_secret"])
    redirect_uri = _env(*_ALIASES["redirect_uri"])

    missing = [
        name
        for name, value in (
            ("client id (SCHWAB_API_KEY)", client_id),
            ("client secret (SCHWAB_APP_SECRET)", client_secret),
            ("redirect uri (SCHWAB_CALLBACK_URL)", redirect_uri),
        )
        if not value
    ]
    if missing:
        raise ConfigError("Missing " + ", ".join(missing) + ".")

    resolved_token = str(token_path) if token_path else _env(*_ALIASES["token_path"])
    resolved_state = Path(state_dir) if state_dir else default_state_dir()
    if state_dir is None:
        env_state = os.environ.get("SCHWAB_REFRESH_STATE_DIR")
        if env_state:
            resolved_state = Path(env_state)
    profile = Path(os.environ.get("SCHWAB_REFRESH_PROFILE_DIR") or resolved_state / "chrome-profile")

    cfg = Settings(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        username=_env(*_ALIASES["username"]),
        password=_env(*_ALIASES["password"]),
        token_path=Path(resolved_token) if resolved_token else None,
        state_dir=resolved_state,
        profile_dir=profile,
        headless=_env_bool("SCHWAB_REFRESH_HEADLESS", True) if headless is None else headless,
        ignore_cert_errors=_env_bool("SCHWAB_REFRESH_IGNORE_CERT_ERRORS", True),
        login_timeout_s=login_timeout_s or _env_int("SCHWAB_REFRESH_LOGIN_TIMEOUT", 600),
        mfa_timeout_s=mfa_timeout_s or _env_int("SCHWAB_REFRESH_MFA_TIMEOUT", 180),
    )

    if not cfg.is_loopback:
        raise ConfigError(
            f"redirect uri {redirect_uri!r} is not a loopback address; this tool "
            "can only capture callbacks on 127.0.0.1/localhost."
        )
    if cfg.redirect.scheme not in ("http", "https"):
        raise ConfigError(f"redirect uri must be http(s), got {cfg.redirect.scheme!r}")
    if require_credentials:
        cfg.require_credentials()
    return cfg


def mask(value: str) -> str:
    """Show first/last 4 chars so logs can identify a key without leaking it."""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"
