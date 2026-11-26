"""Read/write the schwab-py token file format, atomically.

On-disk shape (what ``schwab-py`` and the existing scripts around here use):

    {
      "creation_timestamp": 1764123456,
      "token": {
        "expires_in": 1800,
        "token_type": "Bearer",
        "scope": "api",
        "refresh_token": "...",
        "access_token": "...",
        "id_token": "...",
        "expires_at": 1764125256
      }
    }

``creation_timestamp`` is when the refresh token was minted; schwab-py uses it
to age the refresh token, so a full login resets it to now.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from schwab_refresh.oauth import REFRESH_TOKEN_LIFETIME_S, TokenGrant


class TokenFileError(Exception):
    pass


@dataclass(frozen=True)
class TokenStatus:
    created_at: int | None
    access_expires_at: int | None
    refresh_age_days: float | None
    refresh_days_left: float | None
    scope: str | None

    @property
    def access_valid_for_s(self) -> int | None:
        if self.access_expires_at is None:
            return None
        return int(self.access_expires_at - time.time())


def load_payload(path: str | Path) -> dict:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TokenFileError(f"token file not found: {p}") from exc
    except (OSError, ValueError) as exc:
        raise TokenFileError(f"cannot read token file {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise TokenFileError(f"token file {p} is not a JSON object")
    return data


def token_section(payload: dict) -> dict:
    """Return the ``token`` object (or the flat payload for legacy files)."""
    tok = payload.get("token")
    if isinstance(tok, dict):
        return tok
    if payload.get("access_token"):
        return payload
    raise TokenFileError("token file has neither a 'token' object nor flat token fields")


def get_refresh_token(payload: dict) -> str | None:
    return token_section(payload).get("refresh_token")


def get_access_token(payload: dict) -> str | None:
    return token_section(payload).get("access_token")


def summarize(payload: dict, *, now: float | None = None) -> TokenStatus:
    now = time.time() if now is None else now
    tok = token_section(payload)
    created = payload.get("creation_timestamp")
    try:
        created_i = int(created) if created is not None else None
    except (TypeError, ValueError):
        created_i = None

    try:
        access_exp = int(tok["expires_at"]) if "expires_at" in tok else None
    except (TypeError, ValueError):
        access_exp = None

    if created_i is None:
        refresh_age = None
        refresh_left = None
    else:
        refresh_age = (now - created_i) / 86400.0
        refresh_left = (created_i + REFRESH_TOKEN_LIFETIME_S - now) / 86400.0

    return TokenStatus(
        created_at=created_i,
        access_expires_at=access_exp,
        refresh_age_days=refresh_age,
        refresh_days_left=refresh_left,
        scope=tok.get("scope"),
    )


def write_token_file(
    path: str | Path,
    grant: TokenGrant,
    *,
    now: int | None = None,
    keep_backup: bool = True,
    reset_creation: bool = True,
) -> dict:
    """Atomically replace the token file's token section.

    ``reset_creation=True`` is for a full authorization-code grant: the refresh
    token is brand new, so its 7-day clock restarts. ``reset_creation=False``
    is for a refresh grant, which does NOT extend the refresh token's life and
    must keep the original ``creation_timestamp``.

    A ``.bak`` copy of the previous file is kept. Unknown keys in the existing
    file are preserved.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    now = int(time.time()) if now is None else now

    existing: dict = {}
    if p.exists():
        try:
            existing = load_payload(p)
        except TokenFileError:
            existing = {}

    payload = dict(existing)
    if reset_creation or "creation_timestamp" not in payload:
        payload["creation_timestamp"] = now
    payload["token"] = grant.as_token_dict(now=now)

    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass

    if keep_backup and p.exists():
        try:
            shutil.copy2(p, p.with_name(p.name + ".bak"))
        except OSError:
            pass

    os.replace(tmp, p)
    return payload
