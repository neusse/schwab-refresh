"""Schwab OAuth endpoints: authorize URL, code exchange, refresh grant."""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

AUTHORIZE_URL = "https://api.schwabapi.com/v1/oauth/authorize"
TOKEN_URL = "https://api.schwabapi.com/v1/oauth/token"
QUOTE_URL = "https://api.schwabapi.com/marketdata/v1/quotes"
USER_PREFERENCE_URL = "https://api.schwabapi.com/trader/v1/userPreference"

ACCESS_TOKEN_LIFETIME_S = 1800
REFRESH_TOKEN_LIFETIME_S = 7 * 24 * 3600


class OAuthError(Exception):
    """Token endpoint returned something we cannot use."""

    def __init__(self, message: str, *, status: int | None = None, payload: dict | None = None):
        super().__init__(message)
        self.status = status
        self.payload = payload or {}

    @property
    def is_invalid_grant(self) -> bool:
        return self.payload.get("error") in {
            "invalid_grant",
            "invalid_request",
            "unsupported_grant_type",
        }


@dataclass(frozen=True)
class TokenGrant:
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str
    scope: str | None
    id_token: str | None
    raw: dict

    def as_token_dict(self, *, now: int | None = None) -> dict:
        """Schwab-py token payload shape (what downstream tools expect)."""
        now = int(time.time()) if now is None else now
        token = {
            "expires_in": int(self.expires_in),
            "token_type": self.token_type or "Bearer",
            "scope": self.scope or "api",
            "refresh_token": self.refresh_token,
            "access_token": self.access_token,
            "expires_at": now + int(self.expires_in),
        }
        if self.id_token:
            token["id_token"] = self.id_token
        return token

    @classmethod
    def from_response(cls, data: dict) -> TokenGrant:
        for key in ("access_token", "refresh_token", "expires_in"):
            if not data.get(key):
                raise OAuthError(f"token response missing {key!r}", payload=data)
        return cls(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_in=int(data["expires_in"]),
            token_type=data.get("token_type") or "Bearer",
            scope=data.get("scope"),
            id_token=data.get("id_token"),
            raw=data,
        )


def build_authorize_url(client_id: str, redirect_uri: str, state: str) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
    }
    return f"{AUTHORIZE_URL}?{urlencode(params)}"


def _post_token(client_id: str, client_secret: str, data: dict) -> TokenGrant:
    try:
        resp = httpx.post(
            TOKEN_URL,
            auth=(client_id, client_secret),
            data=data,
            headers={"Accept": "application/json"},
            timeout=45.0,
        )
    except httpx.HTTPError as exc:
        raise OAuthError(f"token endpoint unreachable: {exc}") from exc

    if resp.status_code != 200:
        payload: dict = {}
        try:
            payload = resp.json()
        except ValueError:
            payload = {"body": resp.text[:400]}
        detail = payload.get("error_description") or payload.get("error") or payload.get("body")
        raise OAuthError(
            f"token endpoint returned HTTP {resp.status_code}: {detail}",
            status=resp.status_code,
            payload=payload,
        )
    return TokenGrant.from_response(resp.json())


def exchange_code(
    client_id: str, client_secret: str, redirect_uri: str, code: str
) -> TokenGrant:
    """Authorization-code grant. Issues a BRAND NEW 7-day refresh token."""
    return _post_token(
        client_id,
        client_secret,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        },
    )


def refresh_access_token(client_id: str, client_secret: str, refresh_token: str) -> TokenGrant:
    """Refresh grant. Schwab returns the same refresh token with its ORIGINAL
    expiry — this does NOT extend the 7-day window."""
    return _post_token(
        client_id,
        client_secret,
        {"grant_type": "refresh_token", "refresh_token": refresh_token},
    )


def probe(access_token: str, path: str = QUOTE_URL, params: dict | None = None) -> tuple[bool, str]:
    """Cheap authenticated GET to prove the token works.

    Returns ``(ok, detail)``. Default probe is one quote (market-data scope);
    pass ``USER_PREFERENCE_URL`` to also prove trader scope (streamer).
    """
    try:
        resp = httpx.get(
            path,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            params=params,
            timeout=20.0,
        )
    except httpx.HTTPError as exc:
        return False, f"request failed: {exc}"
    if resp.status_code == 200:
        return True, "HTTP 200"
    return False, f"HTTP {resp.status_code}: {resp.text[:300]}"
