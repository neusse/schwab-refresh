import json
import time

import pytest

from schwab_refresh.oauth import (
    REFRESH_TOKEN_LIFETIME_S,
    OAuthError,
    TokenGrant,
    build_authorize_url,
)
from schwab_refresh.tokenstore import (
    TokenFileError,
    load_payload,
    summarize,
    token_section,
    write_token_file,
)


def _grant(**kw):
    data = {
        "access_token": "ACCESS",
        "refresh_token": "REFRESH",
        "expires_in": 1800,
        "token_type": "Bearer",
        "scope": "api",
        "id_token": "ID",
    }
    data.update(kw)
    return TokenGrant.from_response(data)


def test_authorize_url_encodes_state():
    url = build_authorize_url("abc", "https://127.0.0.1:8182/", "s t/1")
    assert url.startswith("https://api.schwabapi.com/v1/oauth/authorize?")
    assert "client_id=abc" in url
    assert "redirect_uri=https%3A%2F%2F127.0.0.1%3A8182%2F" in url
    assert "state=s+t%2F1" in url


def test_token_grant_dict_shape():
    now = 1_700_000_000
    token = _grant().as_token_dict(now=now)
    assert token["expires_at"] == now + 1800
    assert token["token_type"] == "Bearer"
    assert token["scope"] == "api"
    assert token["id_token"] == "ID"


def test_token_grant_rejects_incomplete_response():
    with pytest.raises(OAuthError):
        TokenGrant.from_response({"access_token": "a"})


def test_write_full_login_resets_creation_and_keeps_unknown_keys(tmp_path):
    path = tmp_path / "token.json"
    path.write_text(json.dumps({"creation_timestamp": 1, "note": "keep me", "token": {}}))

    payload = write_token_file(path, _grant(), now=2_000_000_000)

    on_disk = load_payload(path)
    assert on_disk == payload
    assert on_disk["creation_timestamp"] == 2_000_000_000
    assert on_disk["note"] == "keep me"
    assert on_disk["token"]["access_token"] == "ACCESS"
    assert on_disk["token"]["expires_at"] == 2_000_000_000 + 1800
    assert (tmp_path / "token.json.bak").exists()


def test_refresh_grant_keeps_creation_timestamp(tmp_path):
    path = tmp_path / "token.json"
    path.write_text(json.dumps({"creation_timestamp": 1_000, "token": {"refresh_token": "R"}}))

    write_token_file(path, _grant(access_token="NEW"), now=5_000, reset_creation=False)

    on_disk = load_payload(path)
    assert on_disk["creation_timestamp"] == 1_000
    assert on_disk["token"]["access_token"] == "NEW"


def test_summarize_reports_refresh_budget(tmp_path):
    path = tmp_path / "token.json"
    created = int(time.time()) - 6 * 86400
    write_token_file(path, _grant(), now=created)

    status = summarize(load_payload(path))
    assert status.refresh_age_days == pytest.approx(6.0, abs=0.01)
    assert status.refresh_days_left == pytest.approx(1.0, abs=0.01)
    assert status.created_at + REFRESH_TOKEN_LIFETIME_S > time.time()


def test_token_section_rejects_junk():
    with pytest.raises(TokenFileError):
        token_section({"hello": "world"})
