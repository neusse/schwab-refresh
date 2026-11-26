import sys

import pytest

from schwab_refresh import secretbox


@pytest.fixture
def state(tmp_path):
    return tmp_path / "state"


def test_is_wrapped():
    assert secretbox.is_wrapped("$$dpapi:AAAA$$")
    assert secretbox.is_wrapped("$$aes:AAAA$$")
    assert not secretbox.is_wrapped("plain-text")
    assert not secretbox.is_wrapped("$$notbase64$$")
    assert not secretbox.is_wrapped("")
    assert not secretbox.is_wrapped(None)


def test_roundtrip_native_backend(state):
    envelope = secretbox.encrypt("s3cret!", state_dir=state)
    assert secretbox.is_wrapped(envelope)
    assert "s3cret!" not in envelope
    assert secretbox.decrypt(envelope, state_dir=state) == "s3cret!"


def test_roundtrip_aes_fallback(state, monkeypatch):
    monkeypatch.setattr(secretbox, "_dpapi_available", lambda: False)
    envelope = secretbox.encrypt("hunter2", state_dir=state)
    assert envelope.startswith("$$aes:")
    assert secretbox.decrypt(envelope, state_dir=state) == "hunter2"
    assert (state / "secret.key").exists()
    assert len((state / "secret.key").read_bytes()) == 32


def test_aes_envelope_without_key_fails(state, monkeypatch):
    monkeypatch.setattr(secretbox, "_dpapi_available", lambda: False)
    envelope = secretbox.encrypt("pw", state_dir=state)
    (state / "secret.key").unlink()
    with pytest.raises(secretbox.SecretError):
        secretbox.decrypt(envelope, state_dir=state)


def test_tampered_envelope_fails(state):
    envelope = secretbox.encrypt("pw", state_dir=state)
    body = envelope[2:-2]
    scheme, _, b64 = body.partition(":")
    tampered = f"$${scheme}:{b64[:-4]}AAAA$$"
    with pytest.raises(secretbox.SecretError):
        secretbox.decrypt(tampered, state_dir=state)


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_dpapi_envelope_needs_windows(state, monkeypatch):
    envelope = secretbox.encrypt("pw", state_dir=state)
    assert envelope.startswith("$$dpapi:")
    monkeypatch.setattr(secretbox, "_dpapi_available", lambda: False)
    with pytest.raises(secretbox.SecretError):
        secretbox.decrypt(envelope, state_dir=state)


def test_env_file_rewrite_preserves_other_lines(tmp_path, state):
    env = tmp_path / ".env"
    env.write_text(
        "# leading comment\n"
        "SCHWAB_USERNAME=alice\n"
        "SCHWAB_PASSWORD=hunter2\n"
        "export SCHWAB_REFRESH_HEADLESS=1\n",
        encoding="utf-8",
    )

    envelope = secretbox.encrypt_in_env_file(env, ("SCHWAB_PASSWORD",), state_dir=state)

    text = env.read_text(encoding="utf-8")
    assert envelope is not None and envelope in text
    assert "hunter2" not in text
    assert "# leading comment" in text
    assert "SCHWAB_USERNAME=alice" in text
    assert "export SCHWAB_REFRESH_HEADLESS=1" in text
    assert secretbox.decrypt(envelope, state_dir=state) == "hunter2"


def test_env_file_quoted_password_is_encrypted(tmp_path, state):
    env = tmp_path / ".env"
    env.write_text('SCHWAB_PASSWORD="p@ss#word"\n', encoding="utf-8")
    envelope = secretbox.encrypt_in_env_file(env, ("SCHWAB_PASSWORD",), state_dir=state)
    assert envelope is not None
    assert secretbox.decrypt(envelope, state_dir=state) == "p@ss#word"
    assert "p@ss#word" not in env.read_text(encoding="utf-8")


def test_env_file_already_wrapped_is_noop(tmp_path, state):
    env = tmp_path / ".env"
    env.write_text("SCHWAB_PASSWORD=$$dpapi:AAAA$$\n", encoding="utf-8")
    before = env.read_text(encoding="utf-8")
    assert secretbox.encrypt_in_env_file(env, ("SCHWAB_PASSWORD",), state_dir=state) is None
    assert env.read_text(encoding="utf-8") == before


def test_env_file_missing_returns_none(tmp_path, state):
    missing = tmp_path / "nope.env"
    assert secretbox.encrypt_in_env_file(missing, ("SCHWAB_PASSWORD",), state_dir=state) is None
