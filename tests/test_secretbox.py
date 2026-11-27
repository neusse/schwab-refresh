import sys

import pytest
from dotenv import dotenv_values

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


def test_aes_key_file_is_written_in_binary(state, monkeypatch):
    """A 0x0A byte in the key must stay one byte.

    os.open() without O_BINARY is a *text* handle on Windows and rewrites 0x0A
    as CRLF. A random 32-byte key hits that ~12% of the time, which used to
    leave a 33-byte secret.key and break every later decrypt for that profile.
    """
    monkeypatch.setattr(secretbox, "_dpapi_available", lambda: False)
    monkeypatch.setattr(secretbox.secrets, "token_bytes", lambda n: b"\n" * n)

    envelope = secretbox.encrypt("pw", state_dir=state)

    assert (state / "secret.key").read_bytes() == b"\n" * 32
    assert secretbox.decrypt(envelope, state_dir=state) == "pw"


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

    envelopes = secretbox.encrypt_in_env_file(env, ("SCHWAB_PASSWORD",), state_dir=state)

    text = env.read_text(encoding="utf-8")
    envelope = envelopes["SCHWAB_PASSWORD"]
    assert envelope in text
    assert "hunter2" not in text
    assert "# leading comment" in text
    assert "SCHWAB_USERNAME=alice" in text
    assert "export SCHWAB_REFRESH_HEADLESS=1" in text
    assert secretbox.decrypt(envelope, state_dir=state) == "hunter2"


def test_env_file_quoted_password_is_encrypted(tmp_path, state):
    env = tmp_path / ".env"
    env.write_text('SCHWAB_PASSWORD="p@ss#word"\n', encoding="utf-8")
    envelopes = secretbox.encrypt_in_env_file(env, ("SCHWAB_PASSWORD",), state_dir=state)
    envelope = envelopes["SCHWAB_PASSWORD"]
    assert secretbox.decrypt(envelope, state_dir=state) == "p@ss#word"
    assert "p@ss#word" not in env.read_text(encoding="utf-8")


def test_env_file_already_wrapped_is_noop(tmp_path, state):
    env = tmp_path / ".env"
    env.write_text("SCHWAB_PASSWORD=$$dpapi:AAAA$$\n", encoding="utf-8")
    before = env.read_text(encoding="utf-8")
    assert secretbox.encrypt_in_env_file(env, ("SCHWAB_PASSWORD",), state_dir=state) == {}
    assert env.read_text(encoding="utf-8") == before


def test_env_file_missing_returns_empty(tmp_path, state):
    missing = tmp_path / "nope.env"
    assert secretbox.encrypt_in_env_file(missing, ("SCHWAB_PASSWORD",), state_dir=state) == {}


@pytest.mark.parametrize(
    "line",
    [
        "SCHWAB_API_KEY=value  # inline note",
        r'SCHWAB_API_KEY="pa\"ss\\word"',
        r"SCHWAB_API_KEY='single \\ literal'",
        "SCHWAB_API_KEY=nmE%g8@#Rc",
        "export SCHWAB_API_KEY=exported",
        "SCHWAB_API_KEY=  spaced  ",
    ],
)
def test_rewrite_preserves_the_value_dotenv_parses(tmp_path, state, line):
    """The migration must not change the credential it is protecting."""
    env = tmp_path / ".env"
    env.write_text(line + "\n", encoding="utf-8")
    before = dotenv_values(env)["SCHWAB_API_KEY"]
    assert before

    envelopes = secretbox.encrypt_in_env_file(env, ("SCHWAB_API_KEY",), state_dir=state)

    assert secretbox.decrypt(envelopes["SCHWAB_API_KEY"], state_dir=state) == before
    assert dotenv_values(env)["SCHWAB_API_KEY"] == envelopes["SCHWAB_API_KEY"]


def test_inline_comment_does_not_end_up_inside_the_secret(tmp_path, state):
    env = tmp_path / ".env"
    env.write_text("SCHWAB_API_KEY=value  # rotate me in March\n", encoding="utf-8")

    envelopes = secretbox.encrypt_in_env_file(env, ("SCHWAB_API_KEY",), state_dir=state)

    assert secretbox.decrypt(envelopes["SCHWAB_API_KEY"], state_dir=state) == "value"
    assert dotenv_values(env)["SCHWAB_API_KEY"].startswith("$$")


def test_multiline_quoted_secret_is_left_alone(tmp_path, state):
    """A value spanning lines cannot be bound from one line: leave it readable
    rather than rewriting a fragment and mangling the file."""
    env = tmp_path / ".env"
    before = "SCHWAB_API_KEY=k\nSCHWAB_PASSWORD='multi\nline secret'\n"
    env.write_text(before, encoding="utf-8")

    assert secretbox.encrypt_in_env_file(env, ("SCHWAB_PASSWORD",), state_dir=state) == {}
    assert env.read_text(encoding="utf-8") == before


def test_env_file_wrapped_vars_reports_only_envelopes(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "SCHWAB_API_KEY=$$dpapi:AAAA$$\n"
        "SCHWAB_APP_SECRET=plain\n"
        "SCHWAB_CALLBACK_URL=https://127.0.0.1:8182/\n",
        encoding="utf-8",
    )
    assert secretbox.env_file_wrapped_vars(env) == {"SCHWAB_API_KEY"}
    assert secretbox.env_file_wrapped_vars(tmp_path / "missing.env") == set()


def test_env_file_encrypts_every_matching_line(tmp_path, state):
    env = tmp_path / ".env"
    env.write_text(
        "SCHWAB_API_KEY=plain-key\n"
        "SCHWAB_APP_KEY=alias-key\n"
        "SCHWAB_APP_SECRET=plain-secret\n"
        "SCHWAB_CALLBACK_URL=https://127.0.0.1:8182/\n",
        encoding="utf-8",
    )

    envelopes = secretbox.encrypt_in_env_file(
        env, ("SCHWAB_API_KEY", "SCHWAB_APP_KEY"), state_dir=state
    )

    text = env.read_text(encoding="utf-8")
    assert set(envelopes) == {"SCHWAB_API_KEY", "SCHWAB_APP_KEY"}
    assert secretbox.decrypt(envelopes["SCHWAB_API_KEY"], state_dir=state) == "plain-key"
    assert secretbox.decrypt(envelopes["SCHWAB_APP_KEY"], state_dir=state) == "alias-key"
    assert "plain-key" not in text and "alias-key" not in text
    # Not a candidate for this call, so left alone.
    assert "SCHWAB_APP_SECRET=plain-secret" in text
    assert "SCHWAB_CALLBACK_URL=https://127.0.0.1:8182/" in text
