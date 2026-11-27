"""Two-way protection for the secrets kept in ``.env``.

The app key, the app secret and the login password are the dangerous things on
disk here. `.env` files get copied, synced (OneDrive!), pasted into chats, and
backed up. So the first time a command loads a **plaintext** secret from
`.env`, the tool replaces it with a ``$$…$$`` envelope and never touches the
plaintext again.

Envelope format::

    SCHWAB_API_KEY=$$dpapi:<base64>$$
    SCHWAB_APP_SECRET=$$dpapi:<base64>$$
    SCHWAB_PASSWORD=$$aes:<base64>$$

Backends, chosen per envelope:

* ``dpapi`` — Windows DPAPI (``CryptProtectData``). The blob is bound to the
  current Windows user account, so another user account (or the same file on a
  different PC) cannot decrypt it. Nothing to store or manage. This is the
  default on Windows.
* ``aes`` — AES-GCM with a random key at ``<state>/secret.key`` (0600). Used
  off Windows, or when DPAPI is unavailable. Honest framing: this keeps the
  password out of the open, but the key sits next to it in your profile, so it
  is obfuscation at rest, not account binding.

Both are "not a one-way hash": the tool must replay the password into Schwab's
login form, so the ciphertext has to be reversible.
"""

from __future__ import annotations

import base64
import os
import re
import secrets
import sys
from pathlib import Path

_ENTROPY = b"schwab-refresh:v1"
_KEY_BYTES = 32
_ENVELOPE_RE = re.compile(r"^\$\$(?P<scheme>[a-z]+):(?P<body>[A-Za-z0-9+/=]+)\$\$$")
_LINE_RE = re.compile(
    r"^(?P<prefix>\s*(?:export\s+)?)(?P<key>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<sep>\s*=\s*)(?P<value>.*?)(?P<eol>\r?\n)?$"
)
_VALID_SCHEMES = ("dpapi", "aes")


class SecretError(Exception):
    """The envelope exists but cannot be opened here."""


# --------------------------------------------------------------------- #
# envelope helpers
# --------------------------------------------------------------------- #
def is_wrapped(value: str | None) -> bool:
    return bool(value) and _ENVELOPE_RE.match(value.strip()) is not None


def encrypt(plaintext: str, *, state_dir: Path) -> str:
    """Encrypt to a ``$$scheme:base64$$`` envelope."""
    if not plaintext:
        raise SecretError("cannot encrypt an empty secret")
    if _dpapi_available():
        body = _dpapi_protect(plaintext.encode("utf-8"))
        scheme = "dpapi"
    else:
        body = _aes_protect(plaintext.encode("utf-8"), state_dir=state_dir)
        scheme = "aes"
    return f"$${scheme}:{base64.b64encode(body).decode('ascii')}$$"


def decrypt(envelope: str, *, state_dir: Path) -> str:
    """Open a ``$$scheme:base64$$`` envelope back to plaintext."""
    match = _ENVELOPE_RE.match(envelope.strip())
    if match is None:
        raise SecretError("not a $$…$$ envelope")
    scheme = match.group("scheme")
    try:
        body = base64.b64decode(match.group("body"), validate=True)
    except ValueError as exc:
        raise SecretError("envelope body is not valid base64") from exc

    if scheme == "dpapi":
        if not _dpapi_available():
            raise SecretError("this envelope needs Windows DPAPI, which is not available")
        return _dpapi_unprotect(body).decode("utf-8")
    if scheme == "aes":
        try:
            return _aes_unprotect(body, state_dir=state_dir).decode("utf-8")
        except FileNotFoundError as exc:
            raise SecretError(
                f"the AES key is missing ({exc.filename}); this .env was encrypted "
                "with a key from another machine/profile"
            ) from exc
        except Exception as exc:  # InvalidTag et al.
            raise SecretError(
                f"cannot decrypt the AES envelope: {type(exc).__name__}"
            ) from exc
    raise SecretError(f"unknown envelope scheme {scheme!r}")


# --------------------------------------------------------------------- #
# Windows DPAPI
# --------------------------------------------------------------------- #
def _dpapi_available() -> bool:
    return sys.platform == "win32"


def _dpapi_call(*, protect: bool, data: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    def blob(payload: bytes) -> tuple[DATA_BLOB, ctypes.Array]:
        buf = ctypes.create_string_buffer(payload, len(payload))
        return DATA_BLOB(len(payload), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    fn.argtypes = [
        ctypes.POINTER(DATA_BLOB),  # data in
        wintypes.LPCWSTR,  # description
        ctypes.POINTER(DATA_BLOB),  # entropy
        ctypes.c_void_p,  # reserved
        ctypes.c_void_p,  # prompt struct
        wintypes.DWORD,  # flags
        ctypes.POINTER(DATA_BLOB),  # data out
    ]
    fn.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    in_blob, keep_in = blob(data)
    entropy_blob, keep_entropy = blob(_ENTROPY)
    out_blob = DATA_BLOB()
    _keep = (keep_in, keep_entropy)  # buffers must outlive the call

    # Arg 2 is a description for protect, and an out-pointer for unprotect;
    # None is valid for both, which keeps one signature for the two calls.
    ok = fn(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        0x1,  # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(out_blob),
    )
    if not ok:
        raise SecretError(f"DPAPI call failed (error {ctypes.get_last_error()})")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _dpapi_protect(payload: bytes) -> bytes:
    return _dpapi_call(protect=True, data=payload)


def _dpapi_unprotect(payload: bytes) -> bytes:
    try:
        return _dpapi_call(protect=False, data=payload)
    except SecretError as exc:
        raise SecretError(
            "DPAPI could not open this envelope — it was encrypted for a different "
            "Windows account or machine"
        ) from exc


# --------------------------------------------------------------------- #
# AES-GCM fallback
# --------------------------------------------------------------------- #
def _key_path(state_dir: Path) -> Path:
    return Path(state_dir) / "secret.key"


def _read_key(state_dir: Path) -> bytes:
    path = _key_path(state_dir)
    raw = path.read_bytes()  # FileNotFoundError is intentional & reported
    if len(raw) != _KEY_BYTES:
        raise SecretError(f"corrupt key file {path}")
    return raw


def _load_or_create_key(state_dir: Path) -> bytes:
    path = _key_path(state_dir)
    if path.exists():
        raw = path.read_bytes()
        if len(raw) != _KEY_BYTES:
            raise SecretError(f"corrupt key file {path}")
        return raw
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(_KEY_BYTES)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def _aes_protect(payload: bytes, *, state_dir: Path) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _load_or_create_key(state_dir)
    nonce = os.urandom(12)
    return b"\x01" + nonce + AESGCM(key).encrypt(nonce, payload, _ENTROPY)


def _aes_unprotect(body: bytes, *, state_dir: Path) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(body) < 14 or body[:1] != b"\x01":
        raise SecretError("unsupported AES envelope version")
    key = _read_key(state_dir)
    return AESGCM(key).decrypt(body[1:13], body[13:], _ENTROPY)


# --------------------------------------------------------------------- #
# .env rewriting
# --------------------------------------------------------------------- #
def env_file_wrapped_vars(env_path: str | Path) -> set[str]:
    """Names of the variables in ``env_path`` whose value is already a $$…$$ envelope.

    Reported uppercase. Used by ``doctor`` to say "encrypted at rest" based on
    the file, which is not the same thing as the value this process is using:
    a plaintext environment variable can shadow an encrypted .env line.
    """
    try:
        text = Path(env_path).read_text(encoding="utf-8")
    except OSError:
        return set()
    wrapped: set[str] = set()
    for line in text.splitlines():
        match = _LINE_RE.match(line)
        if match is None:
            continue
        if is_wrapped(match.group("value").strip()):
            wrapped.add(match.group("key").upper())
    return wrapped


def encrypt_in_env_file(
    env_path: str | Path,
    candidates: tuple[str, ...] | list[str],
    *,
    state_dir: Path,
) -> dict[str, str]:
    """Encrypt every plaintext line in ``env_path`` whose key is a candidate.

    Returns ``{ENV_VAR: envelope}`` for the lines rewritten in place, keyed by
    the variable name as it appears in the file, and ``{}`` when nothing
    matched (already wrapped, missing file, value absent). All matches are
    processed, not just the first: one stale alias left behind as plaintext
    would defeat the point of encrypting its sibling.

    Each plaintext is verified to decrypt before anything is written, and no
    plaintext backup is kept — that would defeat the point.
    """
    path = Path(env_path)
    try:
        original = path.read_text(encoding="utf-8")
    except OSError:
        return {}

    wanted = {name.upper() for name in candidates}
    lines = original.splitlines(keepends=True)
    envelopes: dict[str, str] = {}

    for index, line in enumerate(lines):
        match = _LINE_RE.match(line)
        if not match:
            continue
        var = match.group("key")
        if var.upper() not in wanted:
            continue
        raw_value = match.group("value").strip()
        if raw_value[:1] in ("'", '"') and raw_value[-1:] == raw_value[:1]:
            raw_value = raw_value[1:-1]
        if not raw_value or is_wrapped(raw_value):
            continue

        envelope = encrypt(raw_value, state_dir=state_dir)
        if decrypt(envelope, state_dir=state_dir) != raw_value:
            raise SecretError("encryption self-check failed; .env left unchanged")
        lines[index] = f"{match.group('prefix')}{var}={envelope}{match.group('eol') or ''}"
        envelopes[var.upper()] = envelope

    if not envelopes:
        return {}

    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("".join(lines), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)
    return envelopes
