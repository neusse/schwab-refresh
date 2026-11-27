"""Command line interface.

    schwab-refresh login     full OAuth round-trip (mints a NEW 7-day refresh token)
    schwab-refresh refresh   cheap refresh-grant if possible, full login otherwise
    schwab-refresh status    token ages + optional live API probe
    schwab-refresh token     print a valid access token (pipes: $(... token))
    schwab-refresh doctor    environment checks (+ --selftest for browser/callback)

Exit codes:
    0  success
    2  configuration problem
    3  interactive login required (refresh token unusable/expired)
    4  browser/automation failure
    5  token endpoint failure
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import shutil
import sys
import time
from dataclasses import replace
from pathlib import Path

from schwab_refresh import __version__, oauth, secretbox, tokenstore
from schwab_refresh.browser import Browser, BrowserError, chrome_path
from schwab_refresh.callback import CallbackError, CallbackServer, port_is_free
from schwab_refresh.config import ConfigError, Settings, load_settings, mask
from schwab_refresh.flow import LoginError, LoginFlow
from schwab_refresh.logsetup import Logger

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_INTERACTIVE = 3
EXIT_BROWSER = 4
EXIT_TOKEN = 5


# --------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------- #
def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--env-file", help="Load settings from this .env file.")
    parser.add_argument("--token-path", help="Token file to read/write (overrides env).")
    parser.add_argument("--state-dir", help="State dir for profile/logs/TLS (overrides env).")
    parser.add_argument(
        "--visible", action="store_true", help="Show the browser window (debugging, MFA)."
    )
    parser.add_argument(
        "--headless", action="store_true", help="Force headless even if env says otherwise."
    )
    parser.add_argument("--timeout", type=int, help="Overall flow timeout in seconds.")
    parser.add_argument("--mfa-timeout", type=int, help="Phone-approval wait in seconds.")
    parser.add_argument("--fresh-profile", action="store_true", help="Use an empty Chrome profile.")
    parser.add_argument("--verbose", action="store_true", help="Debug logging + page dumps.")
    parser.add_argument("--quiet", action="store_true", help="Only errors on stderr.")
    parser.add_argument("--json", action="store_true", help="Machine-readable summary on stdout.")


def _settings(args, *, need_creds: bool) -> Settings:
    headless: bool | None = None
    if args.visible or getattr(args, "manual", False):
        # --manual means a human has to type; a headless window would be useless.
        headless = False
    elif args.headless:
        headless = True
    cfg = load_settings(
        env_file=args.env_file,
        token_path=args.token_path,
        state_dir=args.state_dir,
        headless=headless,
        login_timeout_s=args.timeout,
        mfa_timeout_s=args.mfa_timeout,
        require_credentials=need_creds,
    )
    if cfg.secrets_encrypted_now and not args.quiet:
        names = ", ".join(cfg.secrets_encrypted_now)
        print(
            f"note: {names} in .env was plaintext; encrypted in place ($$…$$).",
            file=sys.stderr,
        )
    if args.fresh_profile:
        cfg = replace(cfg, profile_dir=cfg.state_dir / "chrome-profile-fresh")
        if cfg.profile_dir.exists():
            shutil.rmtree(cfg.profile_dir, ignore_errors=True)
    return cfg


class _RunLock:
    """One refresh at a time. A stale lock older than 60 minutes is taken over."""

    def __init__(self, state_dir: Path):
        self.path = Path(state_dir) / "refresh.lock"
        self._held = False

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            age = time.time() - self.path.stat().st_mtime
            if age < 3600:
                raise ConfigError(
                    f"another refresh is running (lock: {self.path}, age {age/60:.0f}m)"
                )
            self.path.unlink(missing_ok=True)
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        self._held = True
        return self

    def __exit__(self, *exc):
        if self._held:
            self.path.unlink(missing_ok=True)


def _summary(payload: dict, path: Path) -> dict:
    status = tokenstore.summarize(payload)
    return {
        "token_file": str(path),
        "access_token_expires_at": status.access_expires_at,
        "access_token_valid_for_s": status.access_valid_for_s,
        "refresh_token_created_at": status.created_at,
        "refresh_token_age_days": None
        if status.refresh_age_days is None
        else round(status.refresh_age_days, 2),
        "refresh_token_days_left": None
        if status.refresh_days_left is None
        else round(status.refresh_days_left, 2),
        "scope": status.scope,
    }


def _print_summary(payload: dict, path: Path, args, log: Logger, *, written: bool = True) -> None:
    summary = _summary(payload, path)
    if args.json:
        print(json.dumps(summary, indent=2))
        return
    log.info(f"token {'written' if written else 'file'}: {path}")
    if summary["access_token_valid_for_s"] is not None:
        log.info(
            f"access token valid for {summary['access_token_valid_for_s'] // 60} min"
        )
    if summary["refresh_token_days_left"] is not None:
        log.info(
            f"refresh token: {summary['refresh_token_days_left']:.1f} days left "
            f"(age {summary['refresh_token_age_days']:.1f} d)"
        )


# --------------------------------------------------------------------- #
# core operations
# --------------------------------------------------------------------- #
def do_full_login(
    cfg: Settings, log: Logger, *, manual: bool = False, verbose: bool = False
) -> oauth.TokenGrant:
    state = secrets.token_urlsafe(32)
    auth_url = oauth.build_authorize_url(cfg.client_id, cfg.redirect_uri, state)
    log.info(f"redirect uri: {cfg.redirect_uri}")
    log.info(f"client id:    {mask(cfg.client_id)}")

    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    try:
        with CallbackServer(cfg, log=log.info) as callback:
            with Browser(cfg, log=log.info, debug=verbose) as browser:
                browser.goto(auth_url)
                flow = LoginFlow(
                    browser,
                    log,
                    username=None if manual else cfg.username,
                    password=None if manual else cfg.password,
                    mfa_timeout_s=cfg.mfa_timeout_s,
                    overall_timeout_s=cfg.login_timeout_s,
                )
                result = flow.run(callback)
    except CallbackError as exc:
        raise ConfigError(str(exc)) from exc

    if result.error:
        raise oauth.OAuthError(
            f"Schwab returned {result.error}: {result.error_description or ''}".strip(),
            payload={"error": result.error},
        )
    if not result.code:
        raise oauth.OAuthError("callback carried no authorization code")

    if result.state and result.state != state:
        raise oauth.OAuthError(
            "OAuth state mismatch on the callback — refusing to exchange the code "
            "(possible CSRF or a stale callback). Re-run."
        )
    if not result.state:
        log.warn("callback carried no state parameter (state check skipped)")

    log.step("exchanging the authorization code for tokens")
    return oauth.exchange_code(cfg.client_id, cfg.client_secret, cfg.redirect_uri, result.code)


def do_refresh(cfg: Settings, log: Logger, *, force: bool = False) -> oauth.TokenGrant:
    """Refresh grant only (no browser). Raises oauth.OAuthError if unusable."""
    path = cfg.require_token_path()
    if force:
        raise oauth.OAuthError("forced", payload={"error": "forced"})
    payload = tokenstore.load_payload(path)
    refresh_token = tokenstore.get_refresh_token(payload)
    if not refresh_token:
        raise oauth.OAuthError("no refresh_token in token file", payload={"error": "invalid_grant"})
    log.step("trying the refresh grant (no browser)")
    return oauth.refresh_access_token(cfg.client_id, cfg.client_secret, refresh_token)


# --------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------- #
def _prompt_credentials(cfg: Settings) -> Settings:
    """Ask for the Schwab login at the terminal (password not echoed)."""
    username = input("Schwab login ID: ").strip()
    password = getpass.getpass("Schwab password: ")
    if not username or not password:
        raise ConfigError("login ID and password are both required")
    return replace(cfg, username=username, password=password)


def cmd_login(args) -> int:
    try:
        cfg = _settings(args, need_creds=not (args.manual or args.prompt_credentials))
        log = Logger(cfg.state_dir, verbose=args.verbose, quiet=args.quiet)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    if args.prompt_credentials and not (cfg.username and cfg.password):
        try:
            cfg = _prompt_credentials(cfg)
        except (ConfigError, EOFError) as exc:
            print(f"error: {exc or 'no credentials entered'}", file=sys.stderr)
            return EXIT_CONFIG

    token_path = Path(args.token_path) if args.token_path else cfg.token_path
    try:
        with _RunLock(cfg.state_dir):
            grant = do_full_login(cfg, log, manual=args.manual, verbose=args.verbose)
            if args.no_write:
                log.warn("--no-write: token not saved")
                payload = None
            else:
                if token_path is None:
                    raise ConfigError(
                        "no token output file; set SCHWAB_TOKEN_PATH or pass --token-path"
                    )
                payload = tokenstore.write_token_file(token_path, grant)
        if payload is not None:
            _print_summary(payload, token_path, args, log)
            if args.print_token:
                print(tokenstore.get_access_token(payload))
        elif args.print_token:
            print(grant.access_token)
        return EXIT_OK
    except ConfigError as exc:
        log.error(str(exc))
        return EXIT_CONFIG
    except LoginError as exc:
        log.error(str(exc))
        if exc.screenshot:
            log.error(f"screenshot: {exc.screenshot}")
        return EXIT_BROWSER
    except BrowserError as exc:
        log.error(str(exc))
        return EXIT_BROWSER
    except oauth.OAuthError as exc:
        log.error(f"token exchange failed: {exc}")
        return EXIT_TOKEN
    except KeyboardInterrupt:
        log.warn("interrupted")
        return EXIT_BROWSER
    finally:
        log.close()


def cmd_refresh(args) -> int:
    try:
        cfg = _settings(args, need_creds=False)
        log = Logger(cfg.state_dir, verbose=args.verbose, quiet=args.quiet)
        token_path = cfg.require_token_path()
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        with _RunLock(cfg.state_dir):
            payload = None
            status = None
            if token_path.exists() and not args.force:
                try:
                    payload = tokenstore.load_payload(token_path)
                    status = tokenstore.summarize(payload)
                except tokenstore.TokenFileError as exc:
                    log.warn(f"{exc}; doing a full login")

            if status is not None and status.refresh_days_left is not None:
                if status.refresh_days_left <= 0.25:
                    log.info("refresh token is about to expire: full login required")
                    status = None
                elif status.refresh_days_left < 1.0:
                    log.info(f"refresh token has {status.refresh_days_left:.2f} days left")

            if (
                status is not None
                and not args.force
                and (status.access_valid_for_s or 0) > 300
                and (status.refresh_days_left or 0) > 0.25
            ):
                log.info(
                    f"access token is still valid for {(status.access_valid_for_s or 0) // 60} min; "
                    "nothing to do"
                )
                _print_summary(payload, token_path, args, log, written=False)
                if args.print_token:
                    print(tokenstore.get_access_token(payload))
                return EXIT_OK

            grant = None
            if status is not None and payload is not None:
                try:
                    grant = do_refresh(cfg, log)
                except oauth.OAuthError as exc:
                    if exc.payload.get("error") == "forced":
                        pass
                    elif exc.is_invalid_grant:
                        log.warn(f"refresh grant rejected ({exc}); doing a full login")
                    else:
                        log.warn(f"refresh grant failed ({exc}); doing a full login")

            if grant is None:
                if args.refresh_only:
                    log.error("refresh grant unusable and --refresh-only was given")
                    return EXIT_INTERACTIVE
                cfg = _settings(args, need_creds=True)
                log.step("starting a full browser login (mints a new refresh token)")
                grant = do_full_login(cfg, log, verbose=args.verbose)
                payload = tokenstore.write_token_file(token_path, grant, reset_creation=True)
            else:
                payload = tokenstore.write_token_file(token_path, grant, reset_creation=False)
        _print_summary(payload, token_path, args, log)
        if args.print_token:
            print(tokenstore.get_access_token(payload))
        return EXIT_OK
    except ConfigError as exc:
        log.error(str(exc))
        return EXIT_CONFIG
    except LoginError as exc:
        log.error(str(exc))
        if exc.screenshot:
            log.error(f"screenshot: {exc.screenshot}")
        return EXIT_INTERACTIVE
    except (BrowserError, CallbackError) as exc:
        log.error(str(exc))
        return EXIT_BROWSER
    except oauth.OAuthError as exc:
        log.error(f"token exchange failed: {exc}")
        return EXIT_TOKEN
    except KeyboardInterrupt:
        log.warn("interrupted")
        return EXIT_BROWSER
    finally:
        log.close()


def cmd_token(args) -> int:
    """Print a usable access token; refresh it first if it is close to expiry."""
    args.no_write = False
    args.force = False
    args.refresh_only = False
    args.print_token = False
    try:
        cfg = _settings(args, need_creds=False)
        log = Logger(cfg.state_dir, verbose=args.verbose, quiet=True)
        token_path = cfg.require_token_path()
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        payload = tokenstore.load_payload(token_path)
        status = tokenstore.summarize(payload)
        if (status.access_valid_for_s or 0) < 120:
            log.step("access token stale; refreshing")
            grant = do_refresh(cfg, log)
            payload = tokenstore.write_token_file(token_path, grant, reset_creation=False)
    except tokenstore.TokenFileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except oauth.OAuthError as exc:
        print(f"error: {exc} (run `schwab-refresh refresh`)", file=sys.stderr)
        return EXIT_INTERACTIVE
    finally:
        log.close()

    print(tokenstore.get_access_token(payload))
    return EXIT_OK


def cmd_status(args) -> int:
    try:
        cfg = _settings(args, need_creds=False)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    rows: dict = {
        "client_id": mask(cfg.client_id),
        "redirect_uri": cfg.redirect_uri,
        "callback_port_free": port_is_free(cfg.redirect.hostname or "127.0.0.1", cfg.callback_port),
        "profile_dir": str(cfg.profile_dir),
        "profile_exists": cfg.profile_dir.exists(),
        "state_dir": str(cfg.state_dir),
    }
    exit_code = EXIT_OK
    token_path = cfg.token_path
    if token_path is None:
        rows["token_file"] = None
        rows["error"] = "SCHWAB_TOKEN_PATH not set"
        exit_code = EXIT_CONFIG
    elif not token_path.exists():
        rows["token_file"] = str(token_path)
        rows["error"] = "token file missing; run `schwab-refresh login`"
        exit_code = EXIT_INTERACTIVE
    else:
        try:
            payload = tokenstore.load_payload(token_path)
            rows.update(_summary(payload, token_path))
            if args.verify:
                ok, detail = oauth.probe(
                    tokenstore.get_access_token(payload) or "",
                    params={"symbols": "SPY", "fields": "quote"},
                )
                rows["verify_marketdata"] = {"ok": ok, "detail": detail}
                if ok:
                    ok2, detail2 = oauth.probe(
                        tokenstore.get_access_token(payload) or "",
                        path=oauth.USER_PREFERENCE_URL,
                        params={},
                    )
                    rows["verify_trader"] = {"ok": ok2, "detail": detail2}
        except tokenstore.TokenFileError as exc:
            rows["error"] = str(exc)
            exit_code = EXIT_CONFIG

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for key, value in rows.items():
            print(f"{key:28} {value}")
    return exit_code


def cmd_doctor(args) -> int:
    checks: list[tuple[str, bool, str]] = []

    try:
        # Deliberately avoid importing seleniumbase here: importing it fixes
        # its downloads folder to the current CWD, which would defeat the
        # containment done in Browser.start().
        from importlib.metadata import version as pkg_version

        checks.append(("seleniumbase", True, pkg_version("seleniumbase")))
    except Exception as exc:  # noqa: BLE001
        checks.append(("seleniumbase", False, str(exc)))

    chrome = chrome_path()
    checks.append(("chrome", bool(chrome), chrome or "not found"))

    cfg: Settings | None = None
    try:
        cfg = _settings(args, need_creds=False)
    except ConfigError as exc:
        checks.append(("config", False, str(exc)))

    # Report the *effective* values: an encrypted .env yields $$…$$ in the
    # environment, so masking that would hide the key instead of identifying it.
    env_file = Path(args.env_file) if getattr(args, "env_file", None) else Path.cwd() / ".env"
    wrapped = secretbox.env_file_wrapped_vars(env_file)

    for var, value, secret in (
        ("SCHWAB_API_KEY", cfg.client_id if cfg else os.environ.get("SCHWAB_API_KEY"), True),
        ("SCHWAB_APP_SECRET", cfg.client_secret if cfg else os.environ.get("SCHWAB_APP_SECRET"), True),
        ("SCHWAB_CALLBACK_URL", cfg.redirect_uri if cfg else os.environ.get("SCHWAB_CALLBACK_URL"), False),
        (
            "SCHWAB_TOKEN_PATH",
            str(cfg.token_path) if cfg and cfg.token_path else os.environ.get("SCHWAB_TOKEN_PATH"),
            False,
        ),
    ):
        if not value:
            checks.append((var, False, "missing"))
            continue
        detail = mask(value) if secret else value
        if var in wrapped:
            detail += "  ($$...$$ in .env)"
        checks.append((var, True, detail))

    if cfg is not None:
        checks.append(("credentials", bool(cfg.username and cfg.password), "username+password set" if cfg.username and cfg.password else "missing (needed for unattended login)"))
        checks.append(
            ("callback port", port_is_free(cfg.redirect.hostname or "127.0.0.1", cfg.callback_port), f"{cfg.redirect.hostname}:{cfg.callback_port}")
        )
        checks.append(("state dir", True, str(cfg.state_dir)))
        if cfg.token_path:
            checks.append(("token file", cfg.token_path.exists(), str(cfg.token_path)))

    if args.selftest and cfg is not None:
        checks.append(("loopback callback selftest", *_selftest(cfg, args)))

    if args.json:
        print(json.dumps([{"check": c, "ok": ok, "detail": d} for c, ok, d in checks], indent=2))
    else:
        for name, ok, detail in checks:
            print(f"[{' ok ' if ok else 'FAIL'}] {name:28} {detail}")
    return EXIT_OK if all(ok for _, ok, _ in checks) else EXIT_CONFIG


def _selftest(cfg: Settings, args) -> tuple[bool, str]:
    """Serve the redirect URI locally and have Chrome load it — proves the
    TLS + --ignore-certificate-errors path without touching Schwab."""
    from dataclasses import replace

    log = Logger(cfg.state_dir, quiet=True)
    test_cfg = replace(cfg, headless=True)
    try:
        with CallbackServer(test_cfg, log=lambda *_: None) as server:
            with Browser(test_cfg, log=lambda *_: None, debug=True) as browser:
                marker = secrets.token_hex(4)
                browser.goto(f"{cfg.redirect_uri}?code=SELFTEST{marker}&state=selftest")
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    result = server.poll()
                    if result is not None and result.code == f"SELFTEST{marker}":
                        return True, f"code round-tripped ({marker})"
                    time.sleep(0.25)
                return False, f"no callback; browser url={browser.url!r}"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        log.close()


# --------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="schwab-refresh",
        description="Unattended Charles Schwab OAuth token minting.",
    )
    parser.add_argument("--version", action="version", version=f"schwab-refresh {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    login = sub.add_parser("login", help="Full browser login; mints a new refresh token.")
    _add_common(login)
    login.add_argument("--manual", action="store_true", help="Leave the login form to you (visible window).")
    login.add_argument(
        "--prompt-credentials",
        action="store_true",
        help="Ask for the login ID/password at the terminal instead of reading env/.env.",
    )
    login.add_argument("--no-write", action="store_true", help="Do not save the token file.")
    login.add_argument("--print-token", action="store_true", help="Print the access token to stdout.")
    login.set_defaults(func=cmd_login)

    refresh = sub.add_parser("refresh", help="Refresh if possible; full login when needed.")
    _add_common(refresh)
    refresh.add_argument("--force", action="store_true", help="Skip refresh grant; do a full login.")
    refresh.add_argument("--refresh-only", action="store_true", help="Never open a browser; fail instead.")
    refresh.add_argument("--print-token", action="store_true", help="Print the access token to stdout.")
    refresh.set_defaults(func=cmd_refresh)

    token = sub.add_parser("token", help="Print a valid access token.")
    _add_common(token)
    token.set_defaults(func=cmd_token)

    status = sub.add_parser("status", help="Show token ages and configuration.")
    _add_common(status)
    status.add_argument("--verify", action="store_true", help="Probe the API with the stored access token.")
    status.set_defaults(func=cmd_status)

    doctor = sub.add_parser("doctor", help="Check the environment.")
    _add_common(doctor)
    doctor.add_argument("--selftest", action="store_true", help="Run the loopback callback + browser selftest.")
    doctor.set_defaults(func=cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "print_token"):
        args.print_token = False
    if not hasattr(args, "no_write"):
        args.no_write = False
    if not hasattr(args, "json"):
        args.json = False
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
