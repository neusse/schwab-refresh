"""The Schwab login state machine.

Schwab's OAuth consent flow is a fixed sequence of pages *for a fresh login*,
but a trusted device skips around: MFA can be absent entirely, "trust this
device" can be absent, and BOTH orderings of consent/account picker have been
seen. So this is not the linear step list used by the reference script — it is
a small dispatcher keyed on the current URL, with per-page attempt guards. That
also means a click that silently no-ops (Angular not hydrated yet) is retried
instead of deadlocking the run.

Pages handled:

    /login-one-step              login form
    /authenticators              MFA method picker
    /mobile_approve              waiting for the phone approval
    /devicetag/remember          trust this device
    /third-party-auth/cag        consent (terms + modal)
    /third-party-auth/account    account selection
    /third-party-auth/confirmation  done
    anything off schwab.com      the OAuth redirect (code!)
"""

from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass
from typing import Callable

from schwab_refresh.browser import Browser
from schwab_refresh.callback import CallbackResult, CallbackServer
from schwab_refresh.logsetup import Logger

# -- selectors (mirror schwab_cli/browser/selectors.py @ 2026-04-21) ----
LOGIN_USERNAME = "input#loginIdInput"
LOGIN_PASSWORD = "input#passwordInput"
LOGIN_SUBMIT = "button#btnLogin"
SCHWAB_APP_OPTION = "#mobile_approve"
TRUST_YES = "input#remember-device-yes"
TRUST_CONTINUE = "button#btnContinue"
CONSENT_CHECKBOX = "input#acceptTerms"
CONSENT_CONTINUE = "button#submit-btn"
CONSENT_MODAL_ACCEPT = "button#agree-modal-btn-"
ACCOUNT_CHECKBOX = 'input[type="checkbox"]'
ACCOUNT_CONTINUE = "button#submit-btn"
DONE = "button#cancel-btn"

# -- URL fragments ------------------------------------------------------
URL_LOGIN = "/login-one-step"
URL_MFA_PICKER = "/authenticators"
URL_MFA_WAITING = "/mobile_approve"
URL_TRUST_DEVICE = "/devicetag/remember"
URL_CONSENT = "/third-party-auth/cag"
URL_ACCOUNTS = "/third-party-auth/account"
URL_CONFIRMATION = "/third-party-auth/confirmation"

SCHWAB_DOMAINS = ("schwab.com", "schwabapi.com")

# Copy that means "stop, a human has to look at this".
_BLOCKED_MARKERS = (
    "access denied",
    "you don't have permission to access",
    "unusual activity",
    "we're sorry",
    "temporarily unavailable",
    "system is currently unavailable",
)


class LoginError(Exception):
    """The flow could not complete (bad creds, blocked, unknown page...)."""

    def __init__(self, message: str, *, screenshot: str | None = None):
        super().__init__(message)
        self.screenshot = screenshot


@dataclass
class _PageRule:
    key: str
    match: str
    handle: Callable[[], None]
    retry_after_s: float = 20.0
    description: str = ""


def is_off_schwab(url: str) -> bool:
    return bool(url) and all(domain not in url for domain in SCHWAB_DOMAINS)


def parse_callback(url: str) -> CallbackResult:
    parsed = urllib.parse.urlsplit(url)
    params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    return CallbackResult(
        code=params.get("code"),
        state=params.get("state"),
        error=params.get("error"),
        error_description=params.get("error_description"),
        url=url,
    )


class LoginFlow:
    def __init__(
        self,
        browser: Browser,
        log: Logger,
        *,
        username: str | None,
        password: str | None,
        mfa_timeout_s: int = 180,
        overall_timeout_s: int = 600,
        poll_s: float = 0.4,
    ):
        self.browser = browser
        self.log = log
        self.username = username
        self.password = password
        self.mfa_timeout_s = mfa_timeout_s
        self.overall_timeout_s = overall_timeout_s
        self.poll_s = poll_s
        self._attempts: dict[str, float] = {}
        self._last_page = ""
        self._seen_pages: list[str] = []
        self._awaiting_mfa_since: float | None = None

    # ------------------------------------------------------------------
    def run(self, callback: CallbackServer) -> CallbackResult:
        """Drive the browser until the code is captured (server or URL)."""
        deadline = time.monotonic() + self.overall_timeout_s
        rules = self._rules()

        while time.monotonic() < deadline:
            # 1. the callback server may already have the code
            result = callback.poll()
            if result is not None:
                return result

            url = self.browser.url
            if url and url.startswith("chrome-error://"):
                # Navigation to the loopback failed before Chrome exposed the
                # URL. The server should have the code; give it a moment.
                result = self._wait_callback_briefly(callback, 3.0)
                if result is not None:
                    return result
                raise LoginError(
                    "the browser could not load the loopback callback page and the "
                    "callback server saw no request. Check that SCHWAB_CALLBACK_URL "
                    "matches the port this tool is listening on."
                )

            if is_off_schwab(url):
                result = parse_callback(url)
                if result.should_stop:
                    return result

            self._note_page(url)
            self._check_blocked(url)

            rule = self._match(url, rules)
            if rule is None:
                if not url:
                    time.sleep(self.poll_s)
                    continue
                self._handle_unknown(url, deadline)
                continue

            if rule.key == "mfa" and self._awaiting_mfa_since is None:
                self._awaiting_mfa_since = time.monotonic()
                self.log.step(
                    "waiting for the phone approval — approve the Schwab notification "
                    f"(up to {self.mfa_timeout_s}s)"
                )
            if rule.key == "mfa" and self._mfa_timed_out():
                raise LoginError(
                    "timed out waiting for the mobile app approval. Approve the push "
                    "notification, or raise SCHWAB_REFRESH_MFA_TIMEOUT."
                )

            last = self._attempts.get(rule.key)
            if last is not None and time.monotonic() - last < rule.retry_after_s:
                time.sleep(self.poll_s)
                continue

            self._attempts[rule.key] = time.monotonic()
            self.log.debug(f"handling page {rule.key} at {url}")
            rule.handle()

        url = self.browser.url
        if url and self._match(url, rules) is None and not is_off_schwab(url):
            raise self._unknown_error(url)
        raise LoginError(
            f"login did not complete within {self.overall_timeout_s}s "
            f"(last page: {url!r}; seen: {' -> '.join(self._seen_pages)})"
        )

    # ------------------------------------------------------------------
    def _wait_callback_briefly(self, callback: CallbackServer, seconds: float) -> CallbackResult | None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            result = callback.poll()
            if result is not None:
                return result
            time.sleep(0.2)
        return None

    def _note_page(self, url: str) -> None:
        if url != self._last_page:
            self._last_page = url
            if url:
                self._seen_pages.append(url.split("?")[0])
                self.log.debug(f"page: {url.split('?')[0]}")

    def _check_blocked(self, url: str) -> None:
        now = time.monotonic()
        if now - getattr(self, "_last_block_check", 0.0) < 2.0:
            return
        self._last_block_check = now
        body = self.browser.body_text(600).lower()
        haystack = f"{self.browser.title.lower()} {body}"
        for marker in _BLOCKED_MARKERS:
            if marker in haystack:
                dump = self.browser.debug_dump("blocked")
                hint = (
                    "Schwab's bot protection blocked the login. Try again with a "
                    "visible window (`--visible`) — headless is more likely to be "
                    "challenged — or with `--fresh-profile` if the profile is stale."
                )
                raise LoginError(
                    f"blocked page detected ({marker!r}) at {url}. {hint}",
                    screenshot=dump.get("screenshot"),
                )

    def _match(self, url: str, rules: list[_PageRule]) -> _PageRule | None:
        for rule in rules:
            if rule.match in url:
                return rule
        return None

    def _mfa_timed_out(self) -> bool:
        if self._awaiting_mfa_since is None:
            return False
        return time.monotonic() - self._awaiting_mfa_since > self.mfa_timeout_s

    def _handle_unknown(self, url: str, deadline: float) -> None:
        """Unknown Schwab page: log it, dump evidence, and give it a grace
        period in case it is a transient interstitial."""
        key = url.split("?")[0]
        first = self._attempts.setdefault("unknown:" + key, time.monotonic())
        if time.monotonic() - first < 15 and time.monotonic() < deadline:
            self.log.debug(f"unknown page, waiting: {key}")
            time.sleep(1.0)
            return
        raise self._unknown_error(url)

    def _unknown_error(self, url: str) -> LoginError:
        dump = self.browser.debug_dump("unknown")
        return LoginError(
            f"unexpected page during login: {url.split('?')[0]} — this usually "
            "means Schwab changed the flow, added an identity-verification step, "
            "or wants a human. A screenshot/HTML dump was written to the "
            "diagnostics folder.",
            screenshot=dump.get("screenshot"),
        )

    # ------------------------------------------------------------------
    def _rules(self) -> list[_PageRule]:
        return [
            _PageRule("login", URL_LOGIN, self._login, retry_after_s=25, description="login form"),
            _PageRule("mfa_picker", URL_MFA_PICKER, self._mfa_picker, retry_after_s=15),
            _PageRule("mfa", URL_MFA_WAITING, self._mfa_wait, retry_after_s=5),
            _PageRule("trust", URL_TRUST_DEVICE, self._trust_device, retry_after_s=15),
            _PageRule("consent", URL_CONSENT, self._consent, retry_after_s=25),
            _PageRule("accounts", URL_ACCOUNTS, self._accounts, retry_after_s=25),
            _PageRule("done", URL_CONFIRMATION, self._done, retry_after_s=20),
        ]

    # -- page handlers --------------------------------------------------
    def _login(self) -> None:
        if not self.username or not self.password:
            self.log.step(
                "login page: no saved credentials, waiting for you to sign in "
                "in the browser window"
            )
            return
        self.log.step("login page: submitting credentials")
        self.browser.wait_present(LOGIN_USERNAME, timeout=45)
        self.browser.wait_present(LOGIN_PASSWORD, timeout=15)
        self.browser.fill(LOGIN_USERNAME, self.username)
        self.browser.fill(LOGIN_PASSWORD, self.password)
        self.browser.click(LOGIN_SUBMIT)

        # A failed login bounces back to the same URL with an inline error.
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if URL_LOGIN not in self.browser.url:
                return
            error_text = self.browser.text_of(".alert-danger") or self.browser.text_of("#error")
            if error_text:
                raise LoginError(
                    f"Schwab rejected the saved credentials: {error_text.strip()[:300]}"
                )
            time.sleep(0.4)

    def _mfa_picker(self) -> None:
        self.log.step("MFA required: choosing the Schwab app push")
        self.browser.wait_present(SCHWAB_APP_OPTION, timeout=30)
        self.browser.click(SCHWAB_APP_OPTION)

    def _mfa_wait(self) -> None:
        # No interaction: the page advances once the push is approved.
        self.log.debug("still waiting for the mobile approval")

    def _trust_device(self) -> None:
        self.log.step("trusting this device (keeps future logins MFA-free)")
        self.browser.wait_present(TRUST_YES, timeout=30)
        self.browser.click(TRUST_YES)
        self.browser.click(TRUST_CONTINUE)

    def _consent(self) -> None:
        self.log.step("accepting the third-party consent terms")
        self.browser.wait_present(CONSENT_CHECKBOX, timeout=60)
        self.browser.wait_for_hydration()
        self.browser.click(CONSENT_CHECKBOX)
        self.browser.click(CONSENT_CONTINUE)
        self.browser.wait_present(CONSENT_MODAL_ACCEPT, timeout=30)
        self.browser.wait_for_hydration()
        self.browser.click(CONSENT_MODAL_ACCEPT)
        time.sleep(1.0)

    def _accounts(self) -> None:
        self.log.step("selecting accounts to share")
        self.browser.wait_for_hydration()
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and self.browser.count(ACCOUNT_CHECKBOX) == 0:
            time.sleep(0.3)
        count = self.browser.check_all(ACCOUNT_CHECKBOX)
        self.log.debug(f"checked {count} account checkbox(es)")
        self.browser.click(ACCOUNT_CONTINUE)

    def _done(self) -> None:
        self.log.step("confirming the account link")
        self.browser.wait_for_hydration()
        self.browser.wait_present(DONE, timeout=30)
        self.browser.click(DONE)
