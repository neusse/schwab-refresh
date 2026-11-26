"""Flow tests with a scripted browser — no Selenium, no network."""

from __future__ import annotations

import pytest

from schwab_refresh.callback import CallbackResult
from schwab_refresh.flow import (
    ACCOUNT_CHECKBOX,
    LOGIN_SUBMIT,
    LoginError,
    LoginFlow,
    is_off_schwab,
    parse_callback,
)

PAGES = {
    "login": "https://client.schwab.com/app/access/login-one-step",
    "mfa_picker": "https://client.schwab.com/app/access/authenticators",
    "mfa_wait": "https://client.schwab.com/app/access/mobile_approve",
    "trust": "https://client.schwab.com/app/access/devicetag/remember",
    "consent": "https://client.schwab.com/app/third-party-auth/cag",
    "accounts": "https://client.schwab.com/app/third-party-auth/account",
    "confirmation": "https://client.schwab.com/app/third-party-auth/confirmation",
    "callback": "https://127.0.0.1:8182/?code=THECODE&state=THESTATE",
}


class FakeBrowser:
    """Minimal Browser stand-in: pages advance on clicks / on reads."""

    def __init__(self, *, allow_mfa=True, blocked=False):
        self.page = "login"
        self.allow_mfa = allow_mfa
        self.blocked = blocked
        self.filled: dict[str, str] = {}
        self.clicks: list[str] = []
        self.checks: list[str] = []
        self._reads = 0

    @property
    def url(self) -> str:
        return PAGES[self.page]

    @property
    def title(self):
        return "Access Denied" if self.blocked else "Schwab"

    def body_text(self, limit=600):
        if self.blocked:
            return "Access Denied — you don't have permission to access this server."
        if self.page == "mfa_wait":
            self._reads += 1
            if self._reads >= 2:
                self.page = "trust"
        return ""

    def present(self, selector):
        return True

    def count(self, selector):
        return 2 if selector == ACCOUNT_CHECKBOX else 1

    def wait_present(self, selector, timeout=30):
        return None

    def wait_for_hydration(self, timeout=8):
        return None

    def fill(self, selector, value):
        self.filled[selector] = value

    def click(self, selector):
        self.clicks.append(selector)
        if selector == LOGIN_SUBMIT:
            self.page = "mfa_picker" if self.allow_mfa else "consent"
        elif self.page == "mfa_picker":
            self.page = "mfa_wait"
        elif self.page == "trust":
            self.page = "consent"
        elif self.page == "consent" and selector.startswith("button#agree-modal-btn"):
            self.page = "accounts"
        elif self.page == "accounts":
            self.page = "confirmation"
        elif self.page == "confirmation":
            self.page = "callback"

    def check_all(self, selector):
        self.checks.append(selector)
        return 2

    def debug_dump(self, tag):
        return {"screenshot": None, "html": None}


class FakeCallback:
    def __init__(self, result: CallbackResult | None = None):
        self._result = result

    def poll(self):
        result, self._result = self._result, None
        return result


def _log():
    class _L:
        def info(self, m):
            pass

        def step(self, m):
            pass

        def debug(self, m):
            pass

        def warn(self, m):
            pass

        def error(self, m):
            pass

    return _L()


def test_happy_path_with_mfa():
    browser = FakeBrowser(allow_mfa=True)
    flow = LoginFlow(browser, _log(), username="u", password="p", overall_timeout_s=10)
    result = flow.run(FakeCallback())
    assert result.code == "THECODE"
    assert browser.filled["input#loginIdInput"] == "u"
    assert browser.checks == [ACCOUNT_CHECKBOX]
    assert "input#remember-device-yes" in browser.clicks


def test_trusted_device_skips_mfa():
    browser = FakeBrowser(allow_mfa=False)
    flow = LoginFlow(browser, _log(), username="u", password="p", overall_timeout_s=10)
    result = flow.run(FakeCallback())
    assert result.code == "THECODE"
    assert not any("mobile_approve" in c for c in browser.clicks)


def test_server_capture_wins():
    server_result = CallbackResult(code="SERVERCODE", state="s")
    browser = FakeBrowser()
    flow = LoginFlow(browser, _log(), username="u", password="p", overall_timeout_s=10)
    assert flow.run(FakeCallback(server_result)).code == "SERVERCODE"


def test_blocked_page_raises_with_hint():
    browser = FakeBrowser(blocked=True)
    flow = LoginFlow(browser, _log(), username="u", password="p", overall_timeout_s=3)
    with pytest.raises(LoginError) as exc:
        flow.run(FakeCallback())
    assert "bot protection" in str(exc.value)


def test_unknown_page_times_out_helpfully():
    class Stuck(FakeBrowser):
        @property
        def url(self):
            return "https://client.schwab.com/app/some/new/thing"

    flow = LoginFlow(Stuck(), _log(), username="u", password="p", overall_timeout_s=4)
    with pytest.raises(LoginError) as exc:
        flow.run(FakeCallback())
    assert "unexpected page" in str(exc.value)


def test_off_schwab_helpers():
    assert is_off_schwab("https://127.0.0.1:8182/?code=x")
    assert not is_off_schwab("https://client.schwab.com/app/access/login-one-step")
    parsed = parse_callback("https://127.0.0.1:8182/?code=abc&state=xyz")
    assert parsed.code == "abc"
    assert parsed.state == "xyz"
    assert parsed.should_stop
