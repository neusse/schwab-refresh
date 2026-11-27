"""Browser layer: SeleniumBase UC mode, tuned for Schwab's bot defenses.

Everything here is deliberately copied from the techniques that are proven
against Schwab (schwab_cli + webauto-cli):

* ``uc=True`` — patched UC chromedriver. Plain Selenium and stock
  chromedriver get Akamai'd; this is the piece that does not.
* ``uc_open_with_reconnect(url, 4)`` in headless mode — opens the URL, closes
  the blank tab, detaches the debugger, and reconnects. Akamai flags a session
  that is actively being driven; the reconnect window is what slips past.
* persistent ``user_data_dir`` — keeps the "remember this device" cookie, so
  Schwab stops sending the app-push MFA challenge. This is the difference
  between "runs unattended" and "needs a human every 7 days".
* JS event dispatch for form fields — Schwab's Angular reactive forms ignore
  ``send_keys`` values (the model never binds). focus → value → input/change/
  blur is what a human keystroke looks like to Angular.
"""

from __future__ import annotations

import os
import shutil
import socket
import time
from pathlib import Path
from typing import Any

from schwab_refresh.config import Settings

_RECONNECT_SECONDS = 4


class BrowserError(Exception):
    """Browser could not be launched or navigated."""


def chrome_path() -> str | None:
    """Locate the Chrome binary without relying on SeleniumBase's scan.

    SeleniumBase's own discovery does ``os.sep.join((os.environ.get(var), ...))``
    for PROGRAMFILES / PROGRAMFILES(X86) / LOCALAPPDATA / PROGRAMW6432, so a
    stripped environment (Task Scheduler, some shells) raises TypeError instead
    of falling through. Resolving here keeps both ``doctor`` and ``Browser``
    independent of which env vars happen to be present.
    """
    override = os.environ.get("SCHWAB_REFRESH_CHROME_BIN")
    if override and Path(override).exists():
        return override

    rel = Path("Google/Chrome/Application/chrome.exe")
    candidates = [
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
    ]
    for var in ("PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432", "LOCALAPPDATA"):
        base = os.environ.get(var)
        if base:
            candidates.append(Path(base) / rel)
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    found = shutil.which("chrome") or shutil.which("google-chrome")
    if found:
        return found

    # Last resort: the App Paths key, which also covers non-default installs.
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "")
        if value and Path(value).exists():
            return str(Path(value))
    except (OSError, ImportError):
        pass
    return None


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Browser:
    def __init__(self, cfg: Settings, *, log=print, debug: bool = False):
        self._cfg = cfg
        self._log = log
        self._debug = debug
        self._driver: Any = None
        self._headless = cfg.headless
        self._prev_cwd: Path | None = None

    # -- lifecycle -----------------------------------------------------
    def start(self) -> "Browser":
        import importlib.util

        if importlib.util.find_spec("seleniumbase") is None:  # pragma: no cover
            raise BrowserError("seleniumbase is not installed; run `uv sync`.")

        profile = Path(self._cfg.profile_dir)
        profile.mkdir(parents=True, exist_ok=True)
        # The UC driver creates `downloaded_files/` relative to the process
        # CWD. Run from a contained folder so the project root stays clean.
        try:
            work = Path(self._cfg.state_dir) / "browser-cwd"
            work.mkdir(parents=True, exist_ok=True)
            self._prev_cwd = Path.cwd()
            os.chdir(work)
        except OSError:
            self._prev_cwd = None

        # Import AFTER the chdir: seleniumbase computes its downloads folder
        # as an absolute path at import time, so importing first would put
        # `downloaded_files/` in whatever directory the task started in.
        from seleniumbase import Driver

        debug_port = _free_port()
        args = [f"--remote-debugging-port={debug_port}"]
        if self._cfg.ignore_cert_errors:
            # Lets the browser load our self-signed loopback callback so the
            # URL (with ?code=) survives instead of becoming chrome-error://.
            args += ["--ignore-certificate-errors", "--allow-insecure-localhost"]

        self._log(
            f"launching Chrome UC (headless={self._headless}, "
            f"profile={profile}, debug_port={debug_port})"
        )
        binary = chrome_path()
        if binary is None:
            raise BrowserError(
                "Chrome not found; install Chrome or set SCHWAB_REFRESH_CHROME_BIN."
            )
        try:
            self._driver = Driver(
                uc=True,
                headless=self._headless,
                user_data_dir=str(profile),
                binary_location=binary,
                chromium_arg=",".join(args),
                log_cdp_events=False,
            )
        except Exception as exc:  # SeleniumBase raises a grab-bag
            raise BrowserError(f"failed to launch Chrome UC driver: {exc}") from exc
        self._switch_to_main_window()
        return self

    def close(self) -> None:
        driver, self._driver = self._driver, None
        if driver is None:
            return
        # Park on about:blank before quitting: the persistent profile restores
        # the last tab on next launch, and an OAuth callback URL sitting there
        # would replay a stale ?code= on startup.
        try:
            nav = getattr(driver, "default_get", None) or driver.get
            nav("about:blank")
        except Exception:
            pass
        try:
            driver.quit()
        except Exception:
            pass
        if self._prev_cwd is not None:
            try:
                os.chdir(self._prev_cwd)
            except OSError:
                pass
            self._prev_cwd = None

    def __enter__(self) -> "Browser":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()

    # -- navigation ----------------------------------------------------
    @property
    def url(self) -> str:
        if self._driver is None:
            return ""
        try:
            return self._driver.current_url or ""
        except Exception:
            return ""

    @property
    def title(self) -> str:
        try:
            return self._driver.title or ""
        except Exception:
            return ""

    def goto(self, url: str) -> None:
        if self._driver is None:
            raise BrowserError("browser not started")
        self._log("navigating to Schwab authorize URL")
        try:
            if self._headless:
                self._driver.uc_open_with_reconnect(url, reconnect_time=_RECONNECT_SECONDS)
            else:
                # Visible mode: SB UC patches .get into a detach dance that
                # hangs when the only window is visible. default_get is the
                # original Selenium get.
                self._driver.default_get(url)
        except Exception as exc:
            raise BrowserError(f"navigation failed: {exc}") from exc
        self._switch_to_main_window(target_url=url)

    def _switch_to_main_window(self, target_url: str | None = None) -> None:
        """Prefer the window that actually navigated to ``target_url``.

        SB UC under --remote-debugging-port exposes Chrome UI overlays
        (omnibox popup, devtools) as window handles. Driving one of those
        renders the page but leaves the real tab blank.
        """
        if self._driver is None:
            return
        try:
            handles = list(self._driver.window_handles)
        except Exception:
            return
        scored: list[tuple[int, str]] = []
        for handle in handles:
            try:
                self._driver.switch_to.window(handle)
                url = self._driver.current_url or ""
            except Exception:
                continue
            score = 0
            if url.startswith("http"):
                score += 1
            if target_url and url.split("?")[0] == target_url.split("?")[0]:
                score += 3
            scored.append((score, handle))
        if scored:
            scored.sort(reverse=True)
            try:
                self._driver.switch_to.window(scored[0][1])
            except Exception:
                pass

    # -- element helpers ----------------------------------------------
    def _find(self, selector: str) -> list:
        if self._driver is None:
            return []
        try:
            return self._driver.find_elements("css selector", selector)
        except Exception:
            return []

    def count(self, selector: str) -> int:
        return len(self._find(selector))

    def present(self, selector: str) -> bool:
        return self.count(selector) > 0

    def wait_present(self, selector: str, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.present(selector):
                return
            time.sleep(0.2)
        raise TimeoutError(
            f"{selector!r} not present after {timeout:.0f}s (url: {self.url!r})"
        )

    def fill(self, selector: str, value: str) -> None:
        elements = self._find(selector)
        if not elements:
            raise BrowserError(f"fill: {selector!r} not present")
        self._driver.execute_script(
            """
            const el = arguments[0], val = arguments[1];
            el.focus();
            el.value = val;
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
            el.dispatchEvent(new Event('blur', { bubbles: true }));
            """,
            elements[0],
            value,
        )

    def click(self, selector: str) -> None:
        elements = self._find(selector)
        if not elements:
            raise BrowserError(f"click: {selector!r} not present")
        el = elements[0]
        try:
            self._driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        except Exception:
            pass
        try:
            el.click()
            return
        except Exception:
            pass
        try:
            self._driver.execute_script("arguments[0].click();", el)
            return
        except Exception:
            pass
        self._driver.execute_script(
            """
            const el = arguments[0];
            const r = el.getBoundingClientRect();
            const opts = {bubbles: true, cancelable: true, view: window, composed: true,
                          clientX: r.left + r.width / 2, clientY: r.top + r.height / 2, button: 0};
            el.dispatchEvent(new MouseEvent('mousedown', opts));
            el.dispatchEvent(new MouseEvent('mouseup', opts));
            el.dispatchEvent(new MouseEvent('click', opts));
            """,
            el,
        )

    def check_all(self, selector: str) -> int:
        elements = self._find(selector)
        for el in elements:
            self._driver.execute_script(
                """
                const el = arguments[0];
                if (!el.checked) {
                    el.checked = true;
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                    el.dispatchEvent(new Event('blur', { bubbles: true }));
                }
                """,
                el,
            )
        return len(elements)

    def text_of(self, selector: str) -> str:
        elements = self._find(selector)
        if not elements:
            return ""
        try:
            return (elements[0].text or "").strip()
        except Exception:
            return ""

    def body_text(self, limit: int = 2000) -> str:
        try:
            return (self._driver.find_element("tag name", "body").text or "")[:limit]
        except Exception:
            return ""

    def wait_for_hydration(self, timeout: float = 8.0) -> None:
        """Schwab ships Angular shells whose buttons exist before handlers bind.

        The placeholder ``<title>cag</title>`` is the reliable "not yet" signal
        on the consent page.
        """
        deadline = time.monotonic() + timeout
        start = time.monotonic()
        while time.monotonic() < deadline:
            title = self.title
            if title and title != "cag":
                break
            time.sleep(0.2)
        time.sleep(max(0.0, 0.5 - (time.monotonic() - start)))

    def screenshot(self, path: str | Path, *, full: bool = False) -> str | None:
        if self._driver is None:
            return None
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._driver.save_screenshot(str(p))
            return str(p)
        except Exception:
            return None

    def dump_html(self, path: str | Path) -> str | None:
        if self._driver is None:
            return None
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            p.write_text(self._driver.page_source or "", encoding="utf-8", errors="replace")
            return str(p)
        except Exception:
            return None

    def debug_dump(self, tag: str) -> dict[str, str | None]:
        """Timestamped screenshot + HTML, used on any unexpected page."""
        if not self._debug:
            return {}
        stamp = time.strftime("%Y%m%d-%H%M%S")
        base = Path(self._cfg.state_dir) / "diagnostics" / f"{stamp}-{tag}"
        return {
            "screenshot": self.screenshot(base.with_suffix(".png")),
            "html": self.dump_html(base.with_suffix(".html")),
        }
