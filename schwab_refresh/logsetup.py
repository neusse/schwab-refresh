"""Console + rotating file logging.

Everything goes to stderr (so stdout stays pipeable with ``--print-token``) and
to ``<state>/logs/refresh-<timestamp>.log``. The last 30 logs are kept.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path


class Logger:
    def __init__(self, state_dir: Path, *, verbose: bool = False, quiet: bool = False):
        self._verbose = verbose
        self._quiet = quiet
        log_dir = Path(state_dir) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.path = log_dir / f"refresh-{stamp}.log"
        self._fh = self.path.open("a", encoding="utf-8")
        self._prune(log_dir)

    def _prune(self, log_dir: Path, keep: int = 30) -> None:
        try:
            logs = sorted(log_dir.glob("refresh-*.log"))
        except OSError:
            return
        for old in logs[:-keep]:
            try:
                old.unlink()
            except OSError:
                pass

    def _emit(self, level: str, message: str, to_console: bool) -> None:
        stamp = time.strftime("%H:%M:%S")
        line = f"{stamp} {level:<5} {message}"
        try:
            self._fh.write(line + "\n")
            self._fh.flush()
        except OSError:
            pass
        if to_console and not self._quiet:
            print(line, file=sys.stderr, flush=True)

    def info(self, message: str) -> None:
        self._emit("INFO", message, True)

    def step(self, message: str) -> None:
        self._emit("STEP", message, True)

    def debug(self, message: str) -> None:
        self._emit("DEBUG", message, self._verbose)

    def warn(self, message: str) -> None:
        self._emit("WARN", message, True)

    def error(self, message: str) -> None:
        self._emit("ERROR", message, True)

    def close(self) -> None:
        try:
            self._fh.close()
        except OSError:
            pass
