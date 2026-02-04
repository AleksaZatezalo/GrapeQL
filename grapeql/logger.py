"""
GrapeQL Structured Logger
Author: Aleksa Zatezalo
Version: 3.0
Date: February 2025
Description: Structured logging for all GrapeQL modules. Logs test metadata,
             payloads, HTTP verbs, responses, and timeout errors to file or stdout.
"""

import logging
import json
import sys
import time
from typing import Optional, Dict, Any


class GrapeLogger:
    """
    Centralized structured logger for GrapeQL.

    Produces consistent log records containing:
      - module   : which tester produced the record (e.g. "InjectionTester")
      - test     : the specific test or check name
      - parameter: the field/arg under test
      - payload  : the raw payload sent
      - verb     : HTTP method used (GET / POST)
      - status   : outcome (sent / success / failure / timeout / error)
      - response : truncated server response
      - duration : wall-clock seconds
    """

    _FMT = (
        "%(asctime)s | %(levelname)-7s | %(module_name)-20s | %(test_name)-30s | "
        "%(parameter)-20s | %(verb)-4s | %(status)-8s | %(duration)6.3fs | %(message)s"
    )

    def __init__(
        self,
        log_file: Optional[str] = None,
        level: int = logging.DEBUG,
        name: str = "grapeql",
    ):
        """
        Args:
            log_file: Path to log file. If None, logs to stdout.
            level:    Logging level (default DEBUG).
            name:     Logger name.
        """
        self._logger = logging.getLogger(name)
        self._logger.setLevel(level)
        self._logger.handlers.clear()

        handler: logging.Handler
        if log_file:
            handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        else:
            handler = logging.StreamHandler(sys.stdout)

        handler.setFormatter(logging.Formatter(self._FMT))
        self._logger.addHandler(handler)

    # ------------------------------------------------------------------ #
    #  Public helpers
    # ------------------------------------------------------------------ #

    def log_request(
        self,
        *,
        module: str,
        test: str,
        parameter: str = "-",
        payload: str = "-",
        verb: str = "POST",
        status: str = "sent",
        response: Any = None,
        duration: float = 0.0,
        level: int = logging.INFO,
    ) -> None:
        """
        Emit one structured log record.

        Args:
            module:    Module name (e.g. "InjectionTester").
            test:      Test name (e.g. "sqli_basic").
            parameter: Field.arg being tested.
            payload:   Raw payload string.
            verb:      HTTP method.
            status:    Outcome tag.
            response:  Server response (will be truncated).
            duration:  Elapsed seconds.
            level:     Python logging level.
        """
        response_summary = self._truncate_response(response)
        extra = {
            "module_name": module,
            "test_name": test,
            "parameter": parameter,
            "verb": verb,
            "status": status,
            "duration": duration,
        }
        message = f"payload=[{payload}] response=[{response_summary}]"
        self._logger.log(level, message, extra=extra)

    def log_timeout(
        self,
        *,
        module: str,
        test: str,
        parameter: str = "-",
        payload: str = "-",
        verb: str = "POST",
        duration: float = 0.0,
    ) -> None:
        """Log a timeout event at WARNING level."""
        self.log_request(
            module=module,
            test=test,
            parameter=parameter,
            payload=payload,
            verb=verb,
            status="timeout",
            duration=duration,
            level=logging.WARNING,
        )

    def log_error(
        self,
        *,
        module: str,
        test: str,
        message: str,
        parameter: str = "-",
    ) -> None:
        """Log a generic error at ERROR level."""
        extra = {
            "module_name": module,
            "test_name": test,
            "parameter": parameter,
            "verb": "-",
            "status": "error",
            "duration": 0.0,
        }
        self._logger.error(message, extra=extra)

    # ------------------------------------------------------------------ #
    #  Internals
    # ------------------------------------------------------------------ #

    @staticmethod
    def _truncate_response(response: Any, max_len: int = 200) -> str:
        if response is None:
            return "-"
        if isinstance(response, dict):
            text = json.dumps(response, default=str)
        else:
            text = str(response)
        if len(text) > max_len:
            return text[:max_len] + "…"
        return text