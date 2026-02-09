"""
GrapeQL Clairvoyance Integration
Author: Aleksa Zatezalo
Version: 1.0
Date: February 2025
Description: Wraps the Clairvoyance library to perform blind schema enumeration
             when introspection is disabled. Acts as an automatic fallback in the
             scan pipeline.

Dependency: pip install clairvoyance
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from .utils import GrapePrinter, Finding

# ------------------------------------------------------------------ #
#  Lazy import — clairvoyance is an optional dependency
# ------------------------------------------------------------------ #

_CLAIRVOYANCE_AVAILABLE = False
try:
    from clairvoyance.cli import blind_introspection, load_default_wordlist

    _CLAIRVOYANCE_AVAILABLE = True
except ImportError:
    pass


# ------------------------------------------------------------------ #
#  ClairvoyanceProber
# ------------------------------------------------------------------ #


class ClairvoyanceProber:
    """
    Blind GraphQL schema enumeration via Clairvoyance.

    This module is invoked automatically when live introspection fails
    and no ``--schema-file`` was supplied.  It probes the endpoint by
    fuzzing field and type names from a wordlist, reconstructing as much
    of the schema as the server's error messages reveal.

    Usage::

        prober = ClairvoyanceProber()
        schema_dict = await prober.probe(
            url="https://target.com/graphql",
            headers={"Authorization": "Bearer tok"},
            proxy="http://127.0.0.1:8080",
            wordlist_path="/path/to/wordlist.txt",
        )
        if schema_dict:
            client.load_schema_from_dict(schema_dict)
    """

    def __init__(self):
        self.printer = GrapePrinter()

    # ------------------------------------------------------------------ #
    #  Availability check
    # ------------------------------------------------------------------ #

    @staticmethod
    def is_available() -> bool:
        """Return True if the ``clairvoyance`` package is installed."""
        return _CLAIRVOYANCE_AVAILABLE

    # ------------------------------------------------------------------ #
    #  Wordlist loading
    # ------------------------------------------------------------------ #

    @staticmethod
    def load_wordlist(path: Optional[str] = None) -> List[str]:
        """
        Load a wordlist for blind enumeration.

        Args:
            path: Path to a newline-delimited wordlist file.
                  If *None*, the default wordlist bundled with Clairvoyance
                  is used.

        Returns:
            De-duplicated list of candidate field/type names.
        """
        if path:
            with open(path, "r", encoding="utf-8") as fh:
                words = [line.strip() for line in fh if line.strip()]
        else:
            words = load_default_wordlist()

        return list(set(words))

    # ------------------------------------------------------------------ #
    #  Core probe
    # ------------------------------------------------------------------ #

    async def probe(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        wordlist_path: Optional[str] = None,
        output_path: Optional[str] = None,
        concurrent_requests: int = 10,
    ) -> Optional[Dict]:
        """
        Run Clairvoyance blind introspection and return the recovered schema.

        Args:
            url:                 Target GraphQL endpoint.
            headers:             HTTP headers (auth, cookies, etc.).
            proxy:               Optional HTTP proxy URL.
            wordlist_path:       Path to a custom wordlist.  Falls back to the
                                 Clairvoyance default wordlist.
            output_path:         If set, the raw JSON schema is also written
                                 to this file.
            concurrent_requests: Max parallel requests to the target.

        Returns:
            The ``__schema``-equivalent dict ready for
            ``GraphQLClient.load_schema_from_dict()``, or *None* on failure.
        """
        if not self.is_available():
            self.printer.print_msg(
                "clairvoyance package not installed — "
                "run: pip install clairvoyance",
                status="error",
            )
            return None

        self.printer.print_msg(
            "Introspection disabled — starting Clairvoyance blind enumeration...",
            status="log",
        )

        wordlist = self.load_wordlist(wordlist_path)
        self.printer.print_msg(
            f"Loaded {len(wordlist)} wordlist entries", status="log"
        )

        logger = logging.getLogger("grapeql.clairvoyance")

        try:
            schema_json_str = await blind_introspection(
                url=url,
                logger=logger,
                wordlist=wordlist,
                headers=headers,
                proxy=proxy,
                output_path=output_path,
                concurrent_requests=concurrent_requests,
            )
        except Exception as exc:
            self.printer.print_msg(
                f"Clairvoyance probe failed: {exc}", status="error"
            )
            return None

        if not schema_json_str:
            self.printer.print_msg(
                "Clairvoyance returned an empty schema", status="warning"
            )
            return None

        # ── Parse and normalise ──────────────────────────────────────
        try:
            schema_data = json.loads(schema_json_str)
        except json.JSONDecodeError as exc:
            self.printer.print_msg(
                f"Failed to parse Clairvoyance output: {exc}", status="error"
            )
            return None

        # Clairvoyance returns {"data": {"__schema": {...}}}
        if "data" in schema_data:
            schema_data = schema_data["data"]
        if "__schema" in schema_data:
            schema_data = schema_data["__schema"]

        type_count = len(schema_data.get("types", []))
        self.printer.print_msg(
            f"Clairvoyance recovered {type_count} types from blind enumeration",
            status="success",
        )

        return schema_data

    # ------------------------------------------------------------------ #
    #  Finding helper
    # ------------------------------------------------------------------ #

    def make_finding(self, endpoint: str, type_count: int) -> Finding:
        """Create an informational finding about the blind enumeration."""
        return Finding(
            title="Schema Recovered via Blind Enumeration (Clairvoyance)",
            severity="INFO",
            description=(
                f"Introspection is disabled, but Clairvoyance recovered "
                f"{type_count} types through error-message analysis. "
                f"Field suggestions in error responses should be disabled "
                f"in production to prevent schema leakage."
            ),
            endpoint=endpoint,
            impact="Partial or full schema disclosure despite disabled introspection",
            remediation=(
                "Disable field suggestion hints in GraphQL error messages "
                "(e.g. set suggestions to false in your GraphQL server config)"
            ),
        )