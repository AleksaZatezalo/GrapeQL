"""
GrapeQL Fingerprinting Module
Author: Aleksa Zatezalo
Version: 3.0
Date: February 2025
Description: Fingerprinting module to identify GraphQL engine implementations.
             Engine probe definitions are loaded from YAML test cases.
"""

from typing import Dict, List, Optional, Tuple, Set, Any
from .client import GraphQLClient
from .utils import GrapePrinter, Finding
from .logger import GrapeLogger
from .loader import TestCaseLoader
from .baseline import BaselineTracker

import time


class Fingerprinter:
    """
    Identifies GraphQL server implementations through behavioral fingerprinting.
    Probe queries and expected signatures are loaded from YAML test cases.
    """

    MODULE_NAME = "fingerprint"

    def __init__(
        self,
        logger: Optional[GrapeLogger] = None,
        loader: Optional[TestCaseLoader] = None,
        baseline: Optional[BaselineTracker] = None,
    ):
        self.client = GraphQLClient(logger=logger)
        self.printer = GrapePrinter()
        self.logger = logger
        self.baseline = baseline
        self.findings: List[Finding] = []

        # Load engine definitions from YAML (falls back to empty list)
        self.engines: List[Dict[str, Any]] = []
        if loader:
            self.engines = loader.load_module(self.MODULE_NAME)

    # ------------------------------------------------------------------ #
    #  Setup
    # ------------------------------------------------------------------ #

    async def setup_endpoint(
        self,
        endpoint: str,
        proxy: Optional[str] = None,
        pre_configured_client: Optional[GraphQLClient] = None,
    ) -> bool:
        if pre_configured_client:
            self.client.endpoint = pre_configured_client.endpoint
            self.client.proxy_url = pre_configured_client.proxy_url
            self.client.headers = pre_configured_client.headers.copy()
            self.client.cookies = pre_configured_client.cookies.copy()
            self.client.auth_token = pre_configured_client.auth_token
            self.client.schema = pre_configured_client.schema
            self.client.query_fields = (
                pre_configured_client.query_fields.copy()
                if pre_configured_client.query_fields
                else {}
            )
            self.client.mutation_fields = (
                pre_configured_client.mutation_fields.copy()
                if pre_configured_client.mutation_fields
                else {}
            )
            if pre_configured_client.schema:
                return True

        return await self.client.setup_endpoint(endpoint, proxy)

    # ------------------------------------------------------------------ #
    #  Probe helpers
    # ------------------------------------------------------------------ #

    def _error_contains(
        self, response: Dict, error_text: str, part: str = "message"
    ) -> bool:
        errors = response.get("errors", [])
        return any(
            error_text.lower() in error.get(part, "").lower() for error in errors
        )

    async def _run_probe(self, probe: Dict) -> bool:
        """
        Execute a single probe definition and return True if it matched.

        Probe dict keys:
          - query             : GraphQL query string
          - expect_error      : single error substring to match
          - expect_error_any  : list — match if ANY appear
          - expect_error_part : {part, value} — check a non-message field
          - expect_data       : dict of data fields to match exactly
          - expect_has_data   : True if "data" key must be present
          - expect_no_data    : True if "data" key must be absent
        """
        query = probe.get("query", "")
        self.client.set_log_context("Fingerprinter", "probe")

        start = time.time()
        response, _ = await self.client.graphql_query(
            query,
            _log_parameter="engine_probe",
            _log_payload=query[:100],
        )
        duration = time.time() - start

        # Record baseline
        if self.baseline:
            self.baseline.record("Fingerprinter", duration)

        if not response:
            return False

        # ── expect_error ─────────────────────────────────────────
        if "expect_error" in probe:
            if not self._error_contains(response, probe["expect_error"]):
                return False

        # ── expect_error_any ─────────────────────────────────────
        if "expect_error_any" in probe:
            if not any(
                self._error_contains(response, err)
                for err in probe["expect_error_any"]
            ):
                return False

        # ── expect_error_part ────────────────────────────────────
        if "expect_error_part" in probe:
            eep = probe["expect_error_part"]
            if not self._error_contains(response, eep["value"], part=eep["part"]):
                return False

        # ── expect_data ──────────────────────────────────────────
        if "expect_data" in probe:
            data = response.get("data", {})
            for key, val in probe["expect_data"].items():
                if data.get(key) != val:
                    return False

        # ── expect_has_data / expect_no_data ─────────────────────
        if probe.get("expect_has_data") and "data" not in response:
            return False
        if probe.get("expect_no_data") and "data" in response:
            return False

        return True

    # ------------------------------------------------------------------ #
    #  Main fingerprint loop
    # ------------------------------------------------------------------ #

    async def fingerprint(self) -> Optional[Dict]:
        """
        Identify the GraphQL engine by running YAML-defined probes.
        """
        self.printer.print_section("Fingerprinting GraphQL Engine")

        if not self.client.endpoint:
            self.printer.print_msg("No endpoint set", status="error")
            return None

        if not self.engines:
            self.printer.print_msg(
                "No engine definitions loaded — check test_cases/fingerprint/",
                status="warning",
            )
            return None

        for engine_def in self.engines:
            engine_id = engine_def.get("engine_id", "unknown")
            engine_name = engine_def.get("name", engine_id)
            probes = engine_def.get("probes", [])

            if not probes:
                continue

            try:
                # An engine matches if ANY of its probes succeeds
                matched = False
                for probe in probes:
                    if await self._run_probe(probe):
                        matched = True
                        break

                if matched:
                    self.printer.print_msg(
                        f"Identified GraphQL engine: {engine_name}", status="success"
                    )

                    cves = engine_def.get("cve", [])
                    if cves:
                        cve_str = ", ".join(cves)
                        self.printer.print_msg(
                            f"Known CVEs for this engine: {cve_str}",
                            status="warning",
                        )
                        finding = Finding(
                            title=f"GraphQL Engine Identified: {engine_name}",
                            severity="LOW",
                            description=(
                                f"The GraphQL engine was identified as {engine_name}. "
                                f"This implementation has known vulnerabilities: {cve_str}"
                            ),
                            endpoint=self.client.endpoint,
                            impact="May be vulnerable to known exploits",
                            remediation="Update to the latest version of the GraphQL engine",
                        )
                    else:
                        finding = Finding(
                            title=f"GraphQL Engine Identified: {engine_name}",
                            severity="INFO",
                            description=f"The GraphQL engine was identified as {engine_name}.",
                            endpoint=self.client.endpoint,
                            impact="None - informational only",
                            remediation="None required",
                        )

                    self.findings.append(finding)

                    return {
                        "engine_id": engine_id,
                        "name": engine_name,
                        "url": engine_def.get("url", ""),
                        "technologies": engine_def.get("tech", []),
                        "cves": cves,
                    }

            except Exception as e:
                self.printer.print_msg(
                    f"Error testing for {engine_id}: {str(e)}", status="error"
                )

        self.printer.print_msg("Could not identify GraphQL engine", status="warning")
        return None

    def get_findings(self) -> List[Finding]:
        return self.findings
