"""
GrapeQL Information Disclosure Tester
Author: Aleksa Zatezalo
Version: 3.0
Date: February 2025
Description: Tests GraphQL endpoints for information disclosure vulnerabilities.
             Check definitions are loaded from YAML test cases.
"""

import time
import json
from typing import Dict, List, Optional, Tuple, Any
from .tester import VulnerabilityTester
from .utils import Finding
from .logger import GrapeLogger
from .loader import TestCaseLoader
from .baseline import BaselineTracker


class InfoTester(VulnerabilityTester):
    """
    Tests GraphQL endpoints for information disclosure issues.
    Check definitions come from ``test_cases/info/*.yaml``.
    """

    MODULE_NAME = "info"

    def __init__(
        self,
        logger: Optional[GrapeLogger] = None,
        loader: Optional[TestCaseLoader] = None,
        baseline: Optional[BaselineTracker] = None,
    ):
        super().__init__(logger=logger, loader=loader, baseline=baseline)
        self.test_name = "GraphQL Information Disclosure Testing"

    # ------------------------------------------------------------------ #
    #  Generic check runner driven by YAML definitions
    # ------------------------------------------------------------------ #

    async def _run_check(self, check: Dict[str, Any]) -> Optional[Finding]:
        """
        Execute a single YAML-defined check and return a Finding if it triggers.
        """
        name = check.get("name", "unknown")
        method = check.get("method", "POST").upper()
        detection = check.get("detection", {})
        self.client.set_log_context("InfoTester", name)

        start = time.time()

        # ── Special: just check if schema already exists ─────────
        if method == "CHECK_SCHEMA":
            duration = time.time() - start
            self._record_response_time(duration)
            if detection.get("type") == "schema_exists" and self.client.schema:
                return self._finding_from_check(check)
            return None

        # ── Prepare and send the request ─────────────────────────
        send_as = check.get("send_as", "json")
        query = check.get("query", "")
        response = None

        if send_as == "url_param":
            # GET with ?query=...
            response, _ = await self.client.make_request(
                "GET",
                url=f"{self.client.endpoint}?query={query}",
                _log_parameter=name,
                _log_payload=query,
            )

        elif send_as == "form_data":
            original_ct = self.client.headers.get("Content-Type")
            self.client.headers["Content-Type"] = check.get(
                "content_type", "application/x-www-form-urlencoded"
            )
            try:
                response, _ = await self.client.make_request(
                    "POST",
                    data={"query": query},
                    _log_parameter=name,
                    _log_payload=query,
                )
            finally:
                if original_ct:
                    self.client.headers["Content-Type"] = original_ct
                else:
                    self.client.headers.pop("Content-Type", None)

        elif send_as == "batch":
            batch = [{"query": q} for q in check.get("batch_queries", [])]
            response, _ = await self.client.make_request(
                "POST",
                json=batch,
                _log_parameter=name,
                _log_payload="batch",
            )

        elif method == "GET":
            # Plain GET to endpoint (for graphiql detection)
            response, _ = await self.client.make_request(
                "GET",
                _log_parameter=name,
                _log_payload="-",
            )

        else:
            # Standard POST with query body
            response, _ = await self.client.graphql_query(
                query,
                _log_parameter=name,
                _log_payload=query,
            )

        duration = time.time() - start
        self._record_response_time(duration)

        if response is None:
            return None

        # ── Evaluate detection rules ─────────────────────────────
        det_type = detection.get("type", "")

        if det_type == "error_contains":
            value = detection["value"]
            ci = detection.get("case_insensitive", False)
            errors = response.get("errors", [])
            matched = any(
                (value.lower() if ci else value)
                in (err.get("message", "").lower() if ci else err.get("message", ""))
                for err in errors
            )
            if matched:
                return self._finding_from_check(check)

        elif det_type == "data_field_exists":
            field = detection["field"]
            if response.get("data", {}).get(field):
                return self._finding_from_check(check)

        elif det_type == "response_contains_any":
            text = str(response.get("text", ""))
            ci = detection.get("case_insensitive", False)
            if ci:
                text = text.lower()
            for val in detection.get("values", []):
                if (val.lower() if ci else val) in text:
                    return self._finding_from_check(check)

        elif det_type == "batch_response":
            expected = detection.get("expected_count", 2)
            if isinstance(response, list) and len(response) == expected:
                return self._finding_from_check(check)

        return None

    # ------------------------------------------------------------------ #
    #  Helper to build a Finding from a YAML check definition
    # ------------------------------------------------------------------ #

    @staticmethod
    def _finding_from_check(check: Dict[str, Any]) -> Finding:
        return Finding(
            title=check["title"],
            severity=check.get("severity", "LOW"),
            description=check.get("description", ""),
            endpoint="",  # will be patched in run_test
            impact=check.get("impact", ""),
            remediation=check.get("remediation", ""),
        )

    # ------------------------------------------------------------------ #
    #  Hardcoded fallbacks (used if no YAML loaded)
    # ------------------------------------------------------------------ #

    async def _run_hardcoded_checks(self) -> None:
        """Run the original hardcoded checks when no YAML is available."""
        # Field suggestions
        response, _ = await self.client.graphql_query(
            "query { __schema { directive } }"
        )
        if response and any(
            "did you mean" in str(e.get("message", "")).lower()
            for e in response.get("errors", [])
        ):
            self.add_finding(
                Finding(
                    title="Field Suggestions Enabled",
                    severity="LOW",
                    description="Field suggestions in error messages leak schema info",
                    endpoint=self.client.endpoint,
                    impact="Information Leakage",
                    remediation="Disable field suggestions in production",
                )
            )

        # Introspection
        if self.client.schema:
            self.add_finding(
                Finding(
                    title="Introspection Enabled",
                    severity="MEDIUM",
                    description="Introspection exposes the full schema",
                    endpoint=self.client.endpoint,
                    impact="Schema mapping by attackers",
                    remediation="Disable introspection in production",
                )
            )

    # ------------------------------------------------------------------ #
    #  Main entry point
    # ------------------------------------------------------------------ #

    async def run_test(self) -> List[Finding]:
        if not self.client.endpoint:
            self.printer.print_msg(
                "No endpoint set. Run setup_endpoint first.", status="error"
            )
            return self.findings

        self.printer.print_section("Starting Information Disclosure Testing")

        if not self.test_cases:
            self.printer.print_msg(
                "No YAML checks loaded — running hardcoded checks", status="warning"
            )
            await self._run_hardcoded_checks()
            return self.findings

        for check in self.test_cases:
            test_name = check.get("name", "unknown")
            self.printer.print_msg(f"Testing for {test_name}...", status="log")

            try:
                finding = await self._run_check(check)
                if finding:
                    finding.endpoint = self.client.endpoint
                    self.add_finding(finding)
                    status = "warning" if finding.severity != "HIGH" else "failed"
                    self.printer.print_msg(
                        f"Found issue: {finding.title}", status=status
                    )
                else:
                    self.printer.print_msg(f"{test_name} test passed", status="success")
            except Exception as e:
                self.printer.print_msg(
                    f"Error testing {test_name}: {str(e)}", status="error"
                )

        if not self.findings:
            self.printer.print_msg(
                "No information disclosure issues found", status="success"
            )

        return self.findings