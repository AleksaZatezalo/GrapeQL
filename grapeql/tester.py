"""
GrapeQL Base Vulnerability Tester
Author: Aleksa Zatezalo
Version: 3.0
Date: February 2025
Description: Base class for vulnerability testing modules. Provides shared
             logger, YAML test-case loader, and baseline tracker integration.
"""

from typing import Dict, List, Optional, Any, Tuple
from .client import GraphQLClient
from .utils import GrapePrinter, Finding
from .logger import GrapeLogger
from .loader import TestCaseLoader
from .baseline import BaselineTracker


class VulnerabilityTester:
    """
    Base class for all vulnerability testing modules.

    Subclasses inherit:
      - self.client      : GraphQLClient (with optional logger)
      - self.logger      : GrapeLogger instance (may be None)
      - self.loader      : TestCaseLoader for YAML test cases (may be None)
      - self.baseline    : BaselineTracker for response-time stats (may be None)
      - self.test_cases  : List of dicts loaded from YAML for this module
    """

    # Subclasses should set this to their test_cases subdirectory name
    MODULE_NAME: str = "base"

    def __init__(
        self,
        logger: Optional[GrapeLogger] = None,
        loader: Optional[TestCaseLoader] = None,
        baseline: Optional[BaselineTracker] = None,
    ):
        self.client = GraphQLClient(logger=logger)
        self.printer = GrapePrinter()
        self.logger = logger
        self.loader = loader
        self.baseline = baseline
        self.findings: List[Finding] = []
        self.test_name = "Base Vulnerability Test"
        self.test_cases: List[Dict[str, Any]] = []

        # Auto-load test cases if a loader is provided
        if self.loader and self.MODULE_NAME != "base":
            self.test_cases = self.loader.load_module(self.MODULE_NAME)

    async def setup_endpoint(
        self,
        endpoint: str,
        proxy: Optional[str] = None,
        pre_configured_client: Optional[GraphQLClient] = None,
    ) -> bool:
        """
        Set up the testing environment with the target endpoint.

        If a ``pre_configured_client`` is supplied (already has schema, auth,
        cookies, etc.), its state is copied so that introspection is not
        repeated for every module.
        """
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

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)
        severity = finding.severity.upper()

        if severity in ["HIGH", "CRITICAL"]:
            status = "failed"
        elif severity == "MEDIUM":
            status = "warning"
        else:
            status = "log"

        self.printer.print_msg(f"{severity}: {finding.title}", status=status)

    def set_credentials(self, username: str, password: str) -> None:
        """Set credentials for testing authentication-related issues."""
        self.username = username
        self.password = password
        self.printer.print_msg(
            f"Set credentials: {username}:{password}", status="success"
        )

    def get_findings(self) -> List[Finding]:
        """Get all findings from the test."""
        return self.findings

    def _record_response_time(self, duration: float) -> None:
        """Convenience: record a response time in the baseline tracker."""
        if self.baseline:
            self.baseline.record(self.__class__.__name__, duration)

    async def run_test(self) -> List[Finding]:
        """
        Run all tests and return findings.
        Subclasses MUST override this.
        """
        self.printer.print_msg(
            "Base test class - no actual tests to run", status="warning"
        )
        return self.findings
