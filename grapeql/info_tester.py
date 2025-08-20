"""
GrapeQL Information Disclosure Tester
Author: Aleksa Zatezalo
Version: 2.0
Date: April 2025
Description: Tests GraphQL endpoints for information disclosure vulnerabilities
"""

from typing import Dict, List, Optional, Tuple, Any
from .tester import VulnerabilityTester
from .utils import Finding


class InfoTester(VulnerabilityTester):
    """
    Tests GraphQL endpoints for information disclosure issues like
    field suggestions, CSRF vulnerabilities, and insecure configurations.
    """

    def __init__(self):
        """Initialize the information tester."""
        super().__init__()
        self.test_name = "GraphQL Information Disclosure Testing"
        self.debug_mode = False

    async def check_field_suggestions(self) -> Optional[Finding]:
        """
        Check if field suggestions are enabled, which can leak schema information.

        Returns:
            Optional[Finding]: Finding if vulnerable, None otherwise
        """
        # Send an intentionally invalid query with a typo
        query = "query { __schema { directive } }"

        response, _ = await self.client.graphql_query(query)

        if not response or "errors" not in response:
            return None

        # Check if "Did you mean" appears in error messages
        suggestions_enabled = any(
            "did you mean" in str(err.get("message", "")).lower()
            for err in response.get("errors", [])
        )

        if suggestions_enabled:
            finding = Finding(
                title="Field Suggestions Enabled",
                severity="LOW",
                description="The GraphQL server is providing field suggestions in error messages, which can help attackers discover schema information",
                endpoint=self.client.endpoint,
                impact="Information Leakage - Schema details are being disclosed",
                remediation="Disable field suggestions in production environments",
            )
            return finding

        return None

    async def check_get_method_query(self) -> Optional[Finding]:
        """
        Check if GraphQL queries are allowed over GET requests,
        which may enable CSRF attacks.

        Returns:
            Optional[Finding]: Finding if vulnerable, None otherwise
        """
        query = "query { __typename }"

        # Use direct make_request to bypass normal GraphQL query handling
        response, _ = await self.client.make_request(
            "GET", url=f"{self.client.endpoint}?query={query}"
        )

        if not response:
            return None

        # Check if the query was successful
        if response.get("data", {}).get("__typename"):
            finding = Finding(
                title="GET-based Queries Enabled (Possible CSRF)",
                severity="MEDIUM",
                description="The GraphQL server allows queries via GET requests, which may enable cross-site request forgery (CSRF) attacks",
                endpoint=self.client.endpoint,
                impact="Attackers may be able to execute operations using the victim's credentials",
                remediation="Disable GET method for GraphQL queries or implement proper CSRF protections",
            )
            return finding

        return None

    async def check_get_method_mutation(self) -> Optional[Finding]:
        """
        Check if GraphQL mutations are allowed over GET requests,
        which may enable CSRF attacks.

        Returns:
            Optional[Finding]: Finding if vulnerable, None otherwise
        """
        query = "mutation { __typename }"

        # Use direct make_request to bypass normal GraphQL query handling
        response, _ = await self.client.make_request(
            "GET", url=f"{self.client.endpoint}?query={query}"
        )

        if not response:
            return None

        # Check if the mutation was successful
        if response.get("data", {}).get("__typename"):
            finding = Finding(
                title="GET-based Mutations Enabled (Possible CSRF)",
                severity="HIGH",
                description="The GraphQL server allows mutations via GET requests, which enables cross-site request forgery (CSRF) attacks",
                endpoint=self.client.endpoint,
                impact="Attackers can modify data using the victim's credentials",
                remediation="Disable GET method for GraphQL mutations and implement proper CSRF protections",
            )
            return finding

        return None

    async def check_post_urlencoded(self) -> Optional[Finding]:
        """
        Check if GraphQL supports urlencoded form data, which may enable CSRF attacks.

        Returns:
            Optional[Finding]: Finding if vulnerable, None otherwise
        """
        query = "query { __typename }"

        # Save original content type
        original_content_type = self.client.headers.get("Content-Type")

        # Set URL encoded content type
        self.client.headers["Content-Type"] = "application/x-www-form-urlencoded"

        try:
            # Use direct make_request with form data
            response, _ = await self.client.make_request("POST", data={"query": query})

            if response and response.get("data", {}).get("__typename"):
                finding = Finding(
                    title="URL-encoded POST Queries Enabled (Possible CSRF)",
                    severity="MEDIUM",
                    description="The GraphQL server accepts queries via URL-encoded form data, which may enable cross-site request forgery (CSRF) attacks",
                    endpoint=self.client.endpoint,
                    impact="Attackers may be able to execute operations using the victim's credentials",
                    remediation="Only accept application/json content type for GraphQL operations",
                )
                return finding
        finally:
            # Restore original content type
            if original_content_type:
                self.client.headers["Content-Type"] = original_content_type
            else:
                del self.client.headers["Content-Type"]

        return None

    async def check_introspection(self) -> Optional[Finding]:
        """
        Check if introspection is enabled, which can expose schema details.

        Returns:
            Optional[Finding]: Finding if vulnerable, None otherwise
        """
        # We already know introspection is enabled if we have schema info
        if self.client.schema:
            finding = Finding(
                title="Introspection Enabled",
                severity="MEDIUM",
                description="The GraphQL server has introspection enabled, which exposes detailed schema information",
                endpoint=self.client.endpoint,
                impact="Attackers can map the entire GraphQL schema and discover available operations",
                remediation="Disable introspection in production environments or implement authorization controls",
            )
            return finding

        return None

    async def check_graphiql(self) -> Optional[Finding]:
        """
        Check if GraphiQL or Playground is enabled, which can aid attackers.

        Returns:
            Optional[Finding]: Finding if vulnerable, None otherwise
        """
        # Check for GraphiQL
        response, _ = await self.client.make_request("GET")

        if not response:
            return None

        # Look for GraphiQL or Playground indicators in the response
        response_text = str(response.get("text", "")).lower()

        if "graphiql" in response_text or "playground" in response_text:
            finding = Finding(
                title="GraphiQL/Playground Enabled",
                severity="LOW",
                description="The GraphQL server has GraphiQL or Playground enabled, providing a UI for exploring the API",
                endpoint=self.client.endpoint,
                impact="Makes it easier for attackers to explore and test the API",
                remediation="Disable GraphiQL/Playground in production environments",
            )
            return finding

        return None

    async def check_batch_support(self) -> Optional[Finding]:
        """
        Check if the server supports query batching, which can amplify attacks.

        Returns:
            Optional[Finding]: Finding if vulnerable, None otherwise
        """
        # Create a simple batch of two queries
        batch_query = [
            {"query": "query { __typename }"},
            {"query": "query { __typename }"},
        ]

        response, _ = await self.client.make_request("POST", json=batch_query)

        if not response:
            return None

        # Check if batch was processed successfully (should be an array)
        if isinstance(response, list) and len(response) == 2:
            finding = Finding(
                title="Query Batching Enabled",
                severity="LOW",
                description="The GraphQL server supports query batching, which can be used to amplify attacks",
                endpoint=self.client.endpoint,
                impact="Attackers can send multiple operations in a single request, potentially bypassing rate limits",
                remediation="Implement per-operation rate limiting and set maximum batch size limits",
            )
            return finding

        return None

    async def run_test(self) -> List[Finding]:
        """
        Run all information disclosure tests and return findings.

        Returns:
            List[Finding]: All findings from the test
        """
        if not self.client.endpoint:
            self.printer.print_msg(
                "No endpoint set. Run setup_endpoint first.", status="error"
            )
            return self.findings

        self.printer.print_section("Starting Information Disclosure Testing")

        # Define all tests to run
        tests = [
            ("Field Suggestions", self.check_field_suggestions),
            ("GET-based Queries", self.check_get_method_query),
            ("GET-based Mutations", self.check_get_method_mutation),
            ("URL-encoded POST", self.check_post_urlencoded),
            ("Introspection", self.check_introspection),
            ("GraphiQL/Playground", self.check_graphiql),
            ("Query Batching", self.check_batch_support),
        ]

        # Run each test
        for test_name, test_func in tests:
            self.printer.print_msg(f"Testing for {test_name}...", status="log")

            try:
                finding = await test_func()

                if finding:
                    self.add_finding(finding)
                    self.printer.print_msg(
                        f"Found issue: {finding.title}",
                        status="warning" if finding.severity != "HIGH" else "failed",
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
