"""
Tests for InjectionTester component
"""

import pytest
from unittest.mock import AsyncMock, patch

try:
    from grapeql import InjectionTester
except ImportError:

    class InjectionTester:
        def __init__(self):
            self.findings = []
            self.endpoint = None
            self.credentials = {"username": "admin", "password": "changeme"}


class TestInjectionTester:
    """Test suite for injection testing functionality."""

    @pytest.fixture
    def injection_tester(self):
        """Create an InjectionTester instance for testing."""
        return InjectionTester()

    def test_set_credentials(self, injection_tester):
        """Test setting custom credentials for injection testing."""
        injection_tester.set_credentials("testuser", "testpass")
        assert injection_tester.credentials["username"] == "testuser"
        assert injection_tester.credentials["password"] == "testpass"

    @pytest.mark.asyncio
    async def test_setup_endpoint(self, injection_tester, mock_aioresponses):
        """Test injection tester endpoint setup."""
        endpoint = "https://example.com/graphql"

        mock_aioresponses.post(
            endpoint, payload={"data": {"__schema": {"types": []}}}, status=200
        )

        result = await injection_tester.setup_endpoint(endpoint)
        assert result is True

    @pytest.mark.asyncio
    async def test_sql_injection_detection(self, injection_tester, mock_aioresponses):
        """Test SQL injection vulnerability detection."""
        endpoint = "https://example.com/graphql"
        injection_tester.endpoint = endpoint

        # Mock vulnerable response (SQL error)
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {
                        "message": 'SQLITE_ERROR: near "\'": syntax error',
                        "extensions": {"code": "INTERNAL_ERROR"},
                    }
                ]
            },
        )

        await injection_tester.run_test()
        findings = injection_tester.get_findings()

        # Should detect SQL injection vulnerability
        sql_injection_finding = next(
            (
                f
                for f in findings
                if "sql" in str(f).lower() and "injection" in str(f).lower()
            ),
            None,
        )
        assert sql_injection_finding is not None

    @pytest.mark.asyncio
    async def test_nosql_injection_detection(self, injection_tester, mock_aioresponses):
        """Test NoSQL injection vulnerability detection."""
        endpoint = "https://example.com/graphql"
        injection_tester.endpoint = endpoint

        # Mock vulnerable response (MongoDB error)
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {
                        "message": "MongoError: invalid operator: $where",
                        "extensions": {"code": "INTERNAL_ERROR"},
                    }
                ]
            },
        )

        await injection_tester.run_test()
        findings = injection_tester.get_findings()

        # Should detect NoSQL injection vulnerability
        nosql_injection_finding = next(
            (
                f
                for f in findings
                if "nosql" in str(f).lower() or "mongo" in str(f).lower()
            ),
            None,
        )
        assert nosql_injection_finding is not None

    @pytest.mark.asyncio
    async def test_command_injection_detection(
        self, injection_tester, mock_aioresponses
    ):
        """Test command injection vulnerability detection."""
        endpoint = "https://example.com/graphql"
        injection_tester.endpoint = endpoint

        # Mock vulnerable response (command execution error)
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {
                        "message": "sh: command not found: '; ls -la'",
                        "extensions": {"code": "INTERNAL_ERROR"},
                    }
                ]
            },
        )

        await injection_tester.run_test()
        findings = injection_tester.get_findings()

        # Should detect command injection vulnerability
        cmd_injection_finding = next(
            (
                f
                for f in findings
                if "command" in str(f).lower() and "injection" in str(f).lower()
            ),
            None,
        )
        assert cmd_injection_finding is not None

    @pytest.mark.asyncio
    async def test_ldap_injection_detection(self, injection_tester, mock_aioresponses):
        """Test LDAP injection vulnerability detection."""
        endpoint = "https://example.com/graphql"
        injection_tester.endpoint = endpoint

        # Mock vulnerable response (LDAP error)
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {
                        "message": "javax.naming.directory.InvalidSearchFilterException: [LDAP: error code 87 - invalid attribute syntax]",
                        "extensions": {"code": "INTERNAL_ERROR"},
                    }
                ]
            },
        )

        await injection_tester.run_test()
        findings = injection_tester.get_findings()

        # Should detect LDAP injection vulnerability
        ldap_injection_finding = next(
            (f for f in findings if "ldap" in str(f).lower()), None
        )
        assert ldap_injection_finding is not None

    @pytest.mark.asyncio
    async def test_xpath_injection_detection(self, injection_tester, mock_aioresponses):
        """Test XPath injection vulnerability detection."""
        endpoint = "https://example.com/graphql"
        injection_tester.endpoint = endpoint

        # Mock vulnerable response (XPath error)
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {
                        "message": "XPathExpressionException: A location step was expected following the '/' or '//' token.",
                        "extensions": {"code": "INTERNAL_ERROR"},
                    }
                ]
            },
        )

        await injection_tester.run_test()
        findings = injection_tester.get_findings()

        # Should detect XPath injection vulnerability
        xpath_injection_finding = next(
            (f for f in findings if "xpath" in str(f).lower()), None
        )
        assert xpath_injection_finding is not None

    @pytest.mark.asyncio
    async def test_template_injection_detection(
        self, injection_tester, mock_aioresponses
    ):
        """Test template injection vulnerability detection."""
        endpoint = "https://example.com/graphql"
        injection_tester.endpoint = endpoint

        # Mock vulnerable response (template engine error)
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {
                        "message": "TemplateError: 'dict object' has no attribute '__getitem__'",
                        "extensions": {"code": "INTERNAL_ERROR"},
                    }
                ]
            },
        )

        await injection_tester.run_test()
        findings = injection_tester.get_findings()

        # Should detect template injection vulnerability
        template_injection_finding = next(
            (f for f in findings if "template" in str(f).lower()), None
        )
        assert template_injection_finding is not None

    @pytest.mark.asyncio
    async def test_time_based_injection(self, injection_tester, mock_aioresponses):
        """Test time-based injection detection."""
        endpoint = "https://example.com/graphql"
        injection_tester.endpoint = endpoint

        # Mock response that takes unusually long (simulating time-based attack)
        # This would require custom timing logic in the actual implementation
        mock_aioresponses.post(endpoint, payload={"data": {"user": None}}, status=200)

        await injection_tester.run_test()
        findings = injection_tester.get_findings()

        # Implementation would need to measure response times
        # and detect anomalies indicating successful time-based injection

    @pytest.mark.asyncio
    async def test_boolean_based_injection(self, injection_tester, mock_aioresponses):
        """Test boolean-based blind injection detection."""
        endpoint = "https://example.com/graphql"
        injection_tester.endpoint = endpoint

        # Mock different responses for true/false conditions
        mock_aioresponses.post(
            endpoint, payload={"data": {"user": {"id": "1"}}}, status=200
        )

        await injection_tester.run_test()
        findings = injection_tester.get_findings()

        # Implementation would need to test different payloads
        # and analyze response differences

    @pytest.mark.asyncio
    async def test_safe_endpoint(self, injection_tester, mock_aioresponses):
        """Test injection testing on a safe endpoint."""
        endpoint = "https://example.com/graphql"
        injection_tester.endpoint = endpoint

        # Mock safe responses (properly sanitized)
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {
                        "message": "Variable '$input' of type 'String!' was provided invalid value",
                        "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"},
                    }
                ]
            },
        )

        await injection_tester.run_test()
        findings = injection_tester.get_findings()

        # Should not find injection vulnerabilities
        injection_findings = [
            f
            for f in findings
            if any(
                term in str(f).lower()
                for term in ["injection", "sql", "nosql", "command"]
            )
        ]
        assert len(injection_findings) == 0

    def test_get_findings(self, injection_tester):
        """Test getting injection testing findings."""
        # Mock some findings
        injection_tester.findings = [
            {"type": "critical", "message": "SQL injection vulnerability detected"},
            {"type": "high", "message": "Command injection possible"},
            {"type": "medium", "message": "NoSQL injection indicators found"},
        ]

        findings = injection_tester.get_findings()
        assert len(findings) == 3
        assert any("sql injection" in str(f).lower() for f in findings)
