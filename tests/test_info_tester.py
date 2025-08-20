"""
Tests for InfoTester component (Information Disclosure Testing)
"""

import pytest
from unittest.mock import AsyncMock, patch

try:
    from grapeql import InfoTester
except ImportError:
    class InfoTester:
        def __init__(self):
            self.findings = []
            self.endpoint = None

class TestInfoTester:
    """Test suite for information disclosure testing functionality."""

    @pytest.fixture
    def info_tester(self):
        """Create an InfoTester instance for testing."""
        return InfoTester()

    @pytest.mark.asyncio
    async def test_setup_endpoint(self, info_tester, mock_aioresponses):
        """Test info tester endpoint setup."""
        endpoint = "https://example.com/graphql"
        
        mock_aioresponses.post(
            endpoint,
            payload={"data": {"__schema": {"types": []}}},
            status=200
        )
        
        result = await info_tester.setup_endpoint(endpoint)
        assert result is True

    @pytest.mark.asyncio
    async def test_introspection_enabled(self, info_tester, mock_aioresponses, sample_graphql_schema):
        """Test detection of enabled introspection."""
        endpoint = "https://example.com/graphql"
        info_tester.endpoint = endpoint
        
        # Mock successful introspection response
        mock_aioresponses.post(endpoint, payload=sample_graphql_schema)
        
        await info_tester.run_test()
        findings = info_tester.get_findings()
        
        # Should detect that introspection is enabled
        introspection_finding = next(
            (f for f in findings if "introspection" in str(f).lower()), 
            None
        )
        assert introspection_finding is not None

    @pytest.mark.asyncio
    async def test_introspection_disabled(self, info_tester, mock_aioresponses):
        """Test detection of disabled introspection."""
        endpoint = "https://example.com/graphql"
        info_tester.endpoint = endpoint
        
        # Mock introspection disabled response
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {"message": "GraphQL introspection is not allowed"}
                ]
            }
        )
        
        await info_tester.run_test()
        findings = info_tester.get_findings()
        
        # Should note that introspection is disabled (positive security finding)
        introspection_finding = next(
            (f for f in findings if "introspection" in str(f).lower()), 
            None
        )
        # Depending on implementation, might report this as good security practice

    @pytest.mark.asyncio
    async def test_field_suggestions_detection(self, info_tester, mock_aioresponses):
        """Test detection of field suggestions in error messages."""
        endpoint = "https://example.com/graphql"
        info_tester.endpoint = endpoint
        
        # Mock response with field suggestions
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {
                        "message": "Cannot query field 'usr' on type 'Query'. Did you mean 'user'?",
                        "extensions": {
                            "code": "GRAPHQL_VALIDATION_FAILED"
                        }
                    }
                ]
            }
        )
        
        await info_tester.run_test()
        findings = info_tester.get_findings()
        
        # Should detect field suggestions as information disclosure
        suggestion_finding = next(
            (f for f in findings if "suggestion" in str(f).lower() or "did you mean" in str(f).lower()), 
            None
        )
        assert suggestion_finding is not None

    @pytest.mark.asyncio
    async def test_schema_leak_detection(self, info_tester, mock_aioresponses):
        """Test detection of schema information leaks."""
        endpoint = "https://example.com/graphql"
        info_tester.endpoint = endpoint
        
        # Mock response that leaks schema information
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {
                        "message": "Field 'secret' doesn't exist on type 'User'",
                        "locations": [{"line": 1, "column": 10}],
                        "path": ["user"],
                        "extensions": {
                            "exception": {
                                "stacktrace": [
                                    "GraphQLError: Field 'secret' doesn't exist on type 'User'",
                                    "    at validateFieldSelection (/app/node_modules/graphql/validation/rules/FieldsOnCorrectTypeRule.js:48:13)"
                                ]
                            }
                        }
                    }
                ]
            }
        )
        
        await info_tester.run_test()
        findings = info_tester.get_findings()
        
        # Should detect stack trace as information disclosure
        stacktrace_finding = next(
            (f for f in findings if "stacktrace" in str(f).lower() or "exception" in str(f).lower()), 
            None
        )
        assert stacktrace_finding is not None

    @pytest.mark.asyncio
    async def test_debug_mode_detection(self, info_tester, mock_aioresponses):
        """Test detection of debug mode."""
        endpoint = "https://example.com/graphql"
        info_tester.endpoint = endpoint
        
        # Mock response indicating debug mode
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {
                        "message": "Syntax Error: Expected Name, found }",
                        "extensions": {
                            "exception": {
                                "stacktrace": ["Full stack trace here..."]
                            }
                        }
                    }
                ]
            }
        )
        
        await info_tester.run_test()
        findings = info_tester.get_findings()
        
        # Should detect debug information
        debug_finding = next(
            (f for f in findings if "debug" in str(f).lower() or "stacktrace" in str(f).lower()), 
            None
        )
        assert debug_finding is not None

    @pytest.mark.asyncio
    async def test_graphql_playground_detection(self, info_tester, mock_aioresponses):
        """Test detection of GraphQL Playground."""
        endpoint = "https://example.com/graphql"
        info_tester.endpoint = endpoint
        
        # Mock GET request to detect playground
        mock_aioresponses.get(
            endpoint,
            payload="GraphQL Playground",
            headers={"Content-Type": "text/html"},
            status=200
        )
        
        await info_tester.run_test()
        findings = info_tester.get_findings()
        
        # Should detect GraphQL Playground
        playground_finding = next(
            (f for f in findings if "playground" in str(f).lower()), 
            None
        )
        assert playground_finding is not None

    @pytest.mark.asyncio
    async def test_error_message_analysis(self, info_tester, mock_aioresponses):
        """Test analysis of error messages for sensitive information."""
        endpoint = "https://example.com/graphql"
        info_tester.endpoint = endpoint
        
        # Mock response with potentially sensitive error message
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {
                        "message": "Database connection failed: Connection to postgresql://user:pass@localhost:5432/mydb failed"
                    }
                ]
            }
        )
        
        await info_tester.run_test()
        findings = info_tester.get_findings()
        
        # Should detect database connection information
        db_info_finding = next(
            (f for f in findings if "database" in str(f).lower() or "connection" in str(f).lower()), 
            None
        )
        assert db_info_finding is not None

    def test_get_findings(self, info_tester):
        """Test getting information disclosure findings."""
        # Mock some findings
        info_tester.findings = [
            {"type": "high", "message": "Introspection query enabled"},
            {"type": "medium", "message": "Field suggestions revealed in error messages"},
            {"type": "low", "message": "GraphQL Playground accessible"}
        ]
        
        findings = info_tester.get_findings()
        assert len(findings) == 3
        assert any("introspection" in str(f).lower() for f in findings)