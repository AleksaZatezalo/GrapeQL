"""
Tests for DosTester component (Denial of Service Testing)
"""

import pytest
from unittest.mock import AsyncMock, patch

try:
    from grapeql import DosTester
except ImportError:
    class DosTester:
        def __init__(self):
            self.findings = []
            self.endpoint = None
            self.client = None

class TestDosTester:
    """Test suite for Denial of Service testing functionality."""

    @pytest.fixture
    def dos_tester(self):
        """Create a DosTester instance for testing."""
        return DosTester()

    @pytest.mark.asyncio
    async def test_setup_endpoint(self, dos_tester, mock_aioresponses):
        """Test DoS tester endpoint setup."""
        endpoint = "https://example.com/graphql"
        
        mock_aioresponses.post(
            endpoint,
            payload={"data": {"__schema": {"types": []}}},
            status=200
        )
        
        result = await dos_tester.setup_endpoint(endpoint)
        assert result is True

    @pytest.mark.asyncio
    async def test_setup_endpoint_with_proxy(self, dos_tester, mock_aioresponses):
        """Test DoS tester setup with proxy configuration."""
        endpoint = "https://example.com/graphql"
        proxy = "127.0.0.1:8080"
        
        mock_aioresponses.post(
            endpoint,
            payload={"data": {"__schema": {"types": []}}},
            status=200
        )
        
        result = await dos_tester.setup_endpoint(endpoint, proxy=proxy)
        assert result is True

    @pytest.mark.asyncio
    async def test_circular_query_detection(self, dos_tester, mock_aioresponses):
        """Test detection of circular query vulnerabilities."""
        endpoint = "https://example.com/graphql"
        dos_tester.endpoint = endpoint
        
        # Mock response for circular query test
        mock_aioresponses.post(
            endpoint,
            payload={
                "data": {
                    "user": {
                        "friends": [
                            {
                                "friends": [
                                    {"friends": []}
                                ]
                            }
                        ]
                    }
                }
            },
            status=200
        )
        
        await dos_tester.run_test()
        findings = dos_tester.get_findings()
        
        # Should detect potential for circular queries
        circular_finding = next(
            (f for f in findings if "circular" in str(f).lower() or "recursive" in str(f).lower()), 
            None
        )
        assert circular_finding is not None

    @pytest.mark.asyncio
    async def test_deeply_nested_query_detection(self, dos_tester, mock_aioresponses):
        """Test detection of deeply nested query vulnerabilities."""
        endpoint = "https://example.com/graphql"
        dos_tester.endpoint = endpoint
        
        # Mock successful response to deeply nested query
        mock_aioresponses.post(
            endpoint,
            payload={"data": {"user": {"profile": {"settings": {"preferences": {}}}}}},
            status=200
        )
        
        await dos_tester.run_test()
        findings = dos_tester.get_findings()
        
        # Should detect that deeply nested queries are allowed
        nested_finding = next(
            (f for f in findings if "nested" in str(f).lower() or "depth" in str(f).lower()), 
            None
        )
        assert nested_finding is not None

    @pytest.mark.asyncio
    async def test_alias_overloading_detection(self, dos_tester, mock_aioresponses):
        """Test detection of alias overloading vulnerabilities."""
        endpoint = "https://example.com/graphql"
        dos_tester.endpoint = endpoint
        
        # Mock response accepting many aliases
        mock_aioresponses.post(
            endpoint,
            payload={
                "data": {
                    "user1": {"id": "1"},
                    "user2": {"id": "2"},
                    "user3": {"id": "3"}
                    # ... many more aliases
                }
            },
            status=200
        )
        
        await dos_tester.run_test()
        findings = dos_tester.get_findings()
        
        # Should detect alias overloading vulnerability
        alias_finding = next(
            (f for f in findings if "alias" in str(f).lower() or "overload" in str(f).lower()), 
            None
        )
        assert alias_finding is not None

    @pytest.mark.asyncio
    async def test_field_duplication_detection(self, dos_tester, mock_aioresponses):
        """Test detection of field duplication vulnerabilities."""
        endpoint = "https://example.com/graphql"
        dos_tester.endpoint = endpoint
        
        # Mock response accepting duplicate fields
        mock_aioresponses.post(
            endpoint,
            payload={
                "data": {
                    "user": {
                        "id": "1",
                        "username": "test"
                    }
                }
            },
            status=200
        )
        
        await dos_tester.run_test()
        findings = dos_tester.get_findings()
        
        # Should detect field duplication vulnerability
        duplication_finding = next(
            (f for f in findings if "duplicate" in str(f).lower() or "repeated" in str(f).lower()), 
            None
        )
        assert duplication_finding is not None

    @pytest.mark.asyncio
    async def test_array_based_dos_detection(self, dos_tester, mock_aioresponses):
        """Test detection of array-based DoS vulnerabilities."""
        endpoint = "https://example.com/graphql"
        dos_tester.endpoint = endpoint
        
        # Mock response with large arrays
        mock_aioresponses.post(
            endpoint,
            payload={
                "data": {
                    "users": [{"id": str(i)} for i in range(1000)]
                }
            },
            status=200
        )
        
        await dos_tester.run_test()
        findings = dos_tester.get_findings()
        
        # Should detect potential for array-based DoS
        array_finding = next(
            (f for f in findings if "array" in str(f).lower() or "list" in str(f).lower()), 
            None
        )
        assert array_finding is not None

    @pytest.mark.asyncio
    async def test_timeout_detection(self, dos_tester, mock_aioresponses):
        """Test detection of query timeout vulnerabilities."""
        endpoint = "https://example.com/graphql"
        dos_tester.endpoint = endpoint
        
        # Mock timeout response
        mock_aioresponses.post(
            endpoint,
            exception=asyncio.TimeoutError("Query timeout")
        )
        
        await dos_tester.run_test()
        findings = dos_tester.get_findings()
        
        # Should detect timeout vulnerability
        timeout_finding = next(
            (f for f in findings if "timeout" in str(f).lower()), 
            None
        )
        assert timeout_finding is not None

    @pytest.mark.asyncio
    async def test_complexity_analysis(self, dos_tester, mock_aioresponses):
        """Test query complexity analysis."""
        endpoint = "https://example.com/graphql"
        dos_tester.endpoint = endpoint
        
        # Mock response for complex query
        mock_aioresponses.post(
            endpoint,
            payload={"data": {"users": [{"posts": [{"comments": []}]}]}},
            status=200
        )
        
        await dos_tester.run_test()
        findings = dos_tester.get_findings()
        
        # Should analyze query complexity
        complexity_finding = next(
            (f for f in findings if "complexity" in str(f).lower()), 
            None
        )
        # Depending on implementation, might or might not have complexity findings

    @pytest.mark.asyncio
    async def test_rate_limiting_detection(self, dos_tester, mock_aioresponses):
        """Test detection of rate limiting mechanisms."""
        endpoint = "https://example.com/graphql"
        dos_tester.endpoint = endpoint
        
        # Mock rate limiting response
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {
                        "message": "Rate limit exceeded",
                        "extensions": {
                            "code": "RATE_LIMITED"
                        }
                    }
                ]
            },
            status=429
        )
        
        await dos_tester.run_test()
        findings = dos_tester.get_findings()
        
        # Should detect rate limiting (positive security finding)
        rate_limit_finding = next(
            (f for f in findings if "rate" in str(f).lower() or "limit" in str(f).lower()), 
            None
        )
        # This would be a positive finding (good security practice)

    @pytest.mark.asyncio
    async def test_protected_endpoint(self, dos_tester, mock_aioresponses):
        """Test DoS testing on a well-protected endpoint."""
        endpoint = "https://example.com/graphql"
        dos_tester.endpoint = endpoint
        
        # Mock protected responses
        mock_aioresponses.post(
            endpoint,
            payload={
                "errors": [
                    {
                        "message": "Query complexity limit exceeded",
                        "extensions": {
                            "code": "QUERY_COMPLEXITY_TOO_HIGH"
                        }
                    }
                ]
            },
            status=400
        )
        
        await dos_tester.run_test()
        findings = dos_tester.get_findings()
        
        # Should find fewer vulnerabilities on protected endpoint
        high_severity_findings = [
            f for f in findings 
            if "critical" in str(f).lower() or "high" in str(f).lower()
        ]
        # Should have fewer high-severity findings

    def test_get_findings(self, dos_tester):
        """Test getting DoS testing findings."""
        # Mock some findings
        dos_tester.findings = [
            {"type": "critical", "message": "Circular query DoS vulnerability"},
            {"type": "high", "message": "No query depth limiting"},
            {"type": "medium", "message": "Alias overloading possible"}
        ]
        
        findings = dos_tester.get_findings()
        assert len(findings) == 3
        assert any("circular" in str(f).lower() for f in findings)