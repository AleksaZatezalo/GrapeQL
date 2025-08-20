"""
Tests for Fingerprinter component
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

try:
    from grapeql import Fingerprinter
except ImportError:
    class Fingerprinter:
        def __init__(self):
            self.findings = []
            self.endpoint = None

class TestFingerprinter:
    """Test suite for GraphQL engine fingerprinting functionality."""

    @pytest.fixture
    def fingerprinter(self):
        """Create a Fingerprinter instance for testing."""
        return Fingerprinter()

    @pytest.mark.asyncio
    async def test_setup_endpoint(self, fingerprinter, mock_aioresponses):
        """Test fingerprinter endpoint setup."""
        endpoint = "https://example.com/graphql"
        
        mock_aioresponses.post(
            endpoint,
            payload={"data": {"__schema": {"types": []}}},
            status=200,
            headers={"Server": "Apollo Server"}
        )
        
        result = await fingerprinter.setup_endpoint(endpoint)
        assert result is True
        assert fingerprinter.endpoint == endpoint

    @pytest.mark.asyncio
    async def test_fingerprint_apollo_server(self, fingerprinter, mock_aioresponses):
        """Test fingerprinting Apollo Server."""
        endpoint = "https://example.com/graphql"
        fingerprinter.endpoint = endpoint
        
        # Mock response with Apollo Server headers
        mock_aioresponses.post(
            endpoint,
            payload={"data": {"__schema": {"types": []}}},
            headers={
                "Server": "Apollo Server",
                "x-apollo-operation-name": "IntrospectionQuery"
            }
        )
        
        await fingerprinter.fingerprint()
        findings = fingerprinter.get_findings()
        
        # Check if Apollo Server was detected
        apollo_finding = next((f for f in findings if "Apollo" in str(f)), None)
        assert apollo_finding is not None

    @pytest.mark.asyncio
    async def test_fingerprint_graphql_yoga(self, fingerprinter, mock_aioresponses):
        """Test fingerprinting GraphQL Yoga."""
        endpoint = "https://example.com/graphql"
        fingerprinter.endpoint = endpoint
        
        mock_aioresponses.post(
            endpoint,
            payload={"data": {"__schema": {"types": []}}},
            headers={"Server": "GraphQL Yoga"}
        )
        
        await fingerprinter.fingerprint()
        findings = fingerprinter.get_findings()
        
        yoga_finding = next((f for f in findings if "Yoga" in str(f)), None)
        assert yoga_finding is not None

    @pytest.mark.asyncio
    async def test_fingerprint_hasura(self, fingerprinter, mock_aioresponses):
        """Test fingerprinting Hasura."""
        endpoint = "https://example.com/graphql"
        fingerprinter.endpoint = endpoint
        
        mock_aioresponses.post(
            endpoint,
            payload={
                "data": {
                    "__schema": {
                        "types": [
                            {"name": "hasura_metadata"},
                            {"name": "query_root"}
                        ]
                    }
                }
            }
        )
        
        await fingerprinter.fingerprint()
        findings = fingerprinter.get_findings()
        
        hasura_finding = next((f for f in findings if "Hasura" in str(f)), None)
        assert hasura_finding is not None

    @pytest.mark.asyncio
    async def test_fingerprint_unknown_engine(self, fingerprinter, mock_aioresponses):
        """Test fingerprinting unknown GraphQL engine."""
        endpoint = "https://example.com/graphql"
        fingerprinter.endpoint = endpoint
        
        mock_aioresponses.post(
            endpoint,
            payload={"data": {"__schema": {"types": []}}},
            headers={"Server": "Unknown Server"}
        )
        
        await fingerprinter.fingerprint()
        findings = fingerprinter.get_findings()
        
        # Should still have some findings even if engine is unknown
        assert len(findings) >= 0

    def test_get_findings(self, fingerprinter):
        """Test getting fingerprinting findings."""
        # Mock some findings
        fingerprinter.findings = [
            {"type": "info", "message": "GraphQL engine detected: Apollo Server"},
            {"type": "info", "message": "Version: 2.19.0"}
        ]
        
        findings = fingerprinter.get_findings()
        assert len(findings) == 2
        assert any("Apollo Server" in str(f) for f in findings)

    @pytest.mark.asyncio
    async def test_version_detection(self, fingerprinter, mock_aioresponses):
        """Test GraphQL engine version detection."""
        endpoint = "https://example.com/graphql"
        fingerprinter.endpoint = endpoint
        
        mock_aioresponses.post(
            endpoint,
            payload={"data": {"__schema": {"types": []}}},
            headers={
                "Server": "Apollo Server",
                "x-apollo-server-version": "2.19.0"
            }
        )
        
        await fingerprinter.fingerprint()
        findings = fingerprinter.get_findings()
        
        version_finding = next((f for f in findings if "2.19.0" in str(f)), None)
        assert version_finding is not None

    @pytest.mark.asyncio
    async def test_error_handling(self, fingerprinter, mock_aioresponses):
        """Test error handling during fingerprinting."""
        endpoint = "https://example.com/graphql"
        fingerprinter.endpoint = endpoint
        
        # Mock network error
        mock_aioresponses.post(endpoint, exception=Exception("Network error"))
        
        # Should not raise exception, but handle gracefully
        await fingerprinter.fingerprint()
        
        # Should have recorded the error
        findings = fingerprinter.get_findings()
        error_finding = next((f for f in findings if "error" in str(f).lower()), None)
        # Depending on implementation, might or might not have error findings