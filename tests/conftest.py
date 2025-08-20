"""
Pytest configuration and shared fixtures for GrapeQL test suite
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
import aiohttp
from aioresponses import aioresponses


@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_session():
    """Mock aiohttp session for testing HTTP requests."""
    session = AsyncMock(spec=aiohttp.ClientSession)
    return session


@pytest.fixture
def mock_response():
    """Mock HTTP response object."""
    response = MagicMock()
    response.status = 200
    response.headers = {"Content-Type": "application/json"}
    return response


@pytest.fixture
def sample_graphql_schema():
    """Sample GraphQL schema for testing."""
    return {
        "data": {
            "__schema": {
                "types": [
                    {
                        "name": "Query",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "users", "type": {"name": "User"}, "args": []}
                        ],
                    },
                    {
                        "name": "User",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "id", "type": {"name": "ID"}},
                            {"name": "username", "type": {"name": "String"}},
                            {"name": "email", "type": {"name": "String"}},
                        ],
                    },
                ]
            }
        }
    }


@pytest.fixture
def test_endpoint():
    """Standard test endpoint URL."""
    return "https://127.0.0.1:5013/graphql"


@pytest.fixture
def mock_aioresponses():
    """Mock aioresponses for HTTP mocking."""
    with aioresponses() as m:
        yield m
