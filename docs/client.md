# GraphQLClient Documentation

The `GraphQLClient` class is the core component of GrapeQL, providing a unified HTTP client for all GraphQL operations with consistent request handling, proxy support, and header/cookie management.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Initialization](#initialization)
- [Configuration Methods](#configuration-methods)
- [HTTP Request Methods](#http-request-methods)
- [GraphQL Operations](#graphql-operations)
- [Utility Methods](#utility-methods)
- [Error Handling](#error-handling)
- [Examples](#examples)

## Overview

The `GraphQLClient` is designed with a layered architecture that separates concerns:

- **Configuration Layer**: Manages endpoints, proxies, headers, and authentication
- **HTTP Layer**: Handles raw HTTP requests with consistent error handling
- **GraphQL Layer**: Provides GraphQL-specific operations like queries and introspection
- **Utility Layer**: Offers debugging and connectivity testing tools

## Architecture

```python
class GraphQLClient:
    """
    Unified HTTP client for all GrapeQL modules providing consistent
    request handling, proxy support, and header/cookie management.
    """
```

### Key Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `endpoint` | `Optional[str]` | GraphQL endpoint URL |
| `proxy_url` | `Optional[str]` | HTTP proxy URL |
| `headers` | `Dict[str, str]` | HTTP headers dictionary |
| `cookies` | `Dict[str, str]` | HTTP cookies dictionary |
| `auth_token` | `Optional[str]` | Authentication token |
| `timeout` | `ClientTimeout` | Request timeout configuration |
| `schema` | `Optional[Dict]` | Cached GraphQL schema |
| `query_fields` | `Dict[str, Dict]` | Available query fields |
| `mutation_fields` | `Dict[str, Dict]` | Available mutation fields |

## Initialization

```python
from grapeql.client import GraphQLClient

# Create a new client instance
client = GraphQLClient()
```

**Default Configuration:**
- Headers: `{"Content-Type": "application/json"}`
- Timeout: 10 seconds
- No endpoint, proxy, or authentication configured

## Configuration Methods

### Endpoint Configuration

#### `set_endpoint(endpoint: str) -> None`

Set the GraphQL endpoint URL.

```python
client.set_endpoint("https://api.example.com/graphql")
```

**Parameters:**
- `endpoint` (str): The GraphQL endpoint URL

### Proxy Configuration

#### `configure_proxy(proxy_host: str, proxy_port: int) -> None`

Configure HTTP proxy settings for requests.

```python
client.configure_proxy("proxy.company.com", 8080)
```

**Parameters:**
- `proxy_host` (str): Proxy server hostname or IP
- `proxy_port` (int): Proxy server port

### Header Management

#### `set_header(name: str, value: str) -> None`

Set a single custom header.

```python
client.set_header("User-Agent", "GrapeQL/2.0")
client.set_header("X-API-Version", "v1")
```

#### `set_headers(headers: Dict[str, str]) -> None`

Set multiple headers at once.

```python
headers = {
    "X-API-Key": "your-api-key",
    "Accept": "application/json",
    "Custom-Header": "custom-value"
}
client.set_headers(headers)
```

#### `clear_headers() -> None`

Reset headers to default state (keeps Content-Type).

```python
client.clear_headers()
# Headers are now: {"Content-Type": "application/json"}
```

### Cookie Management

#### `set_cookie(name: str, value: str) -> None`

Set a single cookie.

```python
client.set_cookie("session_id", "abc123xyz")
```

#### `set_cookies(cookies: Dict[str, str]) -> None`

Set multiple cookies at once.

```python
cookies = {
    "session_id": "abc123xyz",
    "csrf_token": "token123",
    "preferences": "dark_mode=true"
}
client.set_cookies(cookies)
```

#### `clear_cookies() -> None`

Remove all cookies.

```python
client.clear_cookies()
```

### Authentication

#### `set_authorization(token: str, prefix: str = "Bearer") -> None`

Set the Authorization header with a token.

```python
# Bearer token (default)
client.set_authorization("your-jwt-token")
# Result: Authorization: Bearer your-jwt-token

# API Key
client.set_authorization("your-api-key", "API-Key")
# Result: Authorization: API-Key your-api-key

# Custom or no prefix
client.set_authorization("custom-token", "")
# Result: Authorization: custom-token
```

## HTTP Request Methods

### `make_request(method: str, url: Optional[str] = None, **kwargs) -> Tuple[Optional[Dict], Optional[str]]`

Make a generic HTTP request with consistent error handling.

```python
# GET request
response, error = await client.make_request("GET", "https://api.example.com/status")

# POST request with JSON payload
response, error = await client.make_request(
    "POST", 
    json={"query": "{ user { name } }"}
)

# Request with custom headers
response, error = await client.make_request(
    "POST",
    headers={"Custom-Header": "value"},
    json={"data": "example"}
)
```

**Parameters:**
- `method` (str): HTTP method (GET, POST, PUT, DELETE, etc.)
- `url` (Optional[str]): URL to request (uses `self.endpoint` if None)
- `**kwargs`: Additional arguments passed to aiohttp request

**Returns:**
- `Tuple[Optional[Dict], Optional[str]]`: (response_data, error_message)

**Response Handling:**
- JSON responses are automatically parsed
- Non-JSON responses are wrapped in `{"text": response_text}`
- Failed JSON parsing returns the raw text

## GraphQL Operations

### `graphql_query(query: str, variables: Optional[Dict] = None, operation_name: Optional[str] = None) -> Tuple[Optional[Dict], Optional[str]]`

Execute a GraphQL query with proper formatting.

```python
# Simple query
query = """
{
    user(id: "123") {
        name
        email
    }
}
"""
result, error = await client.graphql_query(query)

# Query with variables
query = """
query GetUser($userId: ID!) {
    user(id: $userId) {
        name
        email
        posts(limit: $limit) {
            title
        }
    }
}
"""
variables = {"userId": "123", "limit": 10}
result, error = await client.graphql_query(query, variables, "GetUser")

# Mutation
mutation = """
mutation CreateUser($input: UserInput!) {
    createUser(input: $input) {
        id
        name
        email
    }
}
"""
variables = {
    "input": {
        "name": "John Doe",
        "email": "john@example.com"
    }
}
result, error = await client.graphql_query(mutation, variables)
```

**Parameters:**
- `query` (str): GraphQL query or mutation string
- `variables` (Optional[Dict]): Variables for the query
- `operation_name` (Optional[str]): Name of the operation to execute

### `introspection_query() -> bool`

Run introspection query to validate the GraphQL endpoint and cache schema information.

```python
success = await client.introspection_query()

if success:
    print("Schema cached successfully")
    print(f"Available queries: {list(client.query_fields.keys())}")
    print(f"Available mutations: {list(client.mutation_fields.keys())}")
else:
    print("Introspection failed - endpoint might not be GraphQL")
```

**Returns:**
- `bool`: True if introspection succeeded and schema was cached

### `setup_endpoint(endpoint: str, proxy: Optional[str] = None) -> bool`

Convenience method to set endpoint, configure proxy, and run introspection.

```python
# Basic setup
success = await client.setup_endpoint("https://api.example.com/graphql")

# Setup with proxy
success = await client.setup_endpoint(
    "https://api.example.com/graphql", 
    "proxy.company.com:8080"
)

if success:
    print("Client ready for GraphQL operations")
else:
    print("Setup failed - check endpoint and network connectivity")
```

**Parameters:**
- `endpoint` (str): GraphQL endpoint URL
- `proxy` (Optional[str]): Proxy in format "host:port"

## Utility Methods

### `generate_curl() -> str`

Generate a cURL command from the last request for debugging and reporting.

```python
# After making a request
result, error = await client.graphql_query("{ user { name } }")

# Generate equivalent cURL command
curl_command = client.generate_curl()
print(curl_command)
# Output: curl -X POST https://api.example.com/graphql -H 'Content-Type:application/json' -d '{"query": "{ user { name } }"}'
```

### `test_connectivity(host: str, port: int) -> bool`

Test connectivity to a target server using both socket and HTTP methods.

```python
# Test direct connectivity
can_connect = await client.test_connectivity("api.example.com", 443)

if can_connect:
    print("Server is reachable")
else:
    print("Cannot connect to server")
```

**Connection Methods:**
1. **Socket Connection**: Direct TCP connection attempt
2. **HTTP Fallback**: HTTP GET request if socket fails

## Error Handling

The client provides consistent error handling across all operations:

### HTTP Errors

```python
result, error = await client.make_request("POST")

if error:
    if "timed out" in error:
        print("Request timeout - server may be slow")
    elif "Connection" in error:
        print("Network connectivity issue")
    else:
        print(f"Request failed: {error}")
```

### GraphQL Errors

```python
result, error = await client.graphql_query("{ user { name } }")

if error:
    print(f"Request failed: {error}")
elif result and "errors" in result:
    for gql_error in result["errors"]:
        print(f"GraphQL Error: {gql_error['message']}")
else:
    # Success - process result["data"]
    user_data = result["data"]["user"]
```

### Common Error Scenarios

| Error Type | Cause | Solution |
|------------|-------|----------|
| "No endpoint URL provided" | Endpoint not set | Call `set_endpoint()` first |
| "No GraphQL endpoint set" | GraphQL operation without endpoint | Set endpoint before GraphQL calls |
| "Request timed out" | Network timeout | Check connectivity, increase timeout |
| "Introspection failed" | Invalid GraphQL endpoint | Verify endpoint supports GraphQL |

## Examples

### Basic Usage

```python
import asyncio
from grapeql.client import GraphQLClient

async def basic_example():
    client = GraphQLClient()
    
    # Setup
    success = await client.setup_endpoint("https://api.example.com/graphql")
    if not success:
        return
    
    # Query
    query = "{ viewer { login name } }"
    result, error = await client.graphql_query(query)
    
    if error:
        print(f"Error: {error}")
    else:
        print(f"User: {result['data']['viewer']['name']}")

asyncio.run(basic_example())
```

### Authentication Example

```python
async def authenticated_example():
    client = GraphQLClient()
    
    # Configure authentication
    client.set_authorization("your-github-token")
    client.set_header("User-Agent", "MyApp/1.0")
    
    await client.setup_endpoint("https://api.github.com/graphql")
    
    query = """
    {
        viewer {
            login
            repositories(first: 5) {
                nodes {
                    name
                    stargazerCount
                }
            }
        }
    }
    """
    
    result, error = await client.graphql_query(query)
    if not error:
        repos = result["data"]["viewer"]["repositories"]["nodes"]
        for repo in repos:
            print(f"{repo['name']}: {repo['stargazerCount']} stars")
```

### Proxy and Enterprise Setup

```python
async def enterprise_example():
    client = GraphQLClient()
    
    # Configure for corporate environment
    client.configure_proxy("corporate-proxy.company.com", 8080)
    client.set_headers({
        "User-Agent": "CompanyApp/2.0",
        "X-Company-ID": "12345"
    })
    
    # Test connectivity first
    can_connect = await client.test_connectivity("internal-api.company.com", 443)
    if not can_connect:
        print("Cannot reach internal API")
        return
    
    # Setup endpoint
    success = await client.setup_endpoint("https://internal-api.company.com/graphql")
    if success:
        print("Connected to internal GraphQL API")
```

### Error Handling Best Practices

```python
async def robust_example():
    client = GraphQLClient()
    
    try:
        # Setup with error handling
        success = await client.setup_endpoint("https://api.example.com/graphql")
        if not success:
            print("Failed to setup GraphQL endpoint")
            return
        
        # Query with comprehensive error handling
        query = "{ user(id: $id) { name email } }"
        variables = {"id": "123"}
        
        result, error = await client.graphql_query(query, variables)
        
        if error:
            print(f"Request failed: {error}")
            return
        
        if result and "errors" in result:
            print("GraphQL errors:")
            for gql_error in result["errors"]:
                print(f"  - {gql_error['message']}")
            return
        
        # Success
        if result and "data" in result:
            user = result["data"]["user"]
            if user:
                print(f"Found user: {user['name']} ({user['email']})")
            else:
                print("User not found")
        
    except Exception as e:
        print(f"Unexpected error: {e}")
        # Generate debug info
        curl_cmd = client.generate_curl()
        if curl_cmd:
            print(f"Debug with: {curl_cmd}")
```

## Performance Considerations

### Connection Reuse

The client uses aiohttp's connection pooling automatically:

```python
# Multiple requests reuse connections
client = GraphQLClient()
await client.setup_endpoint("https://api.example.com/graphql")

# These requests will reuse the connection
for i in range(10):
    result, error = await client.graphql_query(f"{{ user(id: \"{i}\") {{ name }} }}")
```

### Timeout Configuration

```python
import aiohttp

# Custom timeout
client = GraphQLClient()
client.timeout = aiohttp.ClientTimeout(total=30, connect=10)
```

### Batch Operations

```python
# For multiple operations, consider batching
async def batch_queries():
    client = GraphQLClient()
    await client.setup_endpoint("https://api.example.com/graphql")
    
    # Instead of multiple single queries, use a single query with multiple fields
    batch_query = """
    {
        user1: user(id: "1") { name }
        user2: user(id: "2") { name }
        user3: user(id: "3") { name }
    }
    """
    
    result, error = await client.graphql_query(batch_query)
```

## Advanced Configuration

### Custom SSL Configuration

```python
import ssl
import aiohttp

# Custom SSL context
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False

# Pass to make_request
result, error = await client.make_request(
    "POST",
    ssl=ssl_context,
    json={"query": "{ user { name } }"}
)
```

### Request Interceptors

```python
# Override make_request for custom behavior
class CustomGraphQLClient(GraphQLClient):
    async def make_request(self, method, url=None, **kwargs):
        # Add custom headers
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        kwargs['headers']['X-Request-ID'] = str(uuid.uuid4())
        
        # Call parent method
        return await super().make_request(method, url, **kwargs)
```