"""
GrapeQL HTTP Client
Author: Aleksa Zatezalo (Simplified by Claude)
Version: 2.0
Date: April 2025
Description: Core HTTP client for GrapeQL with consistent request handling
"""

import aiohttp
import asyncio
import json
from typing import Dict, List, Optional, Any, Tuple, Union
from .utils import GrapePrinter

class GraphQLClient:
    """
    Unified HTTP client for all GrapeQL modules providing consistent
    request handling, proxy support, and header/cookie management.
    """

    def __init__(self):
        """Initialize the GraphQL client with default settings."""
        self.printer = GrapePrinter()
        self.endpoint: Optional[str] = None
        self.proxy_url: Optional[str] = None
        self.headers: Dict[str, str] = {"Content-Type": "application/json"}
        self.cookies: Dict[str, str] = {}
        self.auth_token: Optional[str] = None
        self.last_response: Optional[aiohttp.ClientResponse] = None
        self.timeout = aiohttp.ClientTimeout(total=10)
        self.schema: Optional[Dict] = None
        self.query_fields: Dict[str, Dict] = {}
        self.mutation_fields: Dict[str, Dict] = {}

    def configure_proxy(self, proxy_host: str, proxy_port: int) -> None:
        """
        Configure HTTP proxy settings.
        
        Args:
            proxy_host: Proxy server hostname or IP
            proxy_port: Proxy server port
        """
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"
        self.printer.print_msg(f"Proxy configured: {self.proxy_url}", status="success")

    def set_endpoint(self, endpoint: str) -> None:
        """
        Set the GraphQL endpoint URL.
        
        Args:
            endpoint: The GraphQL endpoint URL
        """
        self.endpoint = endpoint
        self.printer.print_msg(f"Endpoint set: {endpoint}", status="success")

    def set_header(self, name: str, value: str) -> None:
        """
        Set a custom header.
        
        Args:
            name: Header name
            value: Header value
        """
        self.headers[name] = value
        self.printer.print_msg(f"Set header {name}: {value}", status="success")

    def set_headers(self, headers: Dict[str, str]) -> None:
        """
        Set multiple custom headers.
        
        Args:
            headers: Dictionary of header name/value pairs
        """
        self.headers.update(headers)
        self.printer.print_msg(f"Set {len(headers)} custom headers", status="success")

    def set_cookie(self, name: str, value: str) -> None:
        """
        Set a cookie.
        
        Args:
            name: Cookie name
            value: Cookie value
        """
        self.cookies[name] = value
        self.printer.print_msg(f"Set cookie {name}: {value}", status="success")

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """
        Set multiple cookies.
        
        Args:
            cookies: Dictionary of cookie name/value pairs
        """
        self.cookies.update(cookies)
        self.printer.print_msg(f"Set {len(cookies)} cookies", status="success")

    def set_authorization(self, token: str, prefix: str = "Bearer") -> None:
        """
        Set Authorization header.
        
        Args:
            token: Authorization token
            prefix: Token type prefix (default: "Bearer")
        """
        self.headers["Authorization"] = f"{prefix} {token}" if prefix else token
        self.auth_token = token
        self.printer.print_msg(f"Set authorization token with prefix '{prefix}'", status="success")

    def clear_headers(self) -> None:
        """Reset headers to default state."""
        self.headers = {"Content-Type": "application/json"}
        self.printer.print_msg("Cleared all custom headers", status="success")

    def clear_cookies(self) -> None:
        """Remove all cookies."""
        self.cookies = {}
        self.printer.print_msg("Cleared all cookies", status="success")

    def generate_curl(self) -> str:
        """
        Generate curl command from last request for debugging and reporting.
        
        Returns:
            str: curl command that reproduces the last request
        """
        if not hasattr(self, "last_response") or not self.last_response:
            return ""

        method = self.last_response.method
        url = str(self.last_response.url)
        headers = [
            "{}:{}".format(k, v)
            for k, v in self.last_response.request_info.headers.items()
        ]
        command = ["curl", "-X", method, url]

        for header in headers:
            command.extend(["-H", f"'{header}'"])

        if hasattr(self.last_response, "_body") and self.last_response._body:
            body = (
                self.last_response._body.decode("utf-8")
                if isinstance(self.last_response._body, bytes)
                else str(self.last_response._body)
            )
            command.extend(["-d", f"'{body}'"])

        return " ".join(command)

    async def make_request(
        self, 
        method: str, 
        url: Optional[str] = None, 
        **kwargs
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Make a generic HTTP request with consistent error handling.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: URL to request (uses self.endpoint if None)
            **kwargs: Additional arguments to pass to aiohttp request
        
        Returns:
            Tuple[Optional[Dict], Optional[str]]: Tuple of (response JSON, error message)
        """
        if not url and not self.endpoint:
            error_msg = "No endpoint URL provided"
            self.printer.print_msg(error_msg, status="error")
            return None, error_msg
            
        target_url = url or self.endpoint
        
        # Prepare request kwargs with defaults
        request_kwargs = {
            "headers": self.headers,
            "cookies": self.cookies,
            "proxy": self.proxy_url,
            "ssl": False,  # Required for intercepting HTTPS
            "timeout": self.timeout
        }
        
        # Update with any additional kwargs
        request_kwargs.update(kwargs)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, target_url, **request_kwargs) as response:
                    self.last_response = response
                    
                    if response.content_type == 'application/json':
                        result = await response.json()
                        return result, None
                    else:
                        text = await response.text()
                        try:
                            # Try to parse as JSON anyway, some servers respond with wrong content type
                            return json.loads(text), None
                        except json.JSONDecodeError:
                            # If it's not JSON, return the text
                            return {"text": text}, None
                            
        except asyncio.TimeoutError:
            error_msg = f"Request to {target_url} timed out"
            self.printer.print_msg(error_msg, status="error")
            return None, error_msg
        except Exception as e:
            error_msg = f"Error making request to {target_url}: {str(e)}"
            self.printer.print_msg(error_msg, status="error")
            return None, error_msg

    async def graphql_query(
        self, 
        query: str, 
        variables: Optional[Dict] = None, 
        operation_name: Optional[str] = None
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Execute a GraphQL query with proper formatting.
        
        Args:
            query: GraphQL query string
            variables: Optional dictionary of variables
            operation_name: Optional operation name
            
        Returns:
            Tuple[Optional[Dict], Optional[str]]: Tuple of (response data, error message)
        """
        if not self.endpoint:
            error_msg = "No GraphQL endpoint set"
            self.printer.print_msg(error_msg, status="error")
            return None, error_msg
            
        payload = {"query": query}
        
        if variables:
            payload["variables"] = variables
            
        if operation_name:
            payload["operationName"] = operation_name
            
        response, error = await self.make_request("POST", json=payload)
        
        if error:
            return None, error
            
        # Extract and format any GraphQL errors
        if response and "errors" in response:
            error_msgs = []
            for error in response.get("errors", []):
                error_msgs.append(error.get("message", "Unknown GraphQL error"))
                
            if error_msgs:
                error_str = "; ".join(error_msgs)
                self.printer.print_msg(f"GraphQL errors: {error_str}", status="error")
                # Don't return error as response might still contain partial data
        
        return response, None

    async def introspection_query(self) -> bool:
        """
        Run introspection query to validate the GraphQL endpoint and cache schema info.
        
        Returns:
            bool: True if introspection succeeded
        """
        query = """
        query {
            __schema {
                queryType {
                    name
                    fields {
                        name
                        args {
                            name
                            type {
                                name
                                kind
                                ofType {
                                    name
                                    kind
                                }
                            }
                        }
                    }
                }
                mutationType {
                    name
                    fields {
                        name
                        args {
                            name
                            type {
                                name
                                kind
                                ofType {
                                    name
                                    kind
                                }
                            }
                        }
                    }
                }
                types {
                    name
                    kind
                    fields {
                        name
                        type {
                            name
                            kind
                            ofType {
                                name
                                kind
                            }
                        }
                    }
                }
            }
        }
        """

        response, error = await self.graphql_query(query)
        
        if error or not response:
            self.printer.print_msg("Introspection failed - endpoint might not be GraphQL", status="failed")
            return False
            
        schema_data = response.get("data", {}).get("__schema")
        
        if not schema_data:
            self.printer.print_msg("Introspection failed - no schema data returned", status="failed")
            return False
            
        # Cache the schema
        self.schema = schema_data
        
        # Process and store query fields
        if schema_data.get("queryType"):
            for field in schema_data["queryType"].get("fields", []):
                self.query_fields[field["name"]] = {
                    "args": field.get("args", [])
                }

        # Process and store mutation fields
        if schema_data.get("mutationType"):
            for field in schema_data["mutationType"].get("fields", []):
                self.mutation_fields[field["name"]] = {
                    "args": field.get("args", [])
                }
                
        self.printer.print_msg("Introspection successful", status="success")
        return True

    async def setup_endpoint(self, endpoint: str, proxy: Optional[str] = None) -> bool:
        """
        Set the endpoint, configure proxy if provided, and run introspection.
        
        Args:
            endpoint: The GraphQL endpoint URL
            proxy: Optional proxy string in format "host:port"
            
        Returns:
            bool: True if endpoint was set and schema retrieved successfully
        """
        self.set_endpoint(endpoint)
        
        if proxy:
            try:
                proxy_host, proxy_port = proxy.split(":")
                self.configure_proxy(proxy_host, int(proxy_port))
            except ValueError:
                self.printer.print_msg("Invalid proxy format. Expected host:port", status="error")
                return False
                
        return await self.introspection_query()

    # For testing connectivity with both direct socket and HTTP
    async def test_connectivity(self, host: str, port: int) -> bool:
        """
        Test connectivity to a target server.
        
        Args:
            host: Target hostname or IP
            port: Target port
            
        Returns:
            bool: True if connection succeeded
        """
        # First try direct socket connection
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=2)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            pass
            
        # If socket fails, try HTTP request
        try:
            test_url = f"http://{host}:{port}"
            response, error = await self.make_request("GET", test_url)
            return error is None
        except Exception:
            return False