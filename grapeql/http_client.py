"""
HTTP client for GraphQL requests

Author: Aleksa Zatezalo
Version: 3.0
"""

import aiohttp
import asyncio
from typing import Dict, List, Optional, Any, Union
import json
import atexit
import shutil


class GraphQLHTTPClient:
    """
    An HTTP client for making GraphQL requests with proper resource management.
    """
    
    def __init__(self):
        """Initialize with default settings."""
        self.endpoint: Optional[str] = None
        self.proxy_url: Optional[str] = None
        self.headers: Dict[str, str] = {"Content-Type": "application/json"}
        self.cookies: Dict[str, str] = {}
        self.last_response = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()
        
        # Register cleanup function
        atexit.register(self._cleanup)
        
    def _cleanup(self):
        """Cleanup resources when the program exits."""
        if self._session and not self._session.closed:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.close())
            else:
                loop.run_until_complete(self.close())
    
    async def ensure_session(self):
        """Ensure an aiohttp client session exists."""
        async with self._session_lock:
            if self._session is None or self._session.closed:
                self._session = aiohttp.ClientSession()
            return self._session
    
    async def close(self):
        """Close the aiohttp client session."""
        async with self._session_lock:
            if self._session and not self._session.closed:
                await self._session.close()
                self._session = None
    
    # Endpoint and proxy configuration
    
    def set_endpoint(self, endpoint: str) -> None:
        """Set the GraphQL endpoint URL."""
        self.endpoint = endpoint
    
    def configure_proxy(self, proxy_host: str, proxy_port: int) -> None:
        """Configure HTTP proxy settings."""
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"
    
    def set_proxy_from_string(self, proxy_string: Optional[str]) -> bool:
        """Set proxy from a string in format 'host:port'."""
        if not proxy_string:
            self.proxy_url = None
            return True
            
        try:
            proxy_host, proxy_port = proxy_string.split(":")
            self.configure_proxy(proxy_host, int(proxy_port))
            return True
        except ValueError:
            return False
    
    # Header and cookie management
    
    def set_header(self, name: str, value: str) -> None:
        """Set a single header."""
        self.headers[name] = value
    
    def set_headers(self, headers: Dict[str, str]) -> None:
        """Set multiple headers."""
        self.headers.update(headers)
    
    def set_cookie(self, name: str, value: str) -> None:
        """Set a single cookie."""
        self.cookies[name] = value
    
    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Set multiple cookies."""
        self.cookies.update(cookies)
    
    def set_authorization(self, token: str, prefix: str = "Bearer") -> None:
        """Set authorization header."""
        self.headers["Authorization"] = f"{prefix} {token}" if prefix else token
    
    def clear_headers(self) -> None:
        """Clear all headers except Content-Type."""
        self.headers = {"Content-Type": "application/json"}
    
    def clear_cookies(self) -> None:
        """Clear all cookies."""
        self.cookies = {}
    
    # HTTP request methods
    
    async def request(
        self, 
        method: str, 
        url: Optional[str] = None, 
        **kwargs
    ) -> Dict:
        """
        Make an HTTP request.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL (if None, uses self.endpoint)
            **kwargs: Additional parameters for aiohttp request
            
        Returns:
            Dict: Response data
        """
        if url is None:
            if self.endpoint is None:
                raise ValueError("No endpoint set. Call set_endpoint first.")
            url = self.endpoint
        
        # Add headers and cookies
        headers = kwargs.pop('headers', {})
        cookies = kwargs.pop('cookies', {})
        
        # Merge with instance headers/cookies
        all_headers = dict(self.headers)
        all_headers.update(headers)
        
        all_cookies = dict(self.cookies)
        all_cookies.update(cookies)
        
        # Set timeout
        timeout = kwargs.pop('timeout', 30)
        if isinstance(timeout, (int, float)):
            timeout = aiohttp.ClientTimeout(total=timeout)
        
        # Get or create session
        session = await self.ensure_session()
        
        try:
            async with session.request(
                method,
                url,
                headers=all_headers,
                cookies=all_cookies,
                proxy=self.proxy_url,
                ssl=False,
                timeout=timeout,
                **kwargs
            ) as response:
                # Store for reference
                self.last_response = response
                
                # Parse response
                try:
                    result = await response.json()
                except (aiohttp.ContentTypeError, ValueError):
                    # Fallback to text
                    text = await response.text()
                    result = {"text": text, "status": response.status}
                    
                return result
        except asyncio.TimeoutError:
            return {"errors": [{"message": "Request timed out"}], "status": "timeout"}
        except Exception as e:
            return {"errors": [{"message": str(e)}], "status": "error"}
    
    async def graphql(
        self, 
        query: str, 
        variables: Optional[Dict] = None, 
        operation_name: Optional[str] = None,
        method: str = "POST"
    ) -> Dict:
        """
        Make a GraphQL request.
        
        Args:
            query: GraphQL query string
            variables: Optional variables for the query
            operation_name: Optional operation name
            method: HTTP method to use (default: POST)
            
        Returns:
            Dict: GraphQL response
        """
        if self.endpoint is None:
            raise ValueError("No endpoint set. Call set_endpoint first.")
        
        # Build payload
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name
        
        # Make request based on method
        if method.upper() == "GET":
            # For GET, use query parameters
            params = {"query": query}
            if variables:
                params["variables"] = json.dumps(variables)
            if operation_name:
                params["operationName"] = operation_name
                
            return await self.request("GET", params=params)
        else:
            # For POST, send as JSON
            return await self.request("POST", json=payload)
    
    async def introspection_query(self) -> Dict:
        """
        Run a simple introspection query to get schema information.
        
        Returns:
            Dict: Schema information or error
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
                            }
                        }
                    }
                }
                types {
                    name
                    kind
                    fields {
                        name
                        args {
                            name
                            type {
                                name
                                kind
                            }
                        }
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
        return await self.graphql(query)
    
    async def has_introspection(self) -> bool:
        """
        Check if introspection is enabled on the endpoint.
        
        Returns:
            bool: True if introspection is enabled
        """
        query = """
        query {
            __schema {
                queryType {
                    name
                }
            }
        }
        """
        result = await self.graphql(query)
        return bool(result.get("data", {}).get("__schema"))
    
    def generate_curl(self) -> str:
        """
        Generate a curl command for the last request.
        
        Returns:
            str: curl command
        """
        if not hasattr(self, "last_response") or self.last_response is None:
            return "No request has been made yet."
        
        response = self.last_response
        method = response.method
        url = str(response.url)
        
        # Extract headers
        headers = []
        for k, v in response.request_info.headers.items():
            headers.append(f"{k}: {v}")
        
        # Build command
        command = ["curl", "-X", method]
        
        for header in headers:
            command.extend(["-H", f"'{header}'"])
            
        if hasattr(response, "_body") and response._body:
            body = (
                response._body.decode("utf-8")
                if isinstance(response._body, bytes)
                else str(response._body)
            )
            command.extend(["-d", f"'{body}'"])
            
        command.append(url)
            
        return " ".join(command)