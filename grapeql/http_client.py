"""
Author: Aleksa Zatezalo
Version: 1.1
Date: March 2025
Description: Unified HTTP client for GraphQL requests with proper session handling
"""

import aiohttp
import asyncio
from typing import Dict, List, Optional, Any, Tuple, Union
from grapeql.headers_manager import HeadersManager
import json
import time
import functools
import atexit


class GraphQLClient:
    """
    A unified HTTP client for making GraphQL requests with support for 
    headers, cookies, proxies, and request caching.
    """
    
    def __init__(self):
        """Initialize the GraphQL client with default settings."""
        self.endpoint: Optional[str] = None
        self.proxy_url: Optional[str] = None
        self.headers_manager = HeadersManager()
        self.last_response = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._request_cache = {}
        self._session_lock = asyncio.Lock()
        
        # Register cleanup function to ensure sessions are closed
        atexit.register(self._cleanup)
        
    def _cleanup(self):
        """Cleanup resources when the program exits."""
        if self._session and not self._session.closed:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.close())
            else:
                loop.run_until_complete(self.close())
        
    def set_endpoint(self, endpoint: str) -> None:
        """
        Set the GraphQL endpoint URL.
        
        Args:
            endpoint: The GraphQL endpoint URL
        """
        self.endpoint = endpoint
        # Clear cache when endpoint changes
        self._request_cache.clear()
        
    def configure_proxy(self, proxy_host: str, proxy_port: int) -> None:
        """
        Configure HTTP proxy settings.
        
        Args:
            proxy_host: The proxy server hostname or IP
            proxy_port: The proxy server port
        """
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"
        
    def set_proxy_from_string(self, proxy_string: Optional[str]) -> bool:
        """
        Set proxy from a string in format "host:port".
        
        Args:
            proxy_string: Proxy string in format "host:port"
            
        Returns:
            bool: True if proxy was set successfully, False otherwise
        """
        if not proxy_string:
            return True
            
        try:
            proxy_host, proxy_port = proxy_string.split(":")
            self.configure_proxy(proxy_host, int(proxy_port))
            return True
        except ValueError:
            return False
    
    def get_headers(self) -> Dict[str, str]:
        """Get all headers."""
        return self.headers_manager.get_all_headers()
    
    def get_cookies(self) -> Dict[str, str]:
        """Get all cookies."""
        return self.headers_manager.get_all_cookies()
    
    def set_header(self, name: str, value: str) -> None:
        """Set a single header."""
        self.headers_manager.add_header(name, value)
        
    def set_headers(self, headers: Dict[str, str]) -> None:
        """Set multiple headers."""
        self.headers_manager.add_headers(headers)
        
    def set_cookie(self, name: str, value: str) -> None:
        """Set a single cookie."""
        self.headers_manager.add_cookie(name, value)
        
    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Set multiple cookies."""
        self.headers_manager.add_cookies(cookies)
        
    def set_authorization(self, token: str, prefix: str = "Bearer") -> None:
        """Set authorization header."""
        self.headers_manager.set_authorization(token, prefix)
        
    def clear_headers(self) -> None:
        """Clear all headers."""
        self.headers_manager.clear_headers()
        
    def clear_cookies(self) -> None:
        """Clear all cookies."""
        self.headers_manager.clear_cookies()
    
    def _get_cache_key(self, method: str, url: str, data: Any = None, **kwargs) -> str:
        """
        Generate a cache key for a request.
        
        Args:
            method: HTTP method
            url: Request URL
            data: Request data
            **kwargs: Additional request parameters
            
        Returns:
            str: Cache key
        """
        # Create a string representation of the request
        key_parts = [method, url]
        
        if data:
            if isinstance(data, dict):
                key_parts.append(json.dumps(data, sort_keys=True))
            else:
                key_parts.append(str(data))
                
        # Add relevant kwargs to the cache key
        for k in sorted(kwargs.keys()):
            if k in ('headers', 'cookies', 'params'):
                if isinstance(kwargs[k], dict):
                    key_parts.append(f"{k}:{json.dumps(kwargs[k], sort_keys=True)}")
                else:
                    key_parts.append(f"{k}:{kwargs[k]}")
                
        return ":".join(key_parts)
    
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
    
    async def request(
        self, 
        method: str, 
        url: Optional[str] = None, 
        use_cache: bool = False,
        **kwargs
    ) -> Dict:
        """
        Make an HTTP request.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL (if None, uses self.endpoint)
            use_cache: Whether to use request caching
            **kwargs: Additional parameters to pass to aiohttp request
            
        Returns:
            Dict: Response data as JSON
        """
        if url is None:
            if self.endpoint is None:
                raise ValueError("No endpoint set. Call set_endpoint first.")
            url = self.endpoint
        
        # Add headers and cookies from the headers manager
        headers = kwargs.pop('headers', {})
        cookies = kwargs.pop('cookies', {})
        
        # Merge with headers from headers_manager
        all_headers = self.get_headers()
        all_headers.update(headers)
        
        # Merge with cookies from headers_manager
        all_cookies = self.get_cookies()
        all_cookies.update(cookies)
        
        # Check if request is in cache
        if use_cache:
            cache_key = self._get_cache_key(
                method, url, kwargs.get('json', kwargs.get('data')), 
                headers=all_headers, cookies=all_cookies
            )
            if cache_key in self._request_cache:
                return self._request_cache[cache_key]
        
        timeout = kwargs.pop('timeout', 30)
        if isinstance(timeout, (int, float)):
            timeout = aiohttp.ClientTimeout(total=timeout)
            
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
                # Store the response for reference (e.g., for curl generation)
                self.last_response = response
                
                # Parse response as JSON if possible
                try:
                    result = await response.json()
                except (aiohttp.ContentTypeError, ValueError):
                    # Fallback to text if not JSON
                    text = await response.text()
                    result = {"text": text, "status": response.status}
                
                # Cache the result if caching is enabled
                if use_cache:
                    self._request_cache[cache_key] = result
                    
                return result
        except Exception as e:
            # Return error as a structured response
            error_response = {
                "errors": [{"message": str(e)}],
                "status": "error"
            }
            return error_response
    
    async def graphql(
        self, 
        query: str, 
        variables: Optional[Dict] = None, 
        operation_name: Optional[str] = None,
        method: str = "POST",
        use_cache: bool = False
    ) -> Dict:
        """
        Make a GraphQL request.
        
        Args:
            query: GraphQL query string
            variables: Optional variables for the query
            operation_name: Optional operation name
            method: HTTP method to use (default: POST)
            use_cache: Whether to use request caching
            
        Returns:
            Dict: GraphQL response
        """
        if self.endpoint is None:
            raise ValueError("No endpoint set. Call set_endpoint first.")
        
        # Build the payload
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name
            
        # Make the request
        if method.upper() == "GET":
            # For GET requests, variables need to be serialized
            params = {"query": query}
            if variables:
                params["variables"] = json.dumps(variables)
            if operation_name:
                params["operationName"] = operation_name
                
            return await self.request(
                "GET", 
                self.endpoint, 
                params=params,
                use_cache=use_cache
            )
        else:
            # For POST requests, send as JSON
            return await self.request(
                "POST", 
                self.endpoint, 
                json=payload,
                use_cache=use_cache
            )
    
    def generate_curl(self) -> str:
        """
        Generate a curl command from the last request.
        
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
        
        # Build the curl command
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
    
    # Common GraphQL operations
    
    async def introspection_schema(self) -> Dict:
        """
        Run a basic introspection query to get schema information.
        
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
                                ofType {
                                    name
                                    kind
                                }
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
        return await self.graphql(query, use_cache=True)
    
    async def simple_introspection(self) -> Dict:
        """
        Run a minimal introspection query to check if introspection is enabled.
        
        Returns:
            Dict: Response indicating if introspection is enabled
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
        return await self.graphql(query, use_cache=True)
        
    async def has_introspection(self) -> bool:
        """
        Check if the endpoint has introspection enabled.
        
        Returns:
            bool: True if introspection is enabled, False otherwise
        """
        result = await self.simple_introspection()
        return bool(result.get("data", {}).get("__schema"))