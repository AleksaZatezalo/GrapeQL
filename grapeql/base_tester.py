"""
Author: Aleksa Zatezalo
Version: 1.1
Date: March 2025
Description: Base class for GraphQL security testers with proper session handling
"""

import asyncio
from typing import Dict, List, Optional, Any, Tuple
from .grapePrint import grapePrint
from .http_client import GraphQLClient
from .schema_manager import SchemaManager

class BaseTester:
    """
    Base class for GraphQL security testing.
    Provides common functionality for all testing modules with proper resource management.
    """
    
    def __init__(self):
        """Initialize with default settings."""
        self.message = grapePrint()
        self.client = GraphQLClient()
        self.schema_manager = SchemaManager(self.client)
        self.username: Optional[str] = "admin"
        self.password: Optional[str] = "changeme"
        self.auth_token: Optional[str] = None
        self.debug_mode = False
    
    def set_debug_mode(self, debug_mode: bool = True) -> None:
        """
        Enable or disable debug mode.
        
        Args:
            debug_mode: Whether to enable debug mode
        """
        self.debug_mode = debug_mode
        
    def set_header(self, name: str, value: str) -> None:
        """
        Set a custom header.
        
        Args:
            name: Header name
            value: Header value
        """
        self.client.set_header(name, value)
        self.message.printMsg(f"Set header {name}: {value}", status="success")
        
    def set_headers(self, headers: Dict[str, str]) -> None:
        """
        Set multiple custom headers.
        
        Args:
            headers: Dictionary of header name/value pairs
        """
        self.client.set_headers(headers)
        
    def set_cookie(self, name: str, value: str) -> None:
        """
        Set a cookie.
        
        Args:
            name: Cookie name
            value: Cookie value
        """
        self.client.set_cookie(name, value)
        self.message.printMsg(f"Set cookie {name}: {value}", status="success")
        
    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """
        Set multiple cookies.
        
        Args:
            cookies: Dictionary of cookie name/value pairs
        """
        self.client.set_cookies(cookies)
        
    def set_authorization(self, token: str, prefix: str = "Bearer") -> None:
        """
        Set Authorization header with token.
        
        Args:
            token: Authorization token
            prefix: Token type prefix (default: "Bearer")
        """
        self.client.set_authorization(token, prefix)
        self.auth_token = token
        self.message.printMsg(f"Set authorization token with prefix '{prefix}'", status="success")
        
    def clear_headers(self) -> None:
        """Reset headers to default state."""
        self.client.clear_headers()
        self.message.printMsg("Cleared all custom headers", status="success")
        
    def clear_cookies(self) -> None:
        """Remove all cookies."""
        self.client.clear_cookies()
        self.message.printMsg("Cleared all cookies", status="success")
    
    def set_credentials(self, username: str, password: str) -> None:
        """
        Set credentials for authentication testing.
        
        Args:
            username: Username
            password: Password
        """
        self.username = username
        self.password = password
        self.message.printMsg(
            f"Set credentials to {username}:{password} for testing",
            status="success",
        )
        
    def configure_proxy(self, proxy_host: str, proxy_port: int) -> None:
        """
        Configure HTTP proxy settings.
        
        Args:
            proxy_host: Proxy host
            proxy_port: Proxy port
        """
        self.client.configure_proxy(proxy_host, proxy_port)
        
    async def set_endpoint(self, endpoint: str, proxy: Optional[str] = None) -> bool:
        """
        Set the endpoint and retrieve its schema.
        
        Args:
            endpoint: GraphQL endpoint URL
            proxy: Optional proxy string in format "host:port"
            
        Returns:
            bool: True if endpoint was set and schema retrieved successfully
        """
        # Set the endpoint in the client
        self.client.set_endpoint(endpoint)
        
        # Configure proxy if provided
        if proxy and not self.client.set_proxy_from_string(proxy):
            self.message.printMsg(
                "Invalid proxy format. Expected host:port", 
                status="error"
            )
            return False
            
        # Check if introspection is enabled
        has_introspection = await self.client.has_introspection()
        
        if has_introspection:
            # Load the full schema
            if await self.schema_manager.load_schema():
                return True
                
        self.message.printMsg(
            "Introspection failed - endpoint might not be GraphQL or introspection is disabled",
            status="error"
        )
        return False
    
    def generate_curl(self) -> str:
        """
        Generate a curl command for the last request.
        
        Returns:
            str: curl command
        """
        return self.client.generate_curl()
    
    async def close(self) -> None:
        """
        Clean up resources by closing the HTTP client.
        This should be called at the end of testing.
        """
        await self.client.close()