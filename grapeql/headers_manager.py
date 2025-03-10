"""
Author: Aleksa Zatezalo
Version: 1.0
Date: March 2025
Description: Module to extend base class with custom headers and cookies support.
"""

from typing import Dict, Optional

class HeadersManager:
    """
    A class for managing custom headers and cookies for GraphQL requests.
    """
    
    def __init__(self):
        """Initialize with default headers."""
        self.headers = {"Content-Type": "application/json"}
        self.cookies = {}
    
    def add_header(self, name: str, value: str) -> None:
        """
        Add a custom header.
        
        Args:
            name: Header name
            value: Header value
        """
        self.headers[name] = value
    
    def add_headers(self, headers: Dict[str, str]) -> None:
        """
        Add multiple custom headers.
        
        Args:
            headers: Dictionary of header name/value pairs
        """
        self.headers.update(headers)
    
    def remove_header(self, name: str) -> None:
        """
        Remove a header if it exists.
        
        Args:
            name: Header name to remove
        """
        if name in self.headers:
            del self.headers[name]
    
    def clear_headers(self) -> None:
        """Reset headers to default state with just Content-Type."""
        self.headers = {"Content-Type": "application/json"}
    
    def add_cookie(self, name: str, value: str) -> None:
        """
        Add a cookie.
        
        Args:
            name: Cookie name
            value: Cookie value
        """
        self.cookies[name] = value
    
    def add_cookies(self, cookies: Dict[str, str]) -> None:
        """
        Add multiple cookies.
        
        Args:
            cookies: Dictionary of cookie name/value pairs
        """
        self.cookies.update(cookies)
    
    def remove_cookie(self, name: str) -> None:
        """
        Remove a cookie if it exists.
        
        Args:
            name: Cookie name to remove
        """
        if name in self.cookies:
            del self.cookies[name]
    
    def clear_cookies(self) -> None:
        """Remove all cookies."""
        self.cookies = {}
    
    def set_authorization(self, token: str, prefix: str = "Bearer") -> None:
        """
        Set Authorization header with optional prefix.
        
        Args:
            token: Authorization token
            prefix: Token type prefix (default: "Bearer")
        """
        self.headers["Authorization"] = f"{prefix} {token}" if prefix else token
    
    def get_all_headers(self) -> Dict[str, str]:
        """
        Get all headers.
        
        Returns:
            Dict[str, str]: All headers
        """
        return self.headers
    
    def get_all_cookies(self) -> Dict[str, str]:
        """
        Get all cookies.
        
        Returns:
            Dict[str, str]: All cookies
        """
        return self.cookies