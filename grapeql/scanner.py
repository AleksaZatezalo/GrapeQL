"""
GrapeQL Scanner Module
Author: Aleksa Zatezalo
Version: 2.0
Date: April 2025
Description: Port scanning and GraphQL endpoint discovery
"""

import asyncio
import socket
from typing import Dict, List, Optional, Tuple, Set
from .client import GraphQLClient
from .utils import GrapePrinter, load_wordlist

class Scanner:
    """
    Scanner for discovering GraphQL endpoints through port scanning and path enumeration.
    """
    
    def __init__(self):
        """Initialize the scanner with default settings."""
        self.client = GraphQLClient()
        self.printer = GrapePrinter()
        self.default_paths = [
            "/graphql",
            "/graphql/playground",
            "/graphiql",
            "/api/explorer",
            "/graphql/v1",
            "/graphql/v2",
            "/graphql/v3",
            "/api/graphql/v1",
            "/api/graphql/v2",
            "/api/public/graphql",
            "/api/private/graphql",
            "/admin/graphql",
            "/user/graphql",
        ]
        self.endpoint_paths = self.default_paths.copy()
        self.vulnerable_endpoints = []

    def set_paths(self, paths: List[str]) -> bool:
        """
        Set custom endpoint paths to scan for GraphQL.
        
        Args:
            paths: List of endpoint paths (e.g. ['/graphql', '/api/gql'])
            
        Returns:
            bool: True if paths were set successfully
        """
        try:
            cleaned_paths = []
            for path in paths:
                if not isinstance(path, str):
                    continue
                    
                # Clean and format the path
                cleaned = path.strip()
                if not cleaned.startswith('/'):
                    cleaned = '/' + cleaned
                cleaned = cleaned.rstrip('/')
                
                cleaned_paths.append(cleaned)
                
            if not cleaned_paths:
                self.printer.print_msg("No valid paths provided", status="error")
                return False
                
            self.endpoint_paths = cleaned_paths
            self.printer.print_msg(f"Set {len(cleaned_paths)} custom endpoint paths", status="success")
            return True
            
        except Exception as e:
            self.printer.print_msg(f"Error setting paths: {str(e)}", status="error")
            return False
            
    def load_paths_from_file(self, filepath: str) -> bool:
        """
        Load endpoint paths from a wordlist file.
        
        Args:
            filepath: Path to wordlist file
            
        Returns:
            bool: True if paths were loaded successfully
        """
        paths = load_wordlist(filepath)
        if not paths:
            self.printer.print_msg(f"Failed to load paths from {filepath}", status="error")
            return False
            
        return self.set_paths(paths)

    async def test_port(self, host: str, port: int) -> bool:
        """
        Test if a specific port is open on a target host.
        
        Args:
            host: Target hostname or IP
            port: Port number to test
            
        Returns:
            bool: True if port is open
        """
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=1)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, socket.gaierror):
            return False
        except Exception:
            return False

    async def scan_port_range(self, host: str, start_port: int = 1, end_port: int = 65535, 
                              chunk_size: int = 1000) -> List[int]:
        """
        Scan a range of ports on a target host.
        
        Args:
            host: Target hostname or IP
            start_port: First port to scan
            end_port: Last port to scan
            chunk_size: Number of ports to scan in parallel
            
        Returns:
            List[int]: List of open ports
        """
        open_ports = []
        
        # Scan ports in chunks to avoid creating too many tasks at once
        for chunk_start in range(start_port, end_port + 1, chunk_size):
            chunk_end = min(chunk_start + chunk_size - 1, end_port)
            
            # Create tasks for this chunk
            tasks = []
            for port in range(chunk_start, chunk_end + 1):
                tasks.append(self.test_port(host, port))
                
            # Run tasks for this chunk
            results = await asyncio.gather(*tasks)
            
            # Process results for this chunk
            for port, is_open in zip(range(chunk_start, chunk_end + 1), results):
                if is_open:
                    self.printer.print_msg(f"Port {port} is open on {host}", status="success")
                    open_ports.append(port)
                    
        return sorted(open_ports)

    async def scan_common_ports(self, host: str) -> List[int]:
        """
        Scan only common HTTP/S ports on a target host.
        
        Args:
            host: Target hostname or IP
            
        Returns:
            List[int]: List of open ports
        """
        common_ports = [80, 443, 8000, 8080, 8443, 3000, 4000, 5000, 8800, 9000]
        
        tasks = []
        for port in common_ports:
            tasks.append(self.test_port(host, port))
            
        results = await asyncio.gather(*tasks)
        
        open_ports = []
        for port, is_open in zip(common_ports, results):
            if is_open:
                self.printer.print_msg(f"Port {port} is open on {host}", status="success")
                open_ports.append(port)
                
        return open_ports

    async def check_endpoint(self, url: str) -> Optional[str]:
        """
        Check if a URL is a valid GraphQL endpoint with introspection.
        
        Args:
            url: URL to check
            
        Returns:
            Optional[str]: URL if it's a valid GraphQL endpoint, None otherwise
        """
        # Use a temporary client so we don't overwrite the main client's state
        temp_client = GraphQLClient()
        
        if await temp_client.setup_endpoint(url):
            self.printer.print_msg(f"Found GraphQL endpoint with introspection: {url}", status="warning")
            return url
        return None

    async def discover_endpoints(self, base_url: str) -> List[str]:
        """
        Discover GraphQL endpoints at a given base URL.
        
        Args:
            base_url: Base URL to scan (e.g., "http://example.com")
            
        Returns:
            List[str]: List of discovered GraphQL endpoints
        """
        valid_endpoints = []
        
        self.printer.print_section(f"Checking GraphQL endpoints at {base_url}")
        
        # Test each potential path
        tasks = []
        for path in self.endpoint_paths:
            endpoint_url = f"{base_url.rstrip('/')}{path}"
            tasks.append(self.check_endpoint(endpoint_url))
            
        results = await asyncio.gather(*tasks)
        
        # Filter out None results
        valid_endpoints = [endpoint for endpoint in results if endpoint]
        
        if valid_endpoints:
            self.printer.print_msg(
                f"Found {len(valid_endpoints)} GraphQL endpoints with introspection", 
                status="success"
            )
        else:
            self.printer.print_msg(
                "No GraphQL endpoints with introspection found", 
                status="warning"
            )
            
        return valid_endpoints

    async def scan_host(self, host: str, scan_all_ports: bool = False) -> List[str]:
        """
        Complete scan of a host: port scan and endpoint discovery.
        
        Args:
            host: Target hostname or IP
            scan_all_ports: Whether to scan all ports (True) or just common ports (False)
            
        Returns:
            List[str]: List of discovered GraphQL endpoints
        """
        self.printer.print_section(f"Starting scan of {host}")
        
        # Scan ports
        if scan_all_ports:
            self.printer.print_msg("Scanning all ports (this may take a while)...", status="log")
            open_ports = await self.scan_port_range(host)
        else:
            self.printer.print_msg("Scanning common HTTP ports...", status="log")
            open_ports = await self.scan_common_ports(host)
            
        if not open_ports:
            self.printer.print_msg("No open ports found", status="warning")
            return []
            
        # Check each port for GraphQL endpoints
        valid_endpoints = []
        for port in open_ports:
            # Check both HTTP and HTTPS
            for protocol in ["http", "https"]:
                base_url = f"{protocol}://{host}:{port}"
                endpoints = await self.discover_endpoints(base_url)
                valid_endpoints.extend(endpoints)
                
        return valid_endpoints

    async def scan_url(self, url: str) -> List[str]:
        """
        Scan a specific URL for GraphQL endpoints.
        
        Args:
            url: Target URL
            
        Returns:
            List[str]: List of discovered GraphQL endpoints
        """
        # If the URL already includes a path, just check that specific endpoint
        if '/' in url.split('://', 1)[-1]:
            result = await self.check_endpoint(url)
            return [result] if result else []
            
        # Otherwise, scan all potential paths
        return await self.discover_endpoints(url)

    async def run_scan(self, target: str, proxy: Optional[str] = None, 
                       scan_all_ports: bool = False) -> List[str]:
        """
        Main entry point for scanning a target.
        
        Args:
            target: Target hostname, IP, or URL
            proxy: Optional proxy string in format "host:port"
            scan_all_ports: Whether to scan all ports
            
        Returns:
            List[str]: List of discovered GraphQL endpoints
        """
        # Configure proxy if provided
        if proxy:
            try:
                proxy_host, proxy_port = proxy.split(":")
                self.client.configure_proxy(proxy_host, int(proxy_port))
            except ValueError:
                self.printer.print_msg("Invalid proxy format. Expected host:port", status="error")
                return []
                
        # Determine if target is a URL or host
        if target.startswith(('http://', 'https://')):
            return await self.scan_url(target)
        else:
            return await self.scan_host(target, scan_all_ports)