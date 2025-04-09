"""
Author: Aleksa Zatezalo
Version: 2.1
Date: March 2025
Description: Optimized enumeration script for GraphQL endpoints with improved performance.
"""

import asyncio
import aiohttp
import socket
from typing import Dict, List, Optional, Set, Tuple
from grapePrint import grapePrint
from http_client import GraphQLClient
import time


class vine:
    """
    A class for discovering GraphQL endpoints through port scanning and directory enumeration.
    Supports proxying HTTP traffic through a proxy while performing direct port scans.
    """

    def __init__(self):
        """
        Initialize the vine class with default settings and API endpoints list.
        """
        self.message = grapePrint()
        self.client = GraphQLClient()
        self.default_api_paths = [
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
        self.api_paths = self.default_api_paths.copy()
        # Configurable parameters
        self.max_concurrent_scans = 50  # Maximum concurrent directory requests
        self.chunk_size = 5000  # Port scan chunk size
        self.port_scan_timeout = 0.5  # Port scan connection timeout
        self.dirb_timeout = 5  # Directory busting timeout
        self.common_ports = [80, 443, 8080, 8443, 3000, 4000, 5013, 8000, 8888]  # Common ports to prioritize

    def set_header(self, name: str, value: str) -> None:
        """Set a custom header."""
        self.client.set_header(name, value)
        self.message.printMsg(f"Set header {name}: {value}", status="success")

    def set_headers(self, headers: Dict[str, str]) -> None:
        """Set multiple custom headers."""
        self.client.set_headers(headers)

    def set_cookie(self, name: str, value: str) -> None:
        """Set a custom cookie."""
        self.client.set_cookie(name, value)
        self.message.printMsg(f"Set cookie {name}: {value}", status="success")

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Set multiple custom cookies."""
        self.client.set_cookies(cookies)

    def set_authorization(self, token: str, prefix: str = "Bearer") -> None:
        """Set authorization header."""
        self.client.set_authorization(token, prefix)
        self.message.printMsg(f"Set authorization token with prefix '{prefix}'", status="success")

    def setApiList(self, endpoints: List[str]) -> bool:
        """
        Set a custom list of API endpoints to scan.

        Args:
            endpoints: List of endpoint paths to scan (e.g., ['/graphql', '/api/graphql'])

        Returns:
            bool: True if endpoints were set successfully, False otherwise
        """
        try:
            # Validate input is a list
            if not isinstance(endpoints, list):
                self.message.printMsg(
                    "Error: Endpoints must be provided as a list", status="error"
                )
                return False

            # Validate and clean each endpoint
            cleaned_endpoints = []
            for endpoint in endpoints:
                # Check if endpoint is a string
                if not isinstance(endpoint, str):
                    self.message.printMsg(
                        f"Warning: Skipping invalid endpoint: {endpoint}",
                        status="warning",
                    )
                    continue

                # Clean the endpoint
                cleaned = endpoint.strip()

                # Ensure endpoint starts with /
                if not cleaned.startswith("/"):
                    cleaned = "/" + cleaned

                # Remove any trailing slashes
                cleaned = cleaned.rstrip("/")

                cleaned_endpoints.append(cleaned)

            # Check if we have any valid endpoints
            if not cleaned_endpoints:
                self.message.printMsg(
                    "Error: No valid endpoints provided", status="error"
                )
                return False

            # Set the new API list
            self.api_paths = cleaned_endpoints
            self.message.printMsg(
                f"Successfully set {len(cleaned_endpoints)} endpoints", status="success"
            )
            return True

        except Exception as e:
            self.message.printMsg(f"Error setting API list: {str(e)}", status="error")
            return False

    def configureProxy(self, proxy_host: str, proxy_port: int) -> None:
        """
        Configure the HTTP proxy settings.

        Args:
            proxy_host: The proxy server hostname or IP
            proxy_port: The proxy server port
        """
        self.client.configure_proxy(proxy_host, proxy_port)

    async def testPortNumber(self, host: str, port: int) -> Tuple[int, bool]:
        """
        Test if a specific port is open on the target host (direct connection, no proxy).

        Args:
            host: The target hostname or IP address
            port: The port number to test

        Returns:
            Tuple[int, bool]: Port number and whether it's open
        """
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.port_scan_timeout)
            writer.close()
            await writer.wait_closed()
            return port, True
        except:
            return port, False

    async def prioritized_port_scan(self, host: str) -> List[int]:
        """
        Optimized port scanning with prioritization of common ports.
        
        Args:
            host: The target hostname or IP address
        
        Returns:
            List[int]: List of open ports
        """
        # First scan common ports
        common_port_tasks = [self.testPortNumber(host, port) for port in self.common_ports]
        common_results = await asyncio.gather(*common_port_tasks)
        
        # Filter open common ports
        open_ports = [port for port, is_open in common_results if is_open]
        
        # If we've found ports in the common list, we can skip the full scan to save time
        if open_ports:
            self.message.printMsg(f"Found {len(open_ports)} open common ports, skipping full scan", status="success")
            for port in open_ports:
                self.message.printMsg(f"{host}:{port} [OPEN]")
            return open_ports
        
        self.message.printMsg("No common ports open, performing selective scan", status="log")
        
        # Selective port ranges to scan based on common web services
        port_ranges = [
            (80, 90),    # HTTP/S
            (443, 450),  # HTTPS
            (3000, 3010), # Development servers
            (4000, 4010), # Development servers
            (8000, 8100), # Common web ports
            (8443, 8453), # HTTPS alt
        ]
        
        all_open_ports = []
        for start, end in port_ranges:
            tasks = [self.testPortNumber(host, port) for port in range(start, end + 1)]
            results = await asyncio.gather(*tasks)
            range_open_ports = [port for port, is_open in results if is_open]
            all_open_ports.extend(range_open_ports)
            
            # Print results for this range
            for port in range_open_ports:
                self.message.printMsg(f"{host}:{port} [OPEN]")
        
        return all_open_ports

    async def dirb(self, base_url: str, path: str) -> Optional[str]:
        """
        Test a single endpoint path for existence on the target URL.
        Filters out WebSocket endpoints.

        Args:
            base_url: The base URL to test against
            path: The endpoint path to append to the base URL

        Returns:
            Optional[str]: Full URL if endpoint exists and is not a WebSocket endpoint, None otherwise
        """
        full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        
        try:
            # Set the URL for this request only, without changing the client's endpoint
            result = await self.client.request(
                "GET", 
                full_url, 
                timeout=self.dirb_timeout,
                use_cache=True  # Enable caching to avoid duplicate requests
            )
            
            # Inspect the response status
            status = result.get("status")
            if status == 404:
                return None
                
            # Check for WebSocket indication
            response_text = result.get("text", "")
            if "WebSockets request was expected" in response_text:
                return None
                
            # Check for GraphQL indicators in the response
            graphql_indicators = ["graphql", "apollo", "playground", "__schema"]
            for indicator in graphql_indicators:
                if indicator.lower() in str(response_text).lower():
                    self.message.printMsg(f"Potential GraphQL endpoint found: {full_url}", status="success")
                    return full_url
                
            return full_url
                
        except Exception as e:
            return None

    async def batch_dirb(self, base_url: str, paths: List[str]) -> List[str]:
        """
        Test a batch of endpoint paths concurrently.
        
        Args:
            base_url: The base URL to test against
            paths: List of paths to test
            
        Returns:
            List[str]: List of valid URLs
        """
        tasks = []
        for path in paths:
            task = self.dirb(base_url, path)
            tasks.append(task)
            
        results = await asyncio.gather(*tasks)
        return [url for url in results if url]

    async def scanEndpoints(self, base_url: str) -> List[str]:
        """
        Scan all API endpoints with optimized concurrency.

        Args:
            base_url: The base URL to test endpoints against

        Returns:
            List[str]: List of valid endpoint URLs found
        """
        # Split API paths into batches for controlled concurrency
        results = []
        
        # Use a semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(self.max_concurrent_scans)
        
        async def scan_with_semaphore(path):
            async with semaphore:
                return await self.dirb(base_url, path)
        
        # Create tasks for all paths
        tasks = [scan_with_semaphore(path) for path in self.api_paths]
        
        # Run all tasks concurrently but with controlled parallelism
        batch_results = await asyncio.gather(*tasks)
        
        # Filter out None values
        return [url for url in batch_results if url]

    async def constructAddress(self, ip: str) -> List[str]:
        """
        Construct full URLs for open ports on a target IP with optimized scanning.

        Args:
            ip: The target IP address

        Returns:
            List[str]: List of URLs constructed from open ports
        """
        self.message.printMsg("Beginning Optimized Port Scan", status="success")
        open_ports = await self.prioritized_port_scan(host=ip)
        
        # If no ports found, try additional port ranges 
        if not open_ports:
            self.message.printMsg("No ports found in initial scan, checking additional ranges", status="log")
            time.sleep(1)
            
            # Scan top 1000 ports in chunks for better performance
            additional_ranges = [
                (1, 1000),       # Top 1000 common ports
                (7000, 7100),    # Additional ranges likely to have web servers
                (9000, 9100)
            ]
            
            for start, end in additional_ranges:
                self.message.printMsg(f"Scanning port range {start}-{end}", status="log")
                chunk_size = 100  # Smaller chunks for better feedback
                for chunk_start in range(start, end + 1, chunk_size):
                    chunk_end = min(chunk_start + chunk_size - 1, end)
                    
                    # Create tasks for this chunk
                    tasks = [self.testPortNumber(ip, port) for port in range(chunk_start, chunk_end + 1)]
                    results = await asyncio.gather(*tasks)
                    
                    # Find open ports in this chunk
                    chunk_open_ports = [port for port, is_open in results if is_open]
                    if chunk_open_ports:
                        for port in chunk_open_ports:
                            self.message.printMsg(f"{ip}:{port} [OPEN]")
                        open_ports.extend(chunk_open_ports)
        
        # Convert ports to URLs
        return [f"http://{ip}:{port}" for port in open_ports]

    async def dirbList(self, valid_endpoints: List[str]) -> List[str]:
        """
        Perform directory busting on a list of endpoints with optimized concurrency.

        Args:
            valid_endpoints: List of base URLs to test

        Returns:
            List[str]: List of all valid URLs found
        """
        if not valid_endpoints:
            self.message.printMsg("No valid endpoints found for directory busting", status="warning")
            return []
            
        self.message.printMsg(f"Started directory busting against {len(valid_endpoints)} endpoints", status="success")
        
        # Progress feedback
        total_endpoints = len(valid_endpoints)
        completed = 0
        start_time = time.time()
        
        # Process each base URL with optimized scanning
        all_valid_urls = []
        
        for endpoint in valid_endpoints:
            self.message.printMsg(f"Scanning endpoint {endpoint} ({completed+1}/{total_endpoints})", status="log")
            found_urls = await self.scanEndpoints(endpoint)
            
            for url in found_urls:
                self.message.printMsg(f"Found URL at {url}")
                all_valid_urls.append(url)
                
            completed += 1
            elapsed = time.time() - start_time
            avg_time = elapsed / completed if completed > 0 else 0
            remaining = avg_time * (total_endpoints - completed)
            
            # Only show timing updates for multiple endpoints
            if total_endpoints > 1:
                self.message.printMsg(
                    f"Progress: {completed}/{total_endpoints} endpoints scanned. " +
                    f"Est. {int(remaining)} seconds remaining.", 
                    status="log"
                )
        
        self.message.printMsg(
            f"Directory busting completed. Found {len(all_valid_urls)} potential GraphQL endpoints.",
            status="log"
        )
        return all_valid_urls

    async def checkEndpoint(self, endpoint: str) -> Optional[str]:
        """
        Test a single endpoint for GraphQL introspection vulnerability.

        Args:
            endpoint: The endpoint URL to test

        Returns:
            Optional[str]: Endpoint URL if vulnerable, None otherwise
        """
        # Set the endpoint temporarily for this test
        self.client.set_endpoint(endpoint)
        
        # Check if introspection is enabled
        if await self.client.has_introspection():
            self.message.printMsg(f"Introspection enabled: {endpoint}", status="warning")
            return endpoint
            
        return None

    async def introspection(self, endpoints: List[str]) -> List[str]:
        """
        Test multiple endpoints for GraphQL introspection vulnerability with optimized concurrency.

        Args:
            endpoints: List of endpoints to test

        Returns:
            List[str]: List of vulnerable endpoints with introspection enabled
        """
        if not endpoints:
            self.message.printMsg("No endpoints to test for introspection", status="warning")
            return []
            
        self.message.printMsg(f"Testing {len(endpoints)} endpoints for introspection", status="success")
        
        # Use a semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(min(len(endpoints), 10))  # Max 10 concurrent tests
        
        async def check_with_semaphore(endpoint):
            async with semaphore:
                return await self.checkEndpoint(endpoint)
        
        # Create tasks with semaphore
        tasks = [check_with_semaphore(endpoint) for endpoint in endpoints]
        
        # Run all tasks concurrently but with controlled parallelism
        results = await asyncio.gather(*tasks)
        
        # Filter valid results
        vulnerable_endpoints = [endpoint for endpoint in results if endpoint]
        
        if vulnerable_endpoints:
            self.message.printMsg(
                f"Found {len(vulnerable_endpoints)} GraphQL endpoints with introspection enabled",
                status="log"
            )
        else:
            self.message.printMsg("No GraphQL endpoints with introspection found", status="warning")
            
        return vulnerable_endpoints

    def validate_proxy(self, proxy_host: str, proxy_port: int) -> bool:
        """
        Validate that proxy is accessible.

        Args:
            proxy_host: The proxy server hostname or IP
            proxy_port: The proxy server port

        Returns:
            bool: True if proxy is valid and accessible, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((proxy_host, proxy_port))
            sock.close()
            return True
        except Exception as e:
            self.message.printMsg(
                f"Proxy validation failed: {str(e)}", status="error"
            )
            return False

    async def test(self, proxy_string: str = None, target_ip: str = None) -> List[str]:
        """
        Main execution function that coordinates the scanning process with optimized performance.

        Args:
            proxy_string: Optional string containing proxy host and port in format "host:port"
            target_ip: Target IP address to scan

        Returns:
            List[str]: List of vulnerable GraphQL endpoints found
        """
        try:
            # Configure proxy if provided
            if proxy_string:
                try:
                    proxy_host, proxy_port_str = proxy_string.split(":")
                    proxy_port = int(proxy_port_str)

                    # Validate and configure proxy
                    if not self.validate_proxy(proxy_host, proxy_port):
                        self.message.printMsg(
                            "Cannot connect to proxy. Please ensure proxy is running and settings are correct.",
                            status="error",
                        )
                        return []

                    self.configureProxy(proxy_host, proxy_port)
                except ValueError:
                    self.message.printMsg(
                        "Invalid proxy string format. Expected format: host:port",
                        status="error",
                    )
                    return []

            # Perform scan using provided target IP with optimized methods
            start_time = time.time()
            valid_endpoints = await self.constructAddress(target_ip)
            port_scan_time = time.time() - start_time
            
            self.message.printMsg(
                f"Port scan completed in {port_scan_time:.1f} seconds. Found {len(valid_endpoints)} open ports.",
                status="success"
            )
            
            if not valid_endpoints:
                self.message.printMsg("No open ports found. Scan cannot continue.", status="error")
                return []
                
            # Perform directory busting
            start_time = time.time()
            url_list = await self.dirbList(valid_endpoints)
            dirb_time = time.time() - start_time
            
            self.message.printMsg(
                f"Directory busting completed in {dirb_time:.1f} seconds.",
                status="success"
            )
            
            if not url_list:
                self.message.printMsg("No potential GraphQL endpoints found.", status="warning")
                return []
                
            # Test for introspection
            start_time = time.time()
            vulnerable_endpoints = await self.introspection(url_list)
            introspection_time = time.time() - start_time
            
            self.message.printMsg(
                f"Introspection testing completed in {introspection_time:.1f} seconds.",
                status="success"
            )
            
            # Summary
            self.message.printMsg(
                f"Scan summary: Found {len(vulnerable_endpoints)} vulnerable GraphQL endpoints out of {len(url_list)} tested.",
                status="success"
            )
            
            return vulnerable_endpoints

        except Exception as e:
            self.message.printMsg(f"Error during scan: {str(e)}", status="error")
            return []