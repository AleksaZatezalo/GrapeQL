"""
Author: Aleksa Zatezalo
Version: 2.7
Date: April 2025
Description: Optimized vine module with improved test reporting
"""

import asyncio
import aiohttp
import socket
from typing import Dict, List, Optional, Set, Tuple
from .grapePrint import grapePrint
from .http_client import GraphQLClient
import time


class vine:
    """
    A class for discovering GraphQL endpoints with focus on common ports.
    Prioritizes testing of common web ports including custom port 5013.
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
        
        # Common ports to check (including 5013)
        self.common_ports = [
            80,     # HTTP
            443,    # HTTPS
            8080,   # Alternative HTTP
            8443,   # Alternative HTTPS
            3000,   # Node.js/React
            4000,   # Node.js/React
            5000,   # Python/Flask
            5013,   # Custom port (specifically requested)
            8000,   # Python/Django
            8081,   # Alternative HTTP
            8888,   # Jupyter/Alternative
            9000,   # PHP/Node.js
            9090,   # Various web services
            9200,   # Elasticsearch
            9443    # Alternative HTTPS
        ]
        
        # Configurable parameters
        self.max_concurrent_scans = 50     # Maximum concurrent directory requests
        self.port_scan_timeout = 0.5       # Port scan connection timeout
        self.dirb_timeout = 5              # Directory busting timeout
        
        # Tracking variables
        self.endpoints_tested = 0
        self.endpoints_found = 0
        self.vulnerable_endpoints = 0
        
        # Websocket filter strings
        self.websocket_indicators = [
            "websocket",
            "WebSockets request was expected",
            "upgrade: websocket",
            "connection: upgrade",
            "connection upgrade",
            "socket.io"
        ]
        
        # Introspection test query - simplified for reliability
        self.introspection_query = """
        query {
            __schema {
                queryType {
                    name
                }
            }
        }
        """

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
    
    def setCommonPorts(self, ports: List[int]) -> bool:
        """
        Set custom list of common ports to scan.
        
        Args:
            ports: List of port numbers to scan
            
        Returns:
            bool: True if ports were set successfully, False otherwise
        """
        try:
            # Validate ports are integers
            valid_ports = []
            for port in ports:
                if isinstance(port, int) and 1 <= port <= 65535:
                    valid_ports.append(port)
                else:
                    self.message.printMsg(
                        f"Warning: Skipping invalid port: {port}. Ports must be integers between 1-65535.",
                        status="warning"
                    )
            
            if not valid_ports:
                self.message.printMsg(
                    "Error: No valid ports provided", status="error"
                )
                return False
                
            # Set the common ports list
            self.common_ports = valid_ports
            self.message.printMsg(
                f"Successfully set {len(valid_ports)} common ports for scanning", status="success"
            )
            return True
            
        except Exception as e:
            self.message.printMsg(f"Error setting port list: {str(e)}", status="error")
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

    async def scanCommonPorts(self, host: str) -> List[int]:
        """
        Scan just the common ports defined in self.common_ports.

        Args:
            host: The target hostname or IP address

        Returns:
            List[int]: List of open common ports
        """
        self.message.printMsg(f"Scanning common ports on {host}", status="success")
        
        # Test all common ports concurrently
        tasks = [self.testPortNumber(host, port) for port in self.common_ports]
        results = await asyncio.gather(*tasks)
        
        # Extract open ports
        open_ports = [port for port, is_open in results if is_open]
        
        # Display open ports
        for port in open_ports:
            self.message.printMsg(f"{host}:{port} [OPEN]")
            
        # Final report
        if open_ports:
            self.message.printMsg(
                f"Common port scan completed. Found {len(open_ports)} open ports.",
                status="success"
            )
        else:
            self.message.printTestResult(
                "Port Scan", 
                vulnerable=False, 
                details=f"No open ports found on {host}"
            )
        
        return sorted(open_ports)

    def is_websocket_response(self, response_text: str) -> bool:
        """
        Check if a response indicates a WebSocket endpoint.
        
        Args:
            response_text: The response text to check
            
        Returns:
            bool: True if response contains WebSocket indicators
        """
        response_lower = response_text.lower()
        for indicator in self.websocket_indicators:
            if indicator.lower() in response_lower:
                return True
        return False

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
        self.endpoints_tested += 1
        
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
                
            # Extract response text
            response_text = str(result.get("text", ""))
            
            # Check for WebSocket indicators and filter out WebSocket endpoints
            if self.is_websocket_response(response_text):
                return None
                
            # Check for GraphQL indicators in the response
            graphql_indicators = ["graphql", "apollo", "playground", "__schema"]
            for indicator in graphql_indicators:
                if indicator.lower() in response_text.lower():
                    self.message.printMsg(f"Potential GraphQL endpoint found: {full_url}", status="success")
                    self.endpoints_found += 1
                    return full_url
            
            # If we get here, the endpoint exists but no GraphQL indicators found
            self.endpoints_found += 1
            return full_url
                
        except Exception as e:
            return None

    async def scanEndpoints(self, base_url: str) -> List[str]:
        """
        Scan all API endpoints with optimized concurrency.

        Args:
            base_url: The base URL to test endpoints against

        Returns:
            List[str]: List of valid endpoint URLs found
        """
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
        valid_urls = [url for url in batch_results if url]
        
        if not valid_urls:
            self.message.printTestResult(
                f"Directory Scan for {base_url}", 
                vulnerable=False, 
                details="No GraphQL endpoints found at this URL"
            )
            
        return valid_urls

    async def constructAddress(self, ip: str) -> List[str]:
        """
        Construct full URLs for all open ports on a target IP using common port scan.

        Args:
            ip: The target IP address

        Returns:
            List[str]: List of URLs constructed from open ports
        """
        self.message.printMsg("Beginning Common Port Scan", status="success")
        open_ports = await self.scanCommonPorts(host=ip)
        
        if not open_ports:
            self.message.printMsg("No open ports found on target", status="warning")
            return []
            
        # Convert ports to URLs - try both http and https
        urls = []
        for port in open_ports:
            # HTTP is more commonly used
            urls.append(f"http://{ip}:{port}")
            # Only add HTTPS for common HTTPS ports to avoid too many requests
            if port in [443, 8443, 9443]:
                urls.append(f"https://{ip}:{port}")
                
        return urls

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
        
        self.endpoints_tested = 0
        self.endpoints_found = 0
        start_time = time.time()
        all_valid_urls = []
        
        for endpoint in valid_endpoints:
            found_urls = await self.scanEndpoints(endpoint)
            all_valid_urls.extend(found_urls)
        
        dirb_time = time.time() - start_time
        
        # Print summary
        if all_valid_urls:
            self.message.printMsg(
                f"Directory busting completed in {dirb_time:.1f} seconds. Found {len(all_valid_urls)} potential endpoints.",
                status="success"
            )
        else:
            self.message.printTestResult(
                "Directory Busting", 
                vulnerable=False, 
                details=f"No endpoints found after testing {self.endpoints_tested} paths in {dirb_time:.1f} seconds"
            )
            
        return all_valid_urls

    async def test_introspection(self, endpoint: str) -> bool:
        """
        Test an endpoint for GraphQL introspection using a direct query.
        
        This is a more reliable method for checking introspection.
        
        Args:
            endpoint: The endpoint URL to test
            
        Returns:
            bool: True if introspection is enabled, False otherwise
        """
        try:
            # Make a direct introspection query
            payload = {"query": self.introspection_query}
            
            result = await self.client.request(
                "POST",
                endpoint,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            # Check if the query was successful
            if "data" in result and "__schema" in result.get("data", {}):
                schema_data = result["data"]["__schema"]
                if schema_data and "queryType" in schema_data:
                    return True
                    
            return False
        except Exception:
            return False

    async def checkEndpoint(self, endpoint: str) -> Optional[str]:
        """
        Test a single endpoint for GraphQL introspection vulnerability.
        Uses a direct introspection query for more reliable results.

        Args:
            endpoint: The endpoint URL to test

        Returns:
            Optional[str]: Endpoint URL if vulnerable, None otherwise
        """
        try:
            # First check if this is a WebSocket endpoint and skip if so
            get_result = await self.client.request("GET", endpoint, use_cache=True)
            response_text = str(get_result.get("text", ""))
            
            if self.is_websocket_response(response_text):
                return None
            
            # Try direct introspection - this is more reliable
            is_introspectable = await self.test_introspection(endpoint)
            
            if is_introspectable:
                self.vulnerable_endpoints += 1
                self.message.printMsg(f"Introspection enabled: {endpoint}", status="warning")
                return endpoint
            
            # Introspection not enabled    
            self.message.printTestResult(
                f"Introspection Test: {endpoint}", 
                vulnerable=False, 
                details="GraphQL endpoint exists but introspection is disabled"
            )
            return None
            
        except Exception:
            return None

    async def introspection(self, endpoints: List[str]) -> List[str]:
        """
        Test multiple endpoints for GraphQL introspection vulnerability.

        Args:
            endpoints: List of endpoints to test

        Returns:
            List[str]: List of vulnerable endpoints with introspection enabled
        """
        if not endpoints:
            self.message.printMsg("No endpoints to test for introspection", status="warning")
            return []
            
        self.message.printMsg(f"Testing {len(endpoints)} endpoints for introspection", status="success")
        
        self.vulnerable_endpoints = 0
        start_time = time.time()
        
        # Use a semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(min(len(endpoints), 10))  # Max 10 concurrent tests
        
        async def check_with_semaphore(endpoint):
            async with semaphore:
                return await self.checkEndpoint(endpoint)
        
        # Create tasks with semaphore
        tasks = [check_with_semaphore(endpoint) for endpoint in endpoints]
        
        # Run all tasks concurrently with controlled parallelism
        results = await asyncio.gather(*tasks)
        
        # Filter valid results
        vulnerable_endpoints = [endpoint for endpoint in results if endpoint]
        scan_time = time.time() - start_time
        
        # Print summary
        if vulnerable_endpoints:
            self.message.printMsg(
                f"Found {len(vulnerable_endpoints)} GraphQL endpoints with introspection enabled",
                status="success"
            )
            self.message.printMsg(
                f"Introspection testing completed in {scan_time:.1f} seconds",
                status="info"
            )
        else:
            self.message.printTestResult(
                "Introspection Testing", 
                vulnerable=False, 
                details=f"No GraphQL endpoints with introspection found in {scan_time:.1f} seconds"
            )
            
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
        Main execution function that coordinates the scanning process focusing on common ports.

        Args:
            proxy_string: Optional string containing proxy host and port in format "host:port"
            target_ip: Target IP address to scan

        Returns:
            List[str]: List of vulnerable GraphQL endpoints found
        """
        try:
            start_time = time.time()
            
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

            # Perform common port scan only
            valid_endpoints = await self.constructAddress(target_ip)
            
            if not valid_endpoints:
                self.message.printMsg("No open ports found. Scan cannot continue.", status="error")
                return []
                
            # Perform directory busting
            url_list = await self.dirbList(valid_endpoints)
            
            if not url_list:
                self.message.printMsg("No potential endpoints found.", status="warning")
                return []
                
            # Test for introspection
            self.message.printMsg("Testing endpoints for introspection...", status="success")
            vulnerable_endpoints = await self.introspection(url_list)
            
            # Print final summary
            end_time = time.time()
            total_time = end_time - start_time
            
            if vulnerable_endpoints:
                self.message.printScanSummary(
                    tests_run=len(url_list),
                    vulnerabilities_found=len(vulnerable_endpoints),
                    scan_time=total_time
                )
            else:
                self.message.printScanSummary(
                    tests_run=len(url_list),
                    vulnerabilities_found=0,
                    scan_time=total_time
                )
            
            # Return results
            return vulnerable_endpoints

        except Exception as e:
            self.message.printMsg(f"Error during scan: {str(e)}", status="error")
            return []