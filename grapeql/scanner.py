"""
Core scanner for GraphQL endpoint discovery and testing

Author: Aleksa Zatezalo
Version: 3.0
"""

import asyncio
import socket
import json
from typing import Dict, List, Optional, Set, Tuple, Any
from .grapePrint import grapePrint
from .http_client import GraphQLHTTPClient
from .schema_analyzer import SchemaAnalyzer


class GraphQLScanner:
    """
    A unified scanner class for discovering and testing GraphQL endpoints.
    """
    
    def __init__(self):
        """Initialize with default settings."""
        self.message = grapePrint()
        self.client = GraphQLHTTPClient()
        self.schema = None
        self.username = "admin"
        self.password = "changeme"
        self.auth_token = None
        self.debug_mode = False
        
        # Default endpoints to check
        self.api_paths = [
            "/graphql",
            "/graphql/console",
            "/graphql/playground",
            "/graphiql",
            "/api/graphql",
            "/api/v1/graphql",
            "/api/v2/graphql",
            "/api/explorer",
        ]
        
        # Common ports to scan
        self.common_ports = [
            80,     # HTTP
            443,    # HTTPS
            8080,   # Alternative HTTP
            8443,   # Alternative HTTPS
            3000,   # Node.js/React
            4000,   # Node.js/React
            5000,   # Python/Flask
            5013,   # DVGA
            8000,   # Python/Django
            9000,   # PHP/Node.js
        ]
        
        # Timeouts and limits
        self.port_timeout = 0.5        # Port scan timeout
        self.request_timeout = 5.0     # HTTP request timeout
        self.max_concurrency = 20      # Maximum concurrent requests
        
    # Configuration methods
    
    def set_debug_mode(self, debug_mode: bool = True) -> None:
        """Enable or disable debug mode."""
        self.debug_mode = debug_mode
        self.client.set_debug_mode(debug_mode)
        
    def set_credentials(self, username: str, password: str) -> None:
        """Set credentials for authentication testing."""
        self.username = username
        self.password = password
        
    def set_api_paths(self, paths: List[str]) -> None:
        """Set custom API paths to scan."""
        self.api_paths = paths
        
    def set_common_ports(self, ports: List[int]) -> None:
        """Set custom ports to scan."""
        self.common_ports = ports
        
    def set_header(self, name: str, value: str) -> None:
        """Set a custom header."""
        self.client.set_header(name, value)
        
    def set_headers(self, headers: Dict[str, str]) -> None:
        """Set multiple custom headers."""
        self.client.set_headers(headers)
        
    def set_cookie(self, name: str, value: str) -> None:
        """Set a cookie."""
        self.client.set_cookie(name, value)
        
    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Set multiple cookies."""
        self.client.set_cookies(cookies)
        
    def set_authorization(self, token: str, prefix: str = "Bearer") -> None:
        """Set Authorization header with token."""
        self.client.set_authorization(token, prefix)
        self.auth_token = token
        
    def configure_proxy(self, proxy_host: str, proxy_port: int) -> None:
        """Configure HTTP proxy settings."""
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
        # Set the endpoint
        self.client.set_endpoint(endpoint)
        
        # Configure proxy if provided
        if proxy:
            if not self.client.set_proxy_from_string(proxy):
                self.message.printMsg("Invalid proxy format. Expected host:port", status="failed")
                return False
        
        try:
            # Try to connect
            self.message.printMsg(f"Connecting to {endpoint}...", status="log")
            
            # Check if endpoint is a GraphQL endpoint
            has_introspection = await self.client.has_introspection()
            
            if has_introspection:
                self.message.printMsg("GraphQL endpoint confirmed with introspection enabled", status="success")
                
                # Load schema with analyzer
                self.schema = SchemaAnalyzer(self.client)
                if await self.schema.load_schema():
                    self.message.printMsg("Schema loaded successfully", status="success")
                    return True
                else:
                    self.message.printMsg("Connected to GraphQL endpoint but failed to load complete schema", status="warning")
                    return True  # We still consider this a success as we confirmed it's a GraphQL endpoint
            else:
                # Try a basic query to see if it's GraphQL but with introspection disabled
                query = "query { __typename }"
                result = await self.client.graphql(query)
                
                if "data" in result:
                    self.message.printMsg("GraphQL endpoint confirmed, but introspection is disabled", status="warning")
                    return True
                    
                self.message.printMsg("Endpoint is not a GraphQL API or is not accessible", status="failed")
                return False
                
        except Exception as e:
            self.message.printMsg(f"Error connecting to endpoint: {str(e)}", status="failed")
            return False
    
    async def close(self) -> None:
        """Clean up resources."""
        if self.client:
            await self.client.close()
    
    # Port scanning methods
    
    async def scan_port(self, host: str, port: int) -> Tuple[int, bool]:
        """
        Check if a port is open on a target host.
        
        Args:
            host: Target hostname or IP
            port: Port number to check
            
        Returns:
            Tuple[int, bool]: Port number and whether it's open
        """
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.port_timeout)
            writer.close()
            await writer.wait_closed()
            return port, True
        except:
            return port, False
    
    async def scan_common_ports(self, host: str) -> List[int]:
        """
        Scan common ports on a target host.
        
        Args:
            host: Target hostname or IP
            
        Returns:
            List[int]: List of open ports
        """
        self.message.printMsg(f"Scanning common ports on {host}...", status="success")
        
        # Scan ports concurrently
        tasks = [self.scan_port(host, port) for port in self.common_ports]
        results = await asyncio.gather(*tasks)
        
        # Filter open ports
        open_ports = [port for port, is_open in results if is_open]
        
        if open_ports:
            self.message.printMsg(f"Found {len(open_ports)} open ports", status="success")
            for port in open_ports:
                self.message.printMsg(f"Port {port}/tcp is open", status="info")
        else:
            self.message.printMsg("No open ports found on common ports", status="warning")
            
        return open_ports
    
    # Endpoint discovery methods
    
    async def check_endpoint(self, base_url: str, path: str) -> Optional[str]:
        """
        Check if a specific path is a GraphQL endpoint.
        
        Args:
            base_url: Base URL (e.g., http://example.com:8080)
            path: Path to check (e.g., /graphql)
            
        Returns:
            Optional[str]: Full URL if it's a GraphQL endpoint, None otherwise
        """
        full_url = f"{base_url.rstrip('/')}{path}"
        
        try:
            # Save current endpoint
            original_endpoint = self.client.endpoint
            
            # Set temporary endpoint
            self.client.set_endpoint(full_url)
            
            # Try a simple introspection query
            is_graphql = await self.client.has_introspection()
            
            # If not introspectable, try a simple query
            if not is_graphql:
                query = "query { __typename }"
                result = await self.client.graphql(query)
                is_graphql = "data" in result
            
            # Restore original endpoint
            self.client.set_endpoint(original_endpoint)
            
            if is_graphql:
                return full_url
            return None
            
        except Exception:
            # Restore original endpoint in case of error
            self.client.set_endpoint(original_endpoint)
            return None
    
    async def discover_endpoints_on_host(self, base_url: str) -> List[str]:
        """
        Discover GraphQL endpoints on a specific host/port.
        
        Args:
            base_url: Base URL to scan (e.g., http://example.com:8080)
            
        Returns:
            List[str]: List of discovered GraphQL endpoints
        """
        self.message.printMsg(f"Checking for GraphQL endpoints on {base_url}...", status="log")
        
        # Use semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.max_concurrency)
        
        async def check_with_limit(path):
            async with semaphore:
                return await self.check_endpoint(base_url, path)
        
        # Check all paths concurrently
        tasks = [check_with_limit(path) for path in self.api_paths]
        results = await asyncio.gather(*tasks)
        
        # Filter valid endpoints
        valid_endpoints = [endpoint for endpoint in results if endpoint]
        
        if valid_endpoints:
            self.message.printMsg(f"Found {len(valid_endpoints)} GraphQL endpoints on {base_url}", status="success")
        
        return valid_endpoints
    
    async def discover_endpoints(self, target: str, proxy: Optional[str] = None) -> List[str]:
        """
        Discover GraphQL endpoints on a target.
        
        Args:
            target: Target hostname or IP
            proxy: Optional proxy string
            
        Returns:
            List[str]: List of discovered GraphQL endpoints
        """
        # Configure proxy if provided
        if proxy:
            if not self.client.set_proxy_from_string(proxy):
                self.message.printMsg("Invalid proxy format. Expected host:port", status="failed")
                return []
            self.message.printMsg(f"Using proxy: {proxy} for endpoint discovery", status="info")
        
        # Scan ports
        open_ports = await self.scan_common_ports(target)
        
        if not open_ports:
            self.message.printMsg("No open ports found, cannot continue", status="failed")
            return []
        
        # Check both HTTP and HTTPS for each port
        base_urls = []
        for port in open_ports:
            # HTTP is more common
            base_urls.append(f"http://{target}:{port}")
            
            # Only check HTTPS for typical HTTPS ports
            if port in [443, 8443]:
                base_urls.append(f"https://{target}:{port}")
        
        # Discover endpoints on each base URL
        all_endpoints = []
        for base_url in base_urls:
            endpoints = await self.discover_endpoints_on_host(base_url)
            all_endpoints.extend(endpoints)
        
        if not all_endpoints:
            self.message.printMsg("No GraphQL endpoints found on target", status="warning")
        else:
            self.message.printMsg(f"Discovered {len(all_endpoints)} GraphQL endpoints in total", status="success")
            
        return all_endpoints
    
    # Engine detection methods
    
    async def detect_engine(self) -> Dict:
        """
        Detect the GraphQL engine implementation.
        
        Returns:
            Dict: Information about the detected engine
        """
        if not self.client.endpoint:
            self.message.printMsg("No endpoint set", status="failed")
            return {"name": "unknown", "technology": ["Unknown"]}
        
        self.message.printMsg("Detecting GraphQL server...", status="log")
        
        # Default response if detection fails
        engine_info = {
            "name": "unknown",
            "url": "",
            "technology": ["Unknown"]
        }
        
        # First, try to gather information about the server
        try:
            # Check HTTP headers for clues (before any GraphQL-specific tests)
            headers_result = await self.client.request("GET")
            headers = {}
            
            # Try to extract headers from the response if available
            if hasattr(self.client, "last_response") and self.client.last_response:
                response = self.client.last_response
                if hasattr(response, "headers"):
                    headers = dict(response.headers)
            
            # Log headers for debugging
            if self.debug_mode and headers:
                self.message.printMsg(f"Server headers: {json.dumps(headers, indent=2)}", status="info")
            
            # Check for common server headers
            server_header = headers.get("Server", "").lower()
            if "express" in server_header:
                engine_info["possible_technology"] = ["Node.js", "Express"]
            elif "nginx" in server_header:
                engine_info["possible_proxy"] = "Nginx"
            elif "apache" in server_header:
                engine_info["possible_proxy"] = "Apache"
            
            # Look for GraphQL-specific fingerprints
            try:
                # Test for Apollo Server
                query = "query @deprecated { __typename }"
                result = await self.client.graphql(query)
                
                # Debug output
                if self.debug_mode:
                    self.message.printMsg(f"Apollo Server test result: {json.dumps(result, indent=2)}", status="info")
                
                errors_text = str(result.get("errors", []))
                if "may not be used on QUERY" in errors_text or "directive is not supported" in errors_text:
                    engine_info = {
                        "name": "Apollo Server",
                        "url": "https://www.apollographql.com/",
                        "technology": ["Node.js", "JavaScript"]
                    }
                    self.message.printMsg("Detected Apollo Server", status="success")
                    return engine_info
                
                # Test for GraphQL-Java / Spring GraphQL
                if any("InvalidSyntax" in str(err.get("extensions", {}).get("classification", "")) 
                    for err in result.get("errors", [])):
                    engine_info = {
                        "name": "GraphQL-Java / Spring GraphQL",
                        "url": "https://www.graphql-java.com/",
                        "technology": ["Java", "Spring"]
                    }
                    self.message.printMsg("Detected GraphQL-Java or Spring GraphQL", status="success")
                    return engine_info
                
                # Test for Graphene
                query = "aaa"  # Invalid query
                result = await self.client.graphql(query)
                
                # Debug output
                if self.debug_mode:
                    self.message.printMsg(f"Graphene test result: {json.dumps(result, indent=2)}", status="info")
                
                if any("Syntax Error GraphQL" in str(err.get("message", "")) 
                    for err in result.get("errors", [])):
                    engine_info = {
                        "name": "Graphene",
                        "url": "https://graphene-python.org/",
                        "technology": ["Python"]
                    }
                    self.message.printMsg("Detected Graphene", status="success")
                    return engine_info
                
                # Test for Hasura
                query = "query { __typename }"
                result = await self.client.graphql(query)
                
                # Debug output
                if self.debug_mode:
                    self.message.printMsg(f"Hasura test result: {json.dumps(result, indent=2)}", status="info")
                
                if result.get("data", {}).get("__typename") == "query_root":
                    engine_info = {
                        "name": "Hasura",
                        "url": "https://hasura.io/",
                        "technology": ["Haskell", "PostgreSQL"]
                    }
                    self.message.printMsg("Detected Hasura", status="success")
                    return engine_info
                
                # Test for GraphQL.NET
                query = "{ __schema { description } }"
                result = await self.client.graphql(query)
                
                # Debug output
                if self.debug_mode:
                    self.message.printMsg(f"GraphQL.NET test result: {json.dumps(result, indent=2)}", status="info")
                
                if any("The field 'description' is not defined" in str(err.get("message", ""))
                    for err in result.get("errors", [])):
                    engine_info = {
                        "name": "GraphQL.NET",
                        "url": "https://github.com/graphql-dotnet/graphql-dotnet",
                        "technology": [".NET", "C#"]
                    }
                    self.message.printMsg("Detected GraphQL.NET", status="success")
                    return engine_info
                
                # Test for Laravel Lighthouse
                query = "aaa"  # Invalid query
                result = await self.client.graphql(query)
                
                # Debug output
                if self.debug_mode:
                    self.message.printMsg(f"Laravel Lighthouse test result: {json.dumps(result, indent=2)}", status="info")
                
                if any("Syntax Error: Unexpected Name" in str(err.get("message", "")) 
                    for err in result.get("errors", [])):
                    engine_info = {
                        "name": "Laravel Lighthouse",
                        "url": "https://lighthouse-php.com/",
                        "technology": ["PHP", "Laravel"]
                    }
                    self.message.printMsg("Detected Laravel Lighthouse", status="success")
                    return engine_info
                
                # Test for Strawberry GraphQL (Python)
                query = "query { __typename }"
                headers = dict(self.client.headers)
                self.client.set_header("Accept", "text/html")
                result = await self.client.request("GET")
                self.client.headers = headers
                
                # Debug output
                if self.debug_mode:
                    self.message.printMsg(f"Strawberry GraphQL test result: {json.dumps(result, indent=2)}", status="info")
                
                response_text = str(result.get("text", ""))
                if "strawberry-graphql" in response_text.lower():
                    engine_info = {
                        "name": "Strawberry GraphQL",
                        "url": "https://strawberry.rocks/",
                        "technology": ["Python"]
                    }
                    self.message.printMsg("Detected Strawberry GraphQL", status="success")
                    return engine_info
                
                # Test for Ariadne (Python)
                if any("The query is invalid" in str(err.get("message", "")) 
                    for err in result.get("errors", [])):
                    engine_info = {
                        "name": "Ariadne",
                        "url": "https://ariadnegraphql.org/",
                        "technology": ["Python"]
                    }
                    self.message.printMsg("Detected Ariadne", status="success")
                    return engine_info
                
                # Test for Juniper (Rust)
                query = "{ notARealField }"
                result = await self.client.graphql(query)
                if any("unknown field" in str(err.get("message", "")).lower() 
                    for err in result.get("errors", [])):
                    engine_info = {
                        "name": "Juniper",
                        "url": "https://github.com/graphql-rust/juniper",
                        "technology": ["Rust"]
                    }
                    self.message.printMsg("Detected Juniper (Rust)", status="success")
                    return engine_info
                
                # Check for general GraphQL identification
                query = "query { __typename }"
                result = await self.client.graphql(query)
                
                if "data" in result and "__typename" in result.get("data", {}):
                    typename = result["data"]["__typename"] 
                    engine_info = {
                        "name": f"Unknown GraphQL Implementation (typename: {typename})",
                        "url": "",
                        "technology": ["GraphQL"],
                        "typename": typename
                    }
                    self.message.printMsg(f"Detected GraphQL server with typename: {typename}", status="info")
                    return engine_info
            
            except Exception as e:
                self.message.printMsg(f"Error during GraphQL detection tests: {str(e)}", status="warning")
                
            # Unknown engine but we might have some info from headers
            if "possible_technology" in engine_info or "possible_proxy" in engine_info:
                tech = engine_info.get("possible_technology", [])
                proxy = engine_info.get("possible_proxy", "")
                
                details = []
                if tech:
                    details.append(f"Possible technology: {', '.join(tech)}")
                if proxy:
                    details.append(f"Possible proxy: {proxy}")
                
                engine_info = {
                    "name": "unknown",
                    "url": "",
                    "technology": tech if tech else ["Unknown"],
                    "details": ". ".join(details)
                }
                self.message.printMsg(f"Partial detection: {engine_info.get('details', '')}", status="info")
                return engine_info
                
            self.message.printMsg("Could not identify GraphQL engine implementation", status="warning")
            return engine_info
            
        except Exception as e:
            self.message.printMsg(f"Error during engine detection: {str(e)}", status="failed")
            return engine_info