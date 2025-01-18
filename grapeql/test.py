#!/usr/bin/env python
"""
Author: Aleksa Zatezalo
Version: 1.1
Date: October 2024
Description: GraphQL endpoint enumeration and introspection tool with proxy support and async scanning.
"""

import asyncio
import argparse
import aiohttp
from aiohttp import ClientSession
from endpointEnum import apiList  # Import just the API list, we'll implement our own scanning
import json
import socket
from concurrent.futures import ThreadPoolExecutor
import sys
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()

class GrapeQLScanner:
    def __init__(self, target_url, proxy=None, concurrency=50):
        self.target_url = target_url
        self.proxy = proxy
        self.concurrency = concurrency
        self.graphql_endpoints = []
        self.open_ports = []
        self.introspection_results = {}
        self.scan_start_time = None
        
        # GraphQL introspection query
        self.introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
        }
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
        """

    def print_grape_banner(self):
        grape = f"""{Fore.MAGENTA}
        .     .  🍇  .      .
     .  .  🍇  .  🍇   .
   .  🍇   GrapeQL  🍇  .
     . 🍇  Scanner  🍇 .
        .  🍇  .  🍇  .
           .    .    .{Style.RESET_ALL}
        """
        print(grape)
        print(f"{Fore.MAGENTA}Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}\n")

    async def test_port(self, host, port, timeout=2):
        """Test if a port is open"""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    async def scan_ports(self, ip, start_port=1, end_port=65535):
        """Scan ports asynchronously"""
        print(f"\n{Fore.CYAN}[*] Starting port scan on {ip}{Style.RESET_ALL}")
        
        # Create chunks of ports for concurrent scanning
        ports = range(start_port, end_port + 1)
        chunk_size = len(ports) // self.concurrency
        port_chunks = [ports[i:i + chunk_size] for i in range(0, len(ports), chunk_size)]
        
        async def scan_chunk(chunk):
            open_ports = []
            for port in chunk:
                if await self.test_port(ip, port):
                    print(f"{Fore.GREEN}[+] Port {port} is open{Style.RESET_ALL}")
                    open_ports.append(port)
            return open_ports
        
        # Scan all chunks concurrently
        tasks = [scan_chunk(chunk) for chunk in port_chunks]
        results = await asyncio.gather(*tasks)
        
        # Flatten results
        return [port for chunk_result in results for port in chunk_result]

    async def scan_endpoint(self, session, base_url, path):
        """Scan a single endpoint"""
        full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with session.get(full_url, proxy=self.proxy, ssl=False) as response:
                if response.status != 404:
                    print(f"{Fore.GREEN}[+] Found endpoint: {full_url} (Status: {response.status}){Style.RESET_ALL}")
                    return full_url
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning {full_url}: {str(e)}{Style.RESET_ALL}")
        return None

    async def scan_endpoints(self):
        """Scan endpoints asynchronously"""
        print(f"\n{Fore.CYAN}[*] Starting endpoint enumeration{Style.RESET_ALL}")
        async with ClientSession() as session:
            tasks = [self.scan_endpoint(session, self.target_url, path) for path in apiList]
            results = await asyncio.gather(*tasks)
        return [r for r in results if r]

    async def banner_grab(self, ip, port):
        """Perform banner grabbing on open ports"""
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            writer.write(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            await writer.drain()
            
            banner = await asyncio.wait_for(reader.read(1024), timeout=3)
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore').strip()
        except Exception as e:
            return f"Banner grab failed: {str(e)}"

    async def perform_introspection(self, endpoint):
        """Perform GraphQL introspection query on identified endpoints"""
        print(f"\n{Fore.CYAN}[*] Attempting introspection on {endpoint}{Style.RESET_ALL}")
        async with ClientSession() as session:
            headers = {'Content-Type': 'application/json'}
            try:
                async with session.post(
                    endpoint,
                    json={'query': self.introspection_query},
                    headers=headers,
                    proxy=self.proxy,
                    ssl=False
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        print(f"{Fore.GREEN}[+] Successful introspection on {endpoint}{Style.RESET_ALL}")
                        return endpoint, result
                    return endpoint, f"Failed with status: {response.status}"
            except Exception as e:
                return endpoint, f"Introspection failed: {str(e)}"

    async def scan(self):
        """Main scanning method"""
        self.print_grape_banner()
        self.scan_start_time = datetime.now()
        
        if not self.target_url:
            return None
        
        print(f"{Fore.CYAN}[*] Target: {self.target_url}")
        print(f"[*] Proxy: {self.proxy if self.proxy else 'None'}{Style.RESET_ALL}")
        
        # Get IP from URL
        ip = self.target_url.split("://")[1].split(":")[0]
        
        # Run port scan and endpoint enumeration concurrently
        self.open_ports, self.graphql_endpoints = await asyncio.gather(
            self.scan_ports(ip),
            self.scan_endpoints()
        )
        
        # Banner grab for open ports
        print(f"\n{Fore.CYAN}[*] Performing banner grabbing...{Style.RESET_ALL}")
        banner_tasks = [self.banner_grab(ip, port) for port in self.open_ports]
        banners = await asyncio.gather(*banner_tasks)
        
        # Perform introspection on GraphQL endpoints
        print(f"\n{Fore.CYAN}[*] Performing GraphQL introspection...{Style.RESET_ALL}")
        introspection_tasks = [self.perform_introspection(endpoint) 
                             for endpoint in self.graphql_endpoints]
        introspection_results = await asyncio.gather(*introspection_tasks)
        
        scan_duration = datetime.now() - self.scan_start_time
        
        # Compile results
        results = {
            'scan_info': {
                'target': self.target_url,
                'start_time': self.scan_start_time.isoformat(),
                'duration': str(scan_duration),
                'proxy_used': self.proxy
            },
            'graphql_endpoints': self.graphql_endpoints,
            'open_ports': [{
                'port': port,
                'banner': banner
            } for port, banner in zip(self.open_ports, banners)],
            'introspection_results': {
                endpoint: result for endpoint, result in introspection_results
            }
        }
        
        return results

def main():
    parser = argparse.ArgumentParser(description='GraphQL Endpoint Scanner with async scanning capabilities')
    parser.add_argument('--url', required=True, help='Target URL (e.g., http://example.com:8080)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--output', help='Output file for results (JSON format)')
    parser.add_argument('--concurrency', type=int, default=50, help='Number of concurrent tasks (default: 50)')
    args = parser.parse_args()

    try:
        # Create scanner instance
        scanner = GrapeQLScanner(args.url, args.proxy, args.concurrency)
        
        # Run the scan
        results = asyncio.run(scanner.scan())
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n{Fore.GREEN}[+] Results saved to {args.output}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[+] Scan Results:{Style.RESET_ALL}")
            print(json.dumps(results, indent=2))
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()