"""
Version: 1.0
Author:Aleksa Zatezalo
Date: February 2025
Description: GraphQL DoS testing module with schema-aware query generation
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Tuple, Any
from grapePrint import grapePrint
import time

### TO DO
# 1. Fingerprint Like GraphW00F
# 2. Remove Websocket Findings
# 3. Limit Links
# 4. Set Introspection DICT
# 5. Port DDOS Tests To the CRUSH

class root():
    """
    A class for testing GraphQL endpoints for various Denial of Service vulnerabilities.
    Generates targeted queries based on introspection of the actual schema.
    """
    
    def __init__(self):
        """Initialize the DoS tester with default settings and printer."""
        self.message = grapePrint()
        self.proxy_url: Optional[str] = None
        self.schema: Optional[Dict] = None
        self.endpoint: Optional[str] = None
        self.query_type: Optional[str] = None
        self.types: Dict[str, Dict] = {}
    
    def configureProxy(self, proxy_host: str, proxy_port: int):
        """Configure HTTP proxy settings."""
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"

    async def runIntrospection(self, session: aiohttp.ClientSession) -> bool:
        """
        Run introspection query to get schema information.
        """
        query = """
        query IntrospectionQuery {
          __schema {
            queryType {
              name
            }
            types {
              name
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

        try:
            async with session.post(
                self.endpoint,
                json={'query': query},
                headers={'Content-Type': 'application/json'},
                timeout=aiohttp.ClientTimeout(total=10),
                proxy=self.proxy_url,
                ssl=False
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    if result.get('data'):
                        self.schema = result['data']['__schema']
                        self.query_type = self.schema['queryType']['name']
                        
                        # Process types into a more usable format
                        for type_info in self.schema['types']:
                            if type_info.get('fields'):
                                self.types[type_info['name']] = {
                                    'fields': type_info['fields']
                                }
                        
                        self.message.printMsg("Successfully retrieved schema", status="log")
                        return True
                    
            self.message.printMsg("Failed to parse introspection result", status="failed")
            return False
            
        except Exception as e:
            self.message.printMsg(f"Introspection query failed: {str(e)}", status="failed")
            return False

    async def setEndpoint(self, endpoint: str, proxy_string: Optional[str] = None) -> bool:
        """
        Set the endpoint and retrieve its schema through introspection.
        
        Args:
            endpoint: The GraphQL endpoint URL
            proxy_string: Optional proxy in format "host:port"
            
        Returns:
            bool: True if endpoint was set and schema retrieved successfully
        """
        self.endpoint = endpoint
        
        # Configure proxy if provided
        if proxy_string:
            try:
                proxy_host, proxy_port = proxy_string.split(':')
                self.configureProxy(proxy_host, int(proxy_port))
            except ValueError:
                self.message.printMsg("Invalid proxy format. Expected host:port", status="failed")
                return False

        # Run introspection
        async with aiohttp.ClientSession() as session:
            return await self.runIntrospection(session)