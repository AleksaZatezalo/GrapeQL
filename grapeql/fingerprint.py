"""
GrapeQL Fingerprinting Module
Author: Aleksa Zatezalo (Simplified by Claude)
Version: 2.0
Date: April 2025
Description: Fingerprinting module to identify GraphQL engine implementations
"""

from typing import Dict, List, Optional, Tuple, Set
from .client import GraphQLClient
from .utils import GrapePrinter, Finding

class Fingerprinter:
    """
    Identifies GraphQL server implementations through behavioral fingerprinting.
    """
    
    def __init__(self):
        """Initialize the fingerprinter."""
        self.client = GraphQLClient()
        self.printer = GrapePrinter()
        self.findings = []
        self.engines = {
            "apollo": {
                "name": "Apollo Server",
                "url": "https://www.apollographql.com/",
                "tech": ["Node.js", "JavaScript"],
                "cve": ["CVE-2023-30783", "CVE-2022-21721"]
            },
            "graphql-yoga": {
                "name": "GraphQL Yoga",
                "url": "https://graphql-yoga.com/",
                "tech": ["Node.js", "JavaScript"],
                "cve": []
            },
            "aws-appsync": {
                "name": "AWS AppSync",
                "url": "https://aws.amazon.com/appsync/",
                "tech": ["AWS"],
                "cve": []
            },
            "graphene": {
                "name": "Graphene",
                "url": "https://graphene-python.org/",
                "tech": ["Python"],
                "cve": []
            },
            "hasura": {
                "name": "Hasura GraphQL Engine",
                "url": "https://hasura.io/",
                "tech": ["Haskell"],
                "cve": ["CVE-2023-22465", "CVE-2021-32675"]
            },
            "graphql-php": {
                "name": "GraphQL PHP",
                "url": "https://webonyx.github.io/graphql-php/",
                "tech": ["PHP"],
                "cve": []
            },
            "ruby-graphql": {
                "name": "Ruby GraphQL",
                "url": "https://graphql-ruby.org/",
                "tech": ["Ruby"],
                "cve": []
            },
            "hypergraphql": {
                "name": "HyperGraphQL",
                "url": "https://www.hypergraphql.org/",
                "tech": ["Java"],
                "cve": []
            },
            "graphql-java": {
                "name": "GraphQL Java",
                "url": "https://www.graphql-java.com/",
                "tech": ["Java"],
                "cve": []
            },
            "ariadne": {
                "name": "Ariadne",
                "url": "https://ariadnegraphql.org/",
                "tech": ["Python"],
                "cve": []
            },
            "graphql-api-for-wp": {
                "name": "GraphQL API for WordPress",
                "url": "https://graphql-api.com/",
                "tech": ["PHP", "WordPress"],
                "cve": []
            },
            "wp-graphql": {
                "name": "WPGraphQL",
                "url": "https://www.wpgraphql.com/",
                "tech": ["PHP", "WordPress"],
                "cve": []
            },
            "gqlgen": {
                "name": "gqlgen",
                "url": "https://gqlgen.com/",
                "tech": ["Go"],
                "cve": []
            },
            "graphql-go": {
                "name": "graphql-go",
                "url": "https://github.com/graphql-go/graphql",
                "tech": ["Go"],
                "cve": []
            },
            "juniper": {
                "name": "Juniper",
                "url": "https://graphql-rust.github.io/",
                "tech": ["Rust"],
                "cve": []
            },
            "sangria": {
                "name": "Sangria",
                "url": "https://sangria-graphql.github.io/",
                "tech": ["Scala"],
                "cve": []
            },
            "strawberry": {
                "name": "Strawberry GraphQL",
                "url": "https://strawberry.rocks/",
                "tech": ["Python"],
                "cve": []
            },
            "mercurius": {
                "name": "Mercurius",
                "url": "https://mercurius.dev/",
                "tech": ["Node.js", "Fastify"],
                "cve": []
            },
            "lighthouse": {
                "name": "Lighthouse",
                "url": "https://lighthouse-php.com/",
                "tech": ["PHP", "Laravel"],
                "cve": []
            }
        }
        
    async def setup_endpoint(self, endpoint: str, proxy: Optional[str] = None) -> bool:
        """
        Set up the fingerprinter with the target endpoint.
        
        Args:
            endpoint: GraphQL endpoint URL
            proxy: Optional proxy in host:port format
            
        Returns:
            bool: True if setup was successful
        """
        return await self.client.setup_endpoint(endpoint, proxy)
        
    def _error_contains(self, response: Dict, error_text: str, part: str = "message") -> bool:
        """
        Check if a response contains a specific error message.
        
        Args:
            response: Response data
            error_text: Error text to look for
            part: Part of the error to check (message, code, etc.)
            
        Returns:
            bool: True if error contains the specified text
        """
        errors = response.get("errors", [])
        return any(error_text.lower() in error.get(part, "").lower() for error in errors)
        
    async def test_apollo(self) -> bool:
        """Test if the endpoint is running Apollo Server."""
        query = "query @skip { __typename }"
        response, _ = await self.client.graphql_query(query)
        if response and self._error_contains(
            response, 'Directive "@skip" argument "if" of type "Boolean!" is required'
        ):
            return True

        query = "query @deprecated { __typename }"
        response, _ = await self.client.graphql_query(query)
        return response and self._error_contains(
            response, 'Directive "@deprecated" may not be used on QUERY'
        )
        
    async def test_yoga(self) -> bool:
        """Test if the endpoint is running GraphQL Yoga."""
        query = """subscription { __typename }"""
        response, _ = await self.client.graphql_query(query)
        return response and (
            self._error_contains(response, "asyncExecutionResult[Symbol.asyncIterator] is not a function") or 
            self._error_contains(response, "Unexpected error.")
        )
        
    async def test_aws_appsync(self) -> bool:
        """Test if the endpoint is running AWS AppSync."""
        query = "query @skip { __typename }"
        response, _ = await self.client.graphql_query(query)
        return response and self._error_contains(response, "MisplacedDirective")
        
    async def test_graphene(self) -> bool:
        """Test if the endpoint is running Graphene."""
        query = "aaa"
        response, _ = await self.client.graphql_query(query)
        return response and self._error_contains(response, "Syntax Error GraphQL (1:1)")
        
    async def test_hasura(self) -> bool:
        """Test if the endpoint is running Hasura."""
        query = """query @cached { __typename }"""
        response, _ = await self.client.graphql_query(query)
        if response and response.get("data", {}).get("__typename") == "query_root":
            return True

        query = "query { aaa }"
        response, _ = await self.client.graphql_query(query)
        if response and self._error_contains(response, 'field "aaa" not found in type: \'query_root\''):
            return True

        query = "query @skip { __typename }"
        response, _ = await self.client.graphql_query(query)
        if response and self._error_contains(response, 'directive "skip" is not allowed on a query'):
            return True

        query = "query { __schema }"
        response, _ = await self.client.graphql_query(query)
        return response and self._error_contains(response, 'missing selection set for "__Schema"')
        
    async def test_graphql_php(self) -> bool:
        """Test if the endpoint is running GraphQL PHP."""
        query = "query ! { __typename }"
        response, _ = await self.client.graphql_query(query)
        if response and self._error_contains(response, 'Syntax Error: Cannot parse the unexpected character "?"'):
            return True

        query = "query @deprecated { __typename }"
        response, _ = await self.client.graphql_query(query)
        return response and self._error_contains(response, 'Directive "deprecated" may not be used on "QUERY"')
        
    async def test_ruby_graphql(self) -> bool:
        """Test if the endpoint is running Ruby GraphQL."""
        query = "query @skip { __typename }"
        response, _ = await self.client.graphql_query(query)
        if response and self._error_contains(response, "'@skip' can't be applied to queries"):
            return True
        elif response and self._error_contains(response, "Directive 'skip' is missing required arguments: if"):
            return True

        query = "query @deprecated { __typename }"
        response, _ = await self.client.graphql_query(query)
        if response and self._error_contains(response, "'@deprecated' can't be applied to queries"):
            return True

        query = """query { __typename { }"""
        response, _ = await self.client.graphql_query(query)
        return response and self._error_contains(response, 'Parse error on "}" (RCURLY)')
        
    async def test_strawberry(self) -> bool:
        """Test if the endpoint is running Strawberry."""
        query = "query @deprecated { __typename }"
        response, _ = await self.client.graphql_query(query)
        return response and self._error_contains(
            response, "Directive '@deprecated' may not be used on query."
        ) and "data" in response
        
    async def test_lighthouse(self) -> bool:
        """Test if the endpoint is running Lighthouse."""
        query = "query { __typename @include(if: falsee) }"
        response, _ = await self.client.graphql_query(query)
        return response and (
            self._error_contains(response, "Internal server error") or 
            self._error_contains(response, "internal", part="category")
        )
        
    async def test_juniper(self) -> bool:
        """Test if the endpoint is running Juniper."""
        query = "queryy { __typename }"
        response, _ = await self.client.graphql_query(query)
        if response and self._error_contains(response, 'Unexpected "queryy"'):
            return True

        query = ""
        response, _ = await self.client.graphql_query(query)
        return response and self._error_contains(response, "Unexpected end of input")
        
    async def test_ariadne(self) -> bool:
        """Test if the endpoint is running Ariadne."""
        query = "query { __typename @abc }"
        response, _ = await self.client.graphql_query(query)
        if response and self._error_contains(response, "Unknown directive '@abc'.") and "data" not in response:
            return True

        query = ""
        response, _ = await self.client.graphql_query(query)
        return response and self._error_contains(response, "The query must be a string.")
        
    async def fingerprint(self) -> Optional[Dict]:
        """
        Identify the GraphQL engine being used.
        
        Returns:
            Optional[Dict]: Engine details if identified, None otherwise
        """
        self.printer.print_section("Fingerprinting GraphQL Engine")
        
        if not self.client.endpoint:
            self.printer.print_msg("No endpoint set", status="error")
            return None
            
        # Define all tests to run with their corresponding engine IDs
        tests = [
            (self.test_apollo, "apollo"),
            (self.test_yoga, "graphql-yoga"),
            (self.test_aws_appsync, "aws-appsync"),
            (self.test_graphene, "graphene"),
            (self.test_hasura, "hasura"),
            (self.test_graphql_php, "graphql-php"),
            (self.test_ruby_graphql, "ruby-graphql"),
            (self.test_ariadne, "ariadne"),
            (self.test_strawberry, "strawberry"),
            (self.test_juniper, "juniper"),
            (self.test_lighthouse, "lighthouse")
        ]
        
        # Run all the tests
        for test_func, engine_id in tests:
            try:
                if await test_func():
                    # Engine identified
                    engine_info = self.engines.get(engine_id, {})
                    engine_name = engine_info.get("name", engine_id)
                    
                    self.printer.print_msg(f"Identified GraphQL engine: {engine_name}", status="success")
                    
                    # Check for known CVEs
                    cves = engine_info.get("cve", [])
                    if cves:
                        cve_str = ", ".join(cves)
                        self.printer.print_msg(f"Known CVEs for this engine: {cve_str}", status="warning")
                        
                        # Add as a finding
                        finding = Finding(
                            title=f"GraphQL Engine Identified: {engine_name}",
                            severity="LOW",
                            description=f"The GraphQL engine was identified as {engine_name}. This implementation has known vulnerabilities: {cve_str}",
                            endpoint=self.client.endpoint,
                            impact="May be vulnerable to known exploits",
                            remediation="Update to the latest version of the GraphQL engine"
                        )
                        self.findings.append(finding)
                    else:
                        # Still add as informational finding
                        finding = Finding(
                            title=f"GraphQL Engine Identified: {engine_name}",
                            severity="INFO",
                            description=f"The GraphQL engine was identified as {engine_name}.",
                            endpoint=self.client.endpoint,
                            impact="None - informational only",
                            remediation="None required"
                        )
                        self.findings.append(finding)
                    
                    return {
                        "engine_id": engine_id,
                        "name": engine_name,
                        "url": engine_info.get("url", ""),
                        "technologies": engine_info.get("tech", []),
                        "cves": cves
                    }
            except Exception as e:
                self.printer.print_msg(f"Error testing for {engine_id}: {str(e)}", status="error")
                
        self.printer.print_msg("Could not identify GraphQL engine", status="warning")
        return None
        
    def get_findings(self) -> List[Finding]:
        """
        Get all findings from fingerprinting.
        
        Returns:
            List[Finding]: List of findings
        """
        return self.findings