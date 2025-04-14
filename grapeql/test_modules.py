"""
Security testing modules for GraphQL endpoints

Author: Aleksa Zatezalo
Version: 3.0
"""

import asyncio
import time
from typing import Dict, List, Optional, Any
import json


class SecurityTester:
    """
    A unified security testing class for GraphQL endpoints.
    """
    
    def __init__(self, scanner):
        """
        Initialize with a GraphQL scanner.
        
        Args:
            scanner: GraphQLScanner instance
        """
        self.scanner = scanner
        self.message = self.scanner.message
        self.client = self.scanner.client
        self.schema = self.scanner.schema
    
    async def test_introspection(self) -> Dict:
        """
        Test if introspection is enabled.
        
        Returns:
            Dict: Test result
        """
        self.message.printMsg("Testing for introspection...", status="log")
        
        result = {
            "name": "Introspection Enabled",
            "description": "GraphQL introspection allows clients to query the schema structure",
            "severity": "MEDIUM",
            "vulnerable": False,
            "details": None
        }
        
        try:
            has_introspection = await self.client.has_introspection()
            
            if has_introspection:
                result["vulnerable"] = True
                result["details"] = "The server has introspection enabled, which can expose sensitive schema information"
                self.message.printMsg("Vulnerability found: Introspection is enabled", status="warning")
            else:
                self.message.printTestResult("Introspection", vulnerable=False,
                    details="Introspection is properly disabled")
                
            return result
            
        except Exception as e:
            result["details"] = f"Error testing introspection: {str(e)}"
            return result
    
    async def test_get_method(self) -> Dict:
        """
        Test if the endpoint allows GraphQL queries over GET requests.
        
        Returns:
            Dict: Test result
        """
        self.message.printMsg("Testing for GET-based queries...", status="log")
        
        result = {
            "name": "GET-based Queries",
            "description": "GraphQL queries allowed over GET requests",
            "severity": "MEDIUM",
            "vulnerable": False,
            "details": None
        }
        
        try:
            # Save the original endpoint
            original_endpoint = self.client.endpoint
            
            # Simple query
            query = "query { __typename }"
            
            # Try using GET method
            get_result = await self.client.graphql(query, method="GET")
            
            # Restore endpoint
            self.client.set_endpoint(original_endpoint)
            
            # Check if the query was successful
            if get_result.get("data", {}).get("__typename") is not None:
                result["vulnerable"] = True
                result["details"] = "The server allows GraphQL queries over GET requests, which may enable CSRF attacks"
                self.message.printMsg("Vulnerability found: GET-based queries are allowed", status="warning")
            else:
                self.message.printTestResult("GET Method Support", vulnerable=False,
                    details="Server properly restricts queries over GET requests")
                
            return result
            
        except Exception as e:
            result["details"] = f"Error testing GET method: {str(e)}"
            return result
    
    async def test_csrf(self) -> Dict:
        """
        Test for potential CSRF vulnerabilities.
        
        Returns:
            Dict: Test result
        """
        self.message.printMsg("Testing for CSRF vulnerabilities...", status="log")
        
        result = {
            "name": "CSRF Vulnerability",
            "description": "Server accepts form-encoded requests, enabling potential CSRF",
            "severity": "MEDIUM",
            "vulnerable": False,
            "details": None
        }
        
        try:
            # Save original content type
            original_headers = dict(self.client.headers)
            
            # Set form-urlencoded content type
            self.client.set_header("Content-Type", "application/x-www-form-urlencoded")
            
            # Simple query
            query = "query { __typename }"
            form_data = {"query": query}
            
            # Make a direct request
            csrf_result = await self.client.request("POST", data=form_data)
            
            # Restore original headers
            self.client.headers = original_headers
            
            # Check if the query was successful
            if csrf_result.get("data", {}).get("__typename") is not None:
                result["vulnerable"] = True
                result["details"] = "The server accepts form-encoded requests, which may enable CSRF attacks"
                self.message.printMsg("Vulnerability found: Form-encoded requests are accepted", status="warning")
            else:
                self.message.printTestResult("CSRF Protection", vulnerable=False,
                    details="Server properly validates Content-Type header for requests")
                
            return result
            
        except Exception as e:
            # Restore original headers in case of error
            self.client.headers = original_headers
            result["details"] = f"Error testing CSRF: {str(e)}"
            return result
    
    async def test_batch_queries(self) -> Dict:
        """
        Test if the endpoint allows batch queries.
        
        Returns:
            Dict: Test result
        """
        self.message.printMsg("Testing for batch query support...", status="log")
        
        result = {
            "name": "Batch Query Support",
            "description": "Server allows batch queries which can be abused for DoS",
            "severity": "LOW",
            "vulnerable": False,
            "details": None
        }
        
        try:
            # Create a batch of simple queries
            batch = [
                {"query": "query { __typename }"},
                {"query": "query { __typename }"},
                {"query": "query { __typename }"}
            ]
            
            # Send the batch
            batch_result = await self.client.request("POST", json=batch)
            
            # Check if the batch was processed
            if isinstance(batch_result, list) and len(batch_result) > 0:
                result["vulnerable"] = True
                result["details"] = "The server supports batch queries, which could be abused for DoS attacks"
                self.message.printMsg("Potential vulnerability: Batch queries are supported", status="warning")
            else:
                self.message.printTestResult("Batch Query Support", vulnerable=False,
                    details="Server does not support batch queries")
                
            return result
            
        except Exception as e:
            result["details"] = f"Error testing batch queries: {str(e)}"
            return result
    
    async def test_field_suggestions(self) -> Dict:
        """
        Test if the server provides field suggestions in error messages.
        
        Returns:
            Dict: Test result
        """
        self.message.printMsg("Testing for field suggestions in errors...", status="log")
        
        result = {
            "name": "Field Suggestions",
            "description": "Server provides field suggestions in error messages",
            "severity": "LOW",
            "vulnerable": False,
            "details": None
        }
        
        try:
            # Query with invalid field
            query = "query { invalidField }"
            
            # Send the query
            query_result = await self.client.graphql(query)
            
            # Check for "Did you mean" in error messages
            errors = query_result.get("errors", [])
            for error in errors:
                error_msg = str(error.get("message", ""))
                if "Did you mean" in error_msg:
                    result["vulnerable"] = True
                    result["details"] = "The server provides field suggestions in error messages, which may leak schema information"
                    self.message.printMsg("Potential vulnerability: Field suggestions are enabled", status="warning")
                    break
            
            if not result["vulnerable"]:
                self.message.printTestResult("Field Suggestions", vulnerable=False,
                    details="Server does not provide field suggestions in error messages")
                
            return result
            
        except Exception as e:
            result["details"] = f"Error testing field suggestions: {str(e)}"
            return result
    
    async def test_dos_vulnerability(self) -> Dict:
        """
        Test for potential DoS vulnerabilities.
        
        Returns:
            Dict: Test result
        """
        self.message.printMsg("Testing for DoS vulnerabilities...", status="log")
        
        result = {
            "name": "DoS Vulnerability",
            "description": "Server is vulnerable to DoS attacks via complex queries",
            "severity": "HIGH",
            "vulnerable": False,
            "details": None
        }
        
        # Skip if schema not available
        if not self.schema:
            result["details"] = "Cannot run DoS tests without schema information"
            return result
        
        try:
            # Generate a potentially expensive query
            query = self.schema.generate_dos_query()
            
            # Set a timeout for the request
            start_time = time.time()
            
            # Send the query
            query_result = await self.client.request("POST", json={"query": query}, timeout=10)
            
            # Calculate response time
            response_time = time.time() - start_time
            
            # Check if the response was slow
            if response_time > 5.0:
                result["vulnerable"] = True
                result["details"] = f"The server took {response_time:.2f} seconds to respond to a complex query"
                self.message.printMsg(f"Potential DoS vulnerability: Slow response time ({response_time:.2f}s)", status="warning")
            else:
                self.message.printTestResult("DoS Protection", vulnerable=False,
                    details=f"Server handled complex query efficiently ({response_time:.2f}s)")
                
            return result
            
        except asyncio.TimeoutError:
            result["vulnerable"] = True
            result["details"] = "The server timed out while processing a complex query"
            self.message.printMsg("Potential DoS vulnerability: Server timed out", status="warning")
            return result
        except Exception as e:
            result["details"] = f"Error testing DoS vulnerability: {str(e)}"
            return result
    
    async def test_injection_vulnerability(self) -> Dict:
        """
        Test for potential injection vulnerabilities.
        
        Returns:
            Dict: Test result
        """
        self.message.printMsg("Testing for injection vulnerabilities...", status="log")
        
        result = {
            "name": "Injection Vulnerability",
            "description": "Server is vulnerable to injection attacks",
            "severity": "HIGH",
            "vulnerable": False,
            "details": None,
            "vulnerable_fields": []
        }
        
        # Skip if schema not available
        if not self.schema:
            result["details"] = "Cannot run injection tests without schema information"
            return result
        
        # Get fields that might be vulnerable to injection
        injectable_fields = self.schema.get_injectable_fields()
        
        if not injectable_fields["query"] and not injectable_fields["mutation"]:
            result["details"] = "No fields found that could be tested for injection"
            return result
        
        # Test payloads
        payloads = [
            # SQL injection
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            # Command injection
            "; ls -la",
            "| cat /etc/passwd",
            # NoSQL injection
            '{\"$gt\": \"\"}',
            '{\"$ne\": null}'
        ]
        
        # Track vulnerable fields
        vulnerable_fields = []
        
        # Test query fields
        for field_info in injectable_fields["query"]:
            field_name = field_info["field"]
            arg_name = field_info["arg"]
            
            self.message.printMsg(f"Testing query field: {field_name}.{arg_name}", status="log")
            
            for payload in payloads:
                # Construct query
                query = f"""
                query {{
                    {field_name}({arg_name}: "{payload}")
                }}
                """
                
                # Send query
                result_data = await self.client.graphql(query)
                
                # Check for signs of successful injection
                response_text = json.dumps(result_data)
                
                # Check for indicators of successful injection
                indicators = [
                    "syntax error",
                    "SQLITE_ERROR",
                    "MySQL",
                    "PostgreSQL",
                    "ENOENT",
                    "command not found",
                    "EACCES",
                    "permission denied",
                    "root:",
                    "/bin/bash",
                    "invalid JSON"
                ]
                
                for indicator in indicators:
                    if indicator.lower() in response_text.lower():
                        vulnerable_fields.append({
                            "field": field_name,
                            "arg": arg_name,
                            "payload": payload,
                            "operation": "query"
                        })
                        break
        
        # Test mutation fields
        for field_info in injectable_fields["mutation"]:
            field_name = field_info["field"]
            arg_name = field_info["arg"]
            
            self.message.printMsg(f"Testing mutation field: {field_name}.{arg_name}", status="log")
            
            for payload in payloads:
                # Construct mutation
                query = f"""
                mutation {{
                    {field_name}({arg_name}: "{payload}")
                }}
                """
                
                # Send mutation
                result_data = await self.client.graphql(query)
                
                # Check for signs of successful injection
                response_text = json.dumps(result_data)
                
                # Check for indicators of successful injection
                indicators = [
                    "syntax error",
                    "SQLITE_ERROR",
                    "MySQL",
                    "PostgreSQL",
                    "E"]