"""
Security testing modules for GraphQL endpoints

Author: Aleksa Zatezalo
Version: 3.0
"""

import asyncio
import time
import json
from typing import Dict, List, Optional, Any


class SecurityTester:
    """
    A unified security testing class for GraphQL endpoints.
    """
    
    def __init__(self, scanner, proxy: Optional[str] = None):
        """
        Initialize with a GraphQL scanner.
        
        Args:
            scanner: GraphQLScanner instance
            proxy: Optional proxy string to route requests through
        """
        self.scanner = scanner
        self.message = self.scanner.message
        self.client = self.scanner.client
        self.schema = self.scanner.schema
        self.proxy = proxy
        
        # Store fingerprinting results
        self.engine_info = None
        
        # Set debug mode according to scanner
        self.debug_mode = scanner.debug_mode
        
        # Configure proxy if provided
        if self.proxy and not self.client.proxy_url:
            self.message.printMsg(f"Configuring security tester to use proxy: {self.proxy}", status="info")
            self.client.set_proxy_from_string(self.proxy)
    
    async def fingerprint_server(self) -> Dict:
        """
        Fingerprint the GraphQL server to identify implementation details.
        
        Returns:
            Dict: Server implementation details
        """
        self.message.printMsg("Fingerprinting GraphQL server...", status="log")
        if self.proxy:
            self.message.printMsg(f"Using proxy: {self.proxy} for fingerprinting", status="info")
        
        try:
            # Use the scanner's detect_engine method
            self.engine_info = await self.scanner.detect_engine()
            
            # Print engine information
            if self.engine_info["name"] != "unknown":
                self.message.printMsg(
                    f"Server identified as: {self.engine_info['name']} "
                    f"({', '.join(self.engine_info['technology'])})", 
                    status="success"
                )
            else:
                self.message.printMsg(
                    "Could not identify GraphQL server implementation",
                    status="warning"
                )
                
            return self.engine_info
            
        except Exception as e:
            self.message.printMsg(f"Error during fingerprinting: {str(e)}", status="failed")
            return {"name": "unknown", "technology": ["Unknown"], "error": str(e)}
    
    async def test_introspection(self) -> Dict:
        """
        Test if introspection is enabled.
        
        Returns:
            Dict: Test result
        """
        self.message.printMsg("Testing for introspection...", status="log")
        if self.proxy:
            self.message.printMsg(f"Using proxy: {self.proxy} for introspection test", status="info")
        
        result = {
            "name": "Introspection Enabled",
            "description": "GraphQL introspection allows clients to query the schema structure",
            "severity": "MEDIUM",
            "vulnerable": False,
            "details": None,
            "curl_command": None
        }
        
        try:
            has_introspection = await self.client.has_introspection()
            
            # Store curl command
            curl_command = self.client.generate_curl()
            result["curl_command"] = curl_command
            
            if has_introspection:
                result["vulnerable"] = True
                result["details"] = "The server has introspection enabled, which can expose sensitive schema information"
                self.message.printMsg("Vulnerability found: Introspection is enabled", status="warning")
                self.message.printMsg(f"Introspection testing curl command: {curl_command}", status="info")
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
        if self.proxy:
            self.message.printMsg(f"Using proxy: {self.proxy} for GET method test", status="info")
        
        result = {
            "name": "GET-based Queries",
            "description": "GraphQL queries allowed over GET requests",
            "severity": "MEDIUM",
            "vulnerable": False,
            "details": None,
            "curl_command": None
        }
        
        try:
            # Save the original endpoint
            original_endpoint = self.client.endpoint
            
            # Simple query
            query = "query { __typename }"
            
            # Try using GET method
            self.message.printMsg("Sending GET query through proxy", status="info")
            get_result = await self.client.graphql(query, method="GET")
            
            # Store curl command
            curl_command = self.client.generate_curl()
            result["curl_command"] = curl_command
            
            # Restore endpoint
            self.client.set_endpoint(original_endpoint)
            
            # Check if the query was successful
            if get_result.get("data", {}).get("__typename") is not None:
                result["vulnerable"] = True
                result["details"] = "The server allows GraphQL queries over GET requests, which may enable CSRF attacks"
                self.message.printMsg("Vulnerability found: GET-based queries are allowed", status="warning")
                self.message.printMsg(f"GET method testing curl command: {curl_command}", status="info")
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
        if self.proxy:
            self.message.printMsg(f"Using proxy: {self.proxy} for CSRF test", status="info")
        
        result = {
            "name": "CSRF Vulnerability",
            "description": "Server accepts form-encoded requests, enabling potential CSRF",
            "severity": "MEDIUM",
            "vulnerable": False,
            "details": None,
            "curl_command": None
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
            self.message.printMsg("Sending form-encoded request through proxy", status="info")
            csrf_result = await self.client.request("POST", data=form_data)
            
            # Generate curl command for reference
            curl_command = self.client.generate_curl()
            result["curl_command"] = curl_command
            
            # Restore original headers
            self.client.headers = original_headers
            
            # Check if the query was successful
            if csrf_result.get("data", {}).get("__typename") is not None:
                result["vulnerable"] = True
                result["details"] = "The server accepts form-encoded requests, which may enable CSRF attacks"
                self.message.printMsg("Vulnerability found: Form-encoded requests are accepted", status="warning")
                self.message.printMsg(f"CSRF testing curl command: {curl_command}", status="info")
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
        if self.proxy:
            self.message.printMsg(f"Using proxy: {self.proxy} for batch query test", status="info")
        
        result = {
            "name": "Batch Query Support",
            "description": "Server allows batch queries which can be abused for DoS",
            "severity": "LOW",
            "vulnerable": False,
            "details": None,
            "curl_command": None
        }
        
        try:
            # Create a batch of simple queries
            batch = [
                {"query": "query { __typename }"},
                {"query": "query { __typename }"},
                {"query": "query { __typename }"}
            ]
            
            # Send the batch
            self.message.printMsg("Sending batch queries through proxy", status="info")
            batch_result = await self.client.request("POST", json=batch)
            
            # Generate curl command for reference
            curl_command = self.client.generate_curl()
            result["curl_command"] = curl_command
            
            # Check if the batch was processed
            if isinstance(batch_result, list) and len(batch_result) > 0:
                result["vulnerable"] = True
                result["details"] = "The server supports batch queries, which could be abused for DoS attacks"
                self.message.printMsg("Potential vulnerability: Batch queries are supported", status="warning")
                self.message.printMsg(f"Batch query testing curl command: {curl_command}", status="info")
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
        if self.proxy:
            self.message.printMsg(f"Using proxy: {self.proxy} for field suggestion test", status="info")
        
        result = {
            "name": "Field Suggestions",
            "description": "Server provides field suggestions in error messages",
            "severity": "LOW",
            "vulnerable": False,
            "details": None,
            "curl_command": None,
            "error_messages": []
        }
        
        try:
            # Query with invalid field
            query = "query { invalidField }"
            
            # Send the query
            self.message.printMsg("Sending invalid field query through proxy", status="info")
            query_result = await self.client.graphql(query)
            
            # Generate curl command for reference
            curl_command = self.client.generate_curl()
            result["curl_command"] = curl_command
            
            # Check for "Did you mean" in error messages
            errors = query_result.get("errors", [])
            error_messages = []
            for error in errors:
                error_msg = str(error.get("message", ""))
                error_messages.append(error_msg)
                if "Did you mean" in error_msg:
                    result["vulnerable"] = True
                    result["details"] = "The server provides field suggestions in error messages, which may leak schema information"
                    self.message.printMsg("Potential vulnerability: Field suggestions are enabled", status="warning")
                    self.message.printMsg(f"Field suggestions testing curl command: {curl_command}", status="info")
                    break
            
            # Store error messages in result
            result["error_messages"] = error_messages
            
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
        if self.proxy:
            self.message.printMsg(f"Using proxy: {self.proxy} for DoS test", status="info")
        
        result = {
            "name": "DoS Vulnerability",
            "description": "Server is vulnerable to DoS attacks via complex queries",
            "severity": "HIGH",
            "vulnerable": False,
            "details": None,
            "response_time": None,
            "curl_command": None
        }
        
        # Skip if schema not available
        if not self.schema:
            result["details"] = "Cannot run DoS tests without schema information"
            return result
        
        try:
            # Generate a potentially expensive query
            query = self.schema.generate_dos_query()
            
            self.message.printMsg("Sending complex query for DoS testing through proxy", status="info")
            self.message.printMsg("Query length: " + str(len(query)) + " characters", status="info")
            
            # Set a timeout for the request
            start_time = time.time()
            
            # Send the query
            query_result = await self.client.request("POST", json={"query": query}, timeout=15)
            
            # Calculate response time
            response_time = time.time() - start_time
            result["response_time"] = response_time
            
            # Generate curl command for reference
            curl_command = self.client.generate_curl()
            result["curl_command"] = curl_command
            
            # Check if the response was slow
            if response_time > 5.0:
                result["vulnerable"] = True
                result["details"] = f"The server took {response_time:.2f} seconds to respond to a complex query"
                self.message.printMsg(f"Potential DoS vulnerability: Slow response time ({response_time:.2f}s)", status="warning")
                self.message.printMsg(f"DoS testing curl command: {curl_command}", status="info")
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
        Test for potential injection vulnerabilities across all fields with arguments.
        
        Returns:
            Dict: Test result
        """
        self.message.printMsg("Testing for injection vulnerabilities across all fields...", status="log")
        if self.proxy:
            self.message.printMsg(f"Using proxy: {self.proxy} for comprehensive injection testing", status="info")
        
        result = {
            "name": "Injection Vulnerability",
            "description": "Server is vulnerable to injection attacks",
            "severity": "HIGH",
            "vulnerable": False,
            "details": None,
            "vulnerable_fields": [],
            "curl_commands": []
        }
        
        # Skip if schema not available
        if not self.schema:
            result["details"] = "Cannot run injection tests without schema information"
            return result
        
        # Get ALL fields with arguments for testing, not just string or ID types
        injectable_fields = self.schema.get_injectable_fields()
        
        if not injectable_fields["query"] and not injectable_fields["mutation"]:
            result["details"] = "No fields with arguments found for testing"
            return result
        
        # Count for logging
        total_fields = len(injectable_fields["query"]) + len(injectable_fields["mutation"])
        self.message.printMsg(f"Testing injection on {total_fields} fields with arguments", status="info")
        
        # Test payloads
        payloads = [
            # SQL injection
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "1 OR 1=1",
            "1' OR '1'='1",
            # NoSQL injection
            "{\"$gt\": \"\"}",
            "{\"$ne\": null}",
            # Command injection
            "; ls -la",
            "| cat /etc/passwd",
            "`id`",
            "$(cat /etc/passwd)",
            # JavaScript injection
            "\"); alert(\"XSS",
            "function(){return true;}()",
            # Path traversal
            "../../../etc/passwd",
            "file:///etc/passwd",
            # Other payloads that might cause errors revealing info
            "null",
            "true",
            "false",
            "undefined",
            "[]",
            "{}",
            "\" SLEEP(5) --",
            "' WAITFOR DELAY '0:0:5' --",
        ]
        
        # Define indicators of successful injection
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
            "invalid JSON",
            "cannot read property",
            "undefined index",
            "typeerror",
            "unexpected token",
            "file not found",
            "timeout",
            "database error",
            "exception",
            "stack trace",
            "line number",
            "internal server",
            "unhandled exception",
            "invalid input syntax",
            "violates foreign key constraint"
        ]
        
        # Track vulnerable fields
        vulnerable_fields = []
        curl_commands = []
        
        # Check for username/password credentials
        username = self.scanner.username
        password = self.scanner.password
        
        # Test query fields
        for field_info in injectable_fields["query"]:
            field_name = field_info["field"]
            arg_name = field_info["arg"]
            arg_type = field_info["type"]
            
            self.message.printMsg(f"Testing query field: {field_name}.{arg_name} (Type: {arg_type})", status="log")
            
            # Select appropriate payloads based on type
            selected_payloads = payloads
            
            # Test each payload
            for payload in selected_payloads:
                # Format the argument value based on its type
                formatted_payload = self._format_payload_for_type(payload, arg_type)
                if formatted_payload is None:
                    continue  # Skip payloads that can't be formatted for this type
                    
                # Construct query with credentials if applicable
                query_parts = [f"{arg_name}: {formatted_payload}"]
                
                # Add credentials if the field has username/password arguments
                field_args = self.schema.query_fields.get(field_name, {}).get("args", [])
                arg_names = [arg.get("name", "") for arg in field_args]
                
                if "username" in arg_names and username:
                    query_parts.append(f"username: \"{username}\"")
                if "password" in arg_names and password:
                    query_parts.append(f"password: \"{password}\"")
                
                query = f"""
                query {{
                    {field_name}({", ".join(query_parts)})
                }}
                """
                
                # Send query
                try:
                    result_data = await self.client.graphql(query)
                    
                    # Store curl command for this test
                    curl_command = self.client.generate_curl()
                    
                    # Check for signs of successful injection
                    response_text = json.dumps(result_data)
                    
                    # Check for indicators of successful injection
                    for indicator in indicators:
                        if indicator.lower() in response_text.lower():
                            vulnerable_field = {
                                "field": field_name,
                                "arg": arg_name,
                                "payload": formatted_payload,
                                "operation": "query"
                            }
                            vulnerable_fields.append(vulnerable_field)
                            curl_commands.append({
                                "field": f"{field_name}.{arg_name}",
                                "payload": formatted_payload,
                                "curl": curl_command
                            })
                            self.message.printMsg(
                                f"Potential injection vulnerability found in {field_name}.{arg_name} with payload: {formatted_payload}", 
                                status="warning"
                            )
                            break
                except Exception as e:
                    # Log exception but continue testing
                    if self.debug_mode:
                        self.message.printMsg(
                            f"Error testing {field_name}.{arg_name} with payload {formatted_payload}: {str(e)}", 
                            status="warning"
                        )
        
        # Test mutation fields
        for field_info in injectable_fields["mutation"]:
            field_name = field_info["field"]
            arg_name = field_info["arg"]
            arg_type = field_info["type"]
            
            self.message.printMsg(f"Testing mutation field: {field_name}.{arg_name} (Type: {arg_type})", status="log")
            
            # Select appropriate payloads based on type
            selected_payloads = payloads
            
            # Test each payload
            for payload in selected_payloads:
                # Format the argument value based on its type
                formatted_payload = self._format_payload_for_type(payload, arg_type)
                if formatted_payload is None:
                    continue  # Skip payloads that can't be formatted for this type
                    
                # Construct mutation with credentials if applicable
                mutation_parts = [f"{arg_name}: {formatted_payload}"]
                
                # Add credentials if the field has username/password arguments
                field_args = self.schema.mutation_fields.get(field_name, {}).get("args", [])
                arg_names = [arg.get("name", "") for arg in field_args]
                
                if "username" in arg_names and username:
                    mutation_parts.append(f"username: \"{username}\"")
                if "password" in arg_names and password:
                    mutation_parts.append(f"password: \"{password}\"")
                
                query = f"""
                mutation {{
                    {field_name}({", ".join(mutation_parts)})
                }}
                """
                
                # Send mutation
                try:
                    result_data = await self.client.graphql(query)
                    
                    # Store curl command for this test
                    curl_command = self.client.generate_curl()
                    
                    # Check for signs of successful injection
                    response_text = json.dumps(result_data)
                    
                    # Check for indicators of successful injection
                    for indicator in indicators:
                        if indicator.lower() in response_text.lower():
                            vulnerable_field = {
                                "field": field_name,
                                "arg": arg_name,
                                "payload": formatted_payload,
                                "operation": "mutation"
                            }
                            vulnerable_fields.append(vulnerable_field)
                            curl_commands.append({
                                "field": f"{field_name}.{arg_name}",
                                "payload": formatted_payload,
                                "curl": curl_command
                            })
                            self.message.printMsg(
                                f"Potential injection vulnerability found in {field_name}.{arg_name} with payload: {formatted_payload}", 
                                status="warning"
                            )
                            break
                except Exception as e:
                    # Log exception but continue testing
                    if self.debug_mode:
                        self.message.printMsg(
                            f"Error testing {field_name}.{arg_name} with payload {formatted_payload}: {str(e)}", 
                            status="warning"
                        )
        
        # Update result based on findings
        if vulnerable_fields:
            result["vulnerable"] = True
            result["details"] = f"Found {len(vulnerable_fields)} potential injection points across {total_fields} tested fields"
            result["vulnerable_fields"] = vulnerable_fields
            result["curl_commands"] = curl_commands
            self.message.printMsg(f"Potential injection vulnerability: {len(vulnerable_fields)} fields vulnerable out of {total_fields} tested", status="warning")
        else:
            self.message.printTestResult("Injection Protection", vulnerable=False,
                details=f"No injection vulnerabilities detected across {total_fields} tested fields")
            
        return result

    def _format_payload_for_type(self, payload: str, arg_type: str) -> Optional[str]:
        """
        Format a payload according to the GraphQL type.
        
        Args:
            payload: Raw payload string
            arg_type: GraphQL type name
            
        Returns:
            Optional[str]: Formatted payload or None if not applicable for this type
        """
        # For String and ID types, wrap in quotes
        if arg_type in ("String", "ID"):
            return f"\"{payload}\""
        
        # For Int type, try to make payload numeric if possible
        elif arg_type == "Int":
            if payload.isdigit() or payload.replace('-', '', 1).isdigit():
                return payload
            elif payload in ("true", "false", "null"):
                return payload
            else:
                # Try to extract numbers from string payloads
                import re
                numbers = re.findall(r'-?\d+', payload)
                if numbers:
                    return numbers[0]
                return "1"  # Default to 1 if no numbers found
        
        # For Float type, similar to Int but with decimal point
        elif arg_type == "Float":
            if payload.replace('.', '', 1).isdigit() or payload.replace('-', '', 1).replace('.', '', 1).isdigit():
                return payload
            elif payload in ("true", "false", "null"):
                return payload
            else:
                # Try to extract floating point numbers from string payloads
                import re
                floats = re.findall(r'-?\d+\.?\d*', payload)
                if floats:
                    return floats[0]
                return "1.0"  # Default to 1.0 if no floats found
        
        # For Boolean type
        elif arg_type == "Boolean":
            if payload.lower() in ("true", "false"):
                return payload.lower()
            elif payload.isdigit():
                return "true" if int(payload) != 0 else "false"
            else:
                return "true"  # Default to true
        
        # For custom types, try to use JSON notation
        elif payload.startswith("{") and payload.endswith("}"):
            return payload
        
        # Fallback to string representation for unknown types
        else:
            if payload.isdigit() or payload.replace('-', '', 1).isdigit():
                return payload
            elif payload.lower() in ("true", "false", "null"):
                return payload
            else:
                return f"\"{payload}\""
        
    async def run_all_tests(self, run_dos: bool = False) -> Dict:
        """
        Run all security tests and return combined results.
        
        Args:
            run_dos: Whether to run DoS tests (may impact performance)
            
        Returns:
            Dict: Combined test results
        """
        start_time = time.time()
        
        # First, fingerprint the server
        fingerprint_result = await self.fingerprint_server()
        
        # Define tests to run
        tests = [
            self.test_introspection(),
            self.test_get_method(),
            self.test_csrf(),
            self.test_batch_queries(),
            self.test_field_suggestions(),
            self.test_injection_vulnerability()
        ]
        
        # Optionally add DoS test
        if run_dos and self.schema:
            tests.append(self.test_dos_vulnerability())
            
        # Run all tests concurrently
        test_results = await asyncio.gather(*tests)
        
        # Count vulnerabilities by severity
        high_count = 0
        medium_count = 0
        low_count = 0
        vuln_count = 0
        
        for result in test_results:
            if result.get("vulnerable", False):
                vuln_count += 1
                severity = result.get("severity", "").upper()
                if severity == "HIGH":
                    high_count += 1
                elif severity == "MEDIUM":
                    medium_count += 1
                elif severity == "LOW":
                    low_count += 1
        
        # Generate results
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Print summary
        self.message.printScanSummary(
            tests_run=len(test_results),
            vulnerabilities_found=vuln_count,
            scan_time=scan_duration
        )
        
        # Include server fingerprinting in results
        server_info = {
            "name": "Server Information",
            "description": "Information about the GraphQL server implementation",
            "severity": "INFO",
            "vulnerable": False,
            "details": f"Server identified as: {fingerprint_result.get('name', 'Unknown')} "
                      f"({', '.join(fingerprint_result.get('technology', ['Unknown']))})",
            "server_info": fingerprint_result
        }
        
        # Get response time statistics
        response_stats = self.client.get_response_time_stats()
        
        return {
            "tests": [server_info] + test_results,
            "summary": {
                "total": len(test_results),
                "vulnerabilities": vuln_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "duration": scan_duration,
                "server_info": fingerprint_result,
                "response_stats": response_stats
            }
        }