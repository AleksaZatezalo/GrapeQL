"""
Author: Aleksa Zatezalo
Version: 2.1
Date: April 2025
Description: GraphQL security testing module for informational issues with improved reporting.
"""

import asyncio
import time
from typing import Dict, List, Optional
from .base_tester import BaseTester

class seeds(BaseTester):
    """
    A class for testing GraphQL endpoints for various security vulnerabilities.
    Generates targeted queries based on introspection of the actual schema.
    """

    def __init__(self):
        """Initialize the security tester with default settings and printer."""
        super().__init__()
        self.debug_mode = False

    def getError(self, response_data: Dict) -> str:
        """Extract error message from GraphQL response."""
        if isinstance(response_data, dict):
            errors = response_data.get("errors", [])
            if errors and isinstance(errors, list):
                return str(errors[0].get("message", ""))
        return ""

    async def checkFieldSuggestions(self) -> Dict:
        """Check if field suggestions are enabled."""

        res = {
            "result": False,
            "title": "Field suggestions are enabled",
            "description": "Field Suggestions are enabled",
            "impact": "Information Leakage - /" + self.client.endpoint.rsplit("/", 1)[-1] if self.client.endpoint else "unknown",
            "severity": "LOW",
            "color": "blue",
            "curl_verify": "",
        }

        query = "query cop { __schema { directive } }"
        if self.debug_mode:
            self.client.set_header("X-GraphQL-Cop-Test", res["title"])

        response_data = await self.client.graphql(query)
        res["curl_verify"] = self.client.generate_curl()

        try:
            if "Did you mean" in str(response_data.get("errors", [])):
                res["result"] = True
        except:
            pass
            
        # Print result using new method
        if res["result"]:
            self.message.printMsg(
                f"Low vulnerability: {res['title']}", status="warning"
            )
        else:
            self.message.printTestResult("Field Suggestions", vulnerable=False, 
                details="Server does not expose field suggestions in error messages")
            
        return res

    async def checkGetBasedMutation(self) -> Dict:
        """Check if mutations are allowed over GET."""

        res = {
            "result": False,
            "title": "Mutation is allowed over GET (possible CSRF)",
            "description": "GraphQL mutations allowed using the GET method",
            "impact": "Possible Cross Site Request Forgery - /" + self.client.endpoint.rsplit("/", 1)[-1] if self.client.endpoint else "unknown",
            "severity": "MEDIUM",
            "color": "yellow",
            "curl_verify": "",
        }

        query = "mutation cop {__typename}"
        if self.debug_mode:
            self.client.set_header("X-GraphQL-Cop-Test", res["title"])

        try:
            response_data = await self.client.graphql(query, method="GET")
            res["curl_verify"] = self.client.generate_curl()
            if response_data.get("data", {}).get("__typename"):
                res["result"] = True
        except:
            pass

        # Print result using new method
        if res["result"]:
            self.message.printMsg(
                f"Medium vulnerability: {res['title']}", status="warning"
            )
        else:
            self.message.printTestResult("GET-based Mutations", vulnerable=False,
                details="Server correctly blocks mutations over GET requests")
            
        return res

    async def checkGetMethodSupport(self) -> Dict:
        """Check for GET method query support."""

        res = {
            "result": False,
            "title": "Queries allowed using GET requests (possible CSRF)",
            "description": "GraphQL queries allowed using the GET method",
            "impact": "Possible Cross Site Request Forgery (CSRF) - /" + self.client.endpoint.rsplit("/", 1)[-1] if self.client.endpoint else "unknown",
            "severity": "MEDIUM",
            "color": "yellow",
            "curl_verify": "",
        }

        query = "query cop {__typename}"
        if self.debug_mode:
            self.client.set_header("X-GraphQL-Cop-Test", res["title"])

        try:
            response_data = await self.client.graphql(query, method="GET")
            res["curl_verify"] = self.client.generate_curl()

            # Check if query was successful
            if response_data and isinstance(response_data, dict):
                if response_data.get("data", {}).get("__typename") is not None:
                    res["result"] = True
                elif "errors" in response_data and not any(
                    "method not allowed" in str(err.get("message", "")).lower()
                    for err in response_data.get("errors", [])
                ):
                    res["result"] = True

        except Exception as e:
            self.message.printMsg(
                f"Error in GET method check: {str(e)}", status="failed"
            )

        # Print result using new method
        if res["result"]:
            self.message.printMsg(
                f"Medium vulnerability: {res['title']}", status="warning"
            )
        else:
            self.message.printTestResult("GET Method Support", vulnerable=False,
                details="Server correctly restricts queries over GET requests")
            
        return res

    async def checkPostBasedCsrf(self) -> Dict:
        """Check for POST-based CSRF vulnerabilities."""

        res = {
            "result": False,
            "title": "POST based url-encoded query (possible CSRF)",
            "description": "GraphQL accepts non-JSON queries over POST",
            "impact": "Possible Cross Site Request Forgery - /" + self.client.endpoint.rsplit("/", 1)[-1] if self.client.endpoint else "unknown",
            "severity": "MEDIUM",
            "color": "yellow",
            "curl_verify": "",
        }

        query = "query cop { __typename }"
        if self.debug_mode:
            self.client.set_header("X-GraphQL-Cop-Test", res["title"])

        # Save original content type
        original_content_type = self.client.get_headers().get("Content-Type")

        try:
            # Test with form-urlencoded content type
            self.client.set_header("Content-Type", "application/x-www-form-urlencoded")
            
            # Use raw request instead of graphql method
            form_data = {"query": query}
            response_data = await self.client.request("POST", data=form_data)
            res["curl_verify"] = self.client.generate_curl()

            # Check if query was successful
            if response_data and isinstance(response_data, dict):
                if response_data.get("data", {}).get("__typename") is not None:
                    res["result"] = True
                elif "errors" in response_data and not any(
                    "content type not supported" in str(err.get("message", "")).lower()
                    for err in response_data.get("errors", [])
                ):
                    res["result"] = True

        except Exception as e:
            self.message.printMsg(
                f"Error in POST CSRF check: {str(e)}", status="failed"
            )
        finally:
            # Restore original content type
            if original_content_type:
                self.client.set_header("Content-Type", original_content_type)
            else:
                self.client.set_header("Content-Type", "application/json")

        # Print result using new method
        if res["result"]:
            self.message.printMsg(
                f"Medium vulnerability: {res['title']}", status="warning"
            )
        else:
            self.message.printTestResult("POST-based CSRF", vulnerable=False,
                details="Server correctly validates Content-Type for POST requests")
            
        return res

    async def runAllChecks(self) -> List[Dict]:
        """Run all security checks and return results."""

        if not self.client.endpoint:
            self.message.printMsg("Endpoint not set", status="failed")
            return []
            
        self.message.printMsg("Starting basic vulnerability scanning", status="success")

        start_time = time.time()
        checks = await asyncio.gather(
            self.checkFieldSuggestions(),
            self.checkGetBasedMutation(),
            self.checkGetMethodSupport(),
            self.checkPostBasedCsrf(),
        )

        vulnerabilities = [check for check in checks if check["result"]]
        end_time = time.time()
        
        # Print summary results
        self.message.printScanSummary(
            tests_run=len(checks),
            vulnerabilities_found=len(vulnerabilities),
            scan_time=end_time - start_time
        )

        return vulnerabilities