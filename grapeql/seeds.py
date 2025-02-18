"""
Author: Aleksa Zatezalo
Version: 1.0
Date: February 2025
Description: GraphQL Security Testing Module
"""

import aiohttp
from typing import Dict, List, Optional, Tuple, Any
from grapePrint import grapePrint

class Seeds:
    """
    A class for testing GraphQL endpoints for various security vulnerabilities.
    Tests include DoS attacks, information disclosure, and CSRF vulnerabilities.
    """
    
    def __init__(self):
        """Initialize the Seeds security tester with default settings."""
        self.message = grapePrint()
        self.proxy_url: Optional[str] = None
        self.endpoint: Optional[str] = None
        
        # Default headers for GraphQL requests
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'GraphQL-Security-Scanner/1.0'
        }
        
        # Test configuration
        self.timeout = 10  # Default timeout in seconds
        self.batch_size = 10  # Default batch size for batch queries
        self.max_aliases = 101  # Maximum number of aliases for overloading test
        self.max_duplicates = 500  # Maximum field duplications
        self.max_directives = 10  # Maximum directives for overloading test


    async def test_info_disclosure(self) -> Dict[str, Dict]:
        """
        Run all information disclosure tests.
        
        Returns:
            Dict[str, Dict]: Results of each test with details
        """
        if not self.endpoint:
            self.message.printMsg("No endpoint set. Call setEndpoint first.", status="failed")
            return {}

        self.message.printMsg("\nTesting Information Disclosure...", status="log")
        
        results = {}
        async with aiohttp.ClientSession() as session:
            # Test Field Suggestions
            self.message.printMsg("\nTesting Field Suggestions...", status="log")
            results['field_suggestions'] = await self.test_field_suggestions(session)
            
            # Test Trace Mode
            self.message.printMsg("\nTesting Trace Mode...", status="log")
            results['trace_mode'] = await self.test_trace_mode(session)
            
            # Test Unhandled Errors
            self.message.printMsg("\nTesting Unhandled Errors...", status="log")
            results['unhandled_errors'] = await self.test_unhandled_errors(session)
            
            # Test GET Method Support
            self.message.printMsg("\nTesting GET Method Support...", status="log")
            results['get_method'] = await self.test_get_method(session)
            
            # Test GET Based Mutations
            self.message.printMsg("\nTesting GET Based Mutations...", status="log")
            results['get_mutation'] = await self.test_get_based_mutation(session)
            
            # Test POST Based CSRF
            self.message.printMsg("\nTesting POST Based CSRF...", status="log")
            results['post_csrf'] = await self.test_post_based_csrf(session)

        return results

    async def test_field_suggestions(self, session: aiohttp.ClientSession) -> Dict:
        """Test for field suggestions vulnerability."""
        result = {
            'result': False,
            'title': 'Field Suggestions',
            'description': 'Field Suggestions are Enabled',
            'impact': f'Information Leakage - /{self.endpoint.rsplit("/", 1)[-1]}',
            'severity': 'LOW'
        }

        query = 'query { __schema { directive } }'
        response = await self._graphql_request(session, query)

        try:
            if 'Did you mean' in str(response.get('errors', [])):
                result['result'] = True
                self.message.printMsg("Field suggestions are enabled!", status="warning")
                self.message.printMsg(f"Impact: {result['impact']}", status="warning")
        except Exception:
            pass

        return result

    async def test_get_based_mutation(self, session: aiohttp.ClientSession) -> Dict:
        """Test for GET-based mutation vulnerability."""
        result = {
            'result': False,
            'title': 'Mutation is allowed over GET (possible CSRF)',
            'description': 'GraphQL mutations allowed using the GET method',
            'impact': f'Possible Cross Site Request Forgery - /{self.endpoint.rsplit("/", 1)[-1]}',
            'severity': 'MEDIUM'
        }

        query = 'mutation { __typename }'
        try:
            async with session.get(
                self.endpoint,
                params={'query': query},
                headers=self.headers,
                proxy=self.proxy_url,
                ssl=False
            ) as response:
                data = await response.json()
                if data.get('data', {}).get('__typename'):
                    result['result'] = True
                    self.message.printMsg("GET-based mutations are allowed!", status="warning")
                    self.message.printMsg(f"Impact: {result['impact']}", status="warning")
        except Exception:
            pass

        return result

    async def test_get_method(self, session: aiohttp.ClientSession) -> Dict:
        """Test for GET method support."""
        result = {
            'result': False,
            'title': 'GET Method Query Support',
            'description': 'GraphQL queries allowed using the GET method',
            'impact': f'Possible Cross Site Request Forgery (CSRF) - /{self.endpoint.rsplit("/", 1)[-1]}',
            'severity': 'MEDIUM'
        }

        query = 'query { __typename }'
        try:
            async with session.get(
                self.endpoint,
                params={'query': query},
                headers=self.headers,
                proxy=self.proxy_url,
                ssl=False
            ) as response:
                data = await response.json()
                if data.get('data', {}).get('__typename'):
                    result['result'] = True
                    self.message.printMsg("GET method queries are supported!", status="warning")
                    self.message.printMsg(f"Impact: {result['impact']}", status="warning")
        except Exception:
            pass

        return result

    async def test_post_based_csrf(self, session: aiohttp.ClientSession) -> Dict:
        """Test for POST-based CSRF vulnerability."""
        result = {
            'result': False,
            'title': 'POST based url-encoded query (possible CSRF)',
            'description': 'GraphQL accepts non-JSON queries over POST',
            'impact': f'Possible Cross Site Request Forgery - /{self.endpoint.rsplit("/", 1)[-1]}',
            'severity': 'MEDIUM'
        }

        query = 'query { __typename }'
        form_data = {'query': query}
        
        try:
            async with session.post(
                self.endpoint,
                data=form_data,  # Use form data instead of JSON
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                proxy=self.proxy_url,
                ssl=False
            ) as response:
                data = await response.json()
                if data.get('data', {}).get('__typename'):
                    result['result'] = True
                    self.message.printMsg("POST-based CSRF is possible!", status="warning")
                    self.message.printMsg(f"Impact: {result['impact']}", status="warning")
        except Exception:
            pass

        return result

    async def test_trace_mode(self, session: aiohttp.ClientSession) -> Dict:
        """Test for trace mode enablement."""
        result = {
            'result': False,
            'title': 'Trace Mode',
            'description': 'Tracing is Enabled',
            'impact': f'Information Leakage - /{self.endpoint.rsplit("/", 1)[-1]}',
            'severity': 'INFO'
        }

        query = 'query { __typename }'
        response = await self._graphql_request(session, query)

        try:
            if response.get('errors', [{}])[0].get('extensions', {}).get('tracing'):
                result['result'] = True
                self.message.printMsg("Trace mode is enabled!", status="warning")
                self.message.printMsg(f"Impact: {result['impact']}", status="warning")
            elif '\'extensions\': {\'tracing\':' in str(response).lower():
                result['result'] = True
                self.message.printMsg("Trace mode is enabled!", status="warning")
                self.message.printMsg(f"Impact: {result['impact']}", status="warning")
        except Exception:
            pass

        return result

    async def test_unhandled_errors(self, session: aiohttp.ClientSession) -> Dict:
        """Test for unhandled error disclosure."""
        result = {
            'result': False,
            'title': 'Unhandled Errors Detection',
            'description': 'Exception errors are not handled',
            'impact': f'Information Leakage - /{self.endpoint.rsplit("/", 1)[-1]}',
            'severity': 'INFO'
        }

        query = 'qwerty { abc }'  # Invalid query to trigger error
        response = await self._graphql_request(session, query)

        try:
            if response.get('errors', [{}])[0].get('extensions', {}).get('exception'):
                result['result'] = True
                self.message.printMsg("Unhandled errors are exposed!", status="warning")
                self.message.printMsg(f"Impact: {result['impact']}", status="warning")
            elif '\'extensions\': {\'exception\':' in str(response).lower():
                result['result'] = True
                self.message.printMsg("Unhandled errors are exposed!", status="warning")
                self.message.printMsg(f"Impact: {result['impact']}", status="warning")
        except Exception:
            pass

        return result
    
    async def test(self) -> Dict[str, Dict]:
        """
        Run comprehensive security tests on the GraphQL endpoint.
        Tests for information disclosure and CSRF vulnerabilities.
        
        Returns:
            Dict[str, Dict]: Results of all tests with details
        """
        if not self.endpoint:
            self.message.printMsg("No endpoint set. Call setEndpoint first.", status="failed")
            return {}

        self.message.printMsg(f"\nTesting GraphQL endpoint: {self.endpoint}", status="log")
        results = {}

        async with aiohttp.ClientSession() as session:
            # Group 1: Information Disclosure Tests
            self.message.printMsg("\n=== Information Disclosure Tests ===", status="log")
            info_results = await self.test_info_disclosure(session)
            results['information_disclosure'] = info_results

            # Group 2: Individual Tests
            self.message.printMsg("\n=== Field Tests ===", status="log")
            results['field_suggestions'] = await self.test_field_suggestions(session)

            self.message.printMsg("\n=== CSRF Vulnerability Tests ===", status="log")
            results['get_based_mutation'] = await self.test_get_based_mutation(session)
            results['get_method'] = await self.test_get_method(session)
            results['post_based_csrf'] = await self.test_post_based_csrf(session)

            self.message.printMsg("\n=== Error Handling Tests ===", status="log")
            results['trace_mode'] = await self.test_trace_mode(session)
            results['unhandled_errors'] = await self.test_unhandled_errors(session)

        # Print Summary
        self.message.printMsg("\n=== Test Summary ===", status="success")
        vulnerabilities_found = 0
        
        for test_name, test_result in results.items():
            if isinstance(test_result, dict):
                if test_result.get('result'):
                    vulnerabilities_found += 1
                    self.message.printMsg(
                        f"{test_name}: {test_result['title']} - {test_result['severity']}", 
                        status="warning"
                    )

        if vulnerabilities_found == 0:
            self.message.printMsg("No vulnerabilities found", status="success")
        else:
            self.message.printMsg(
                f"Found {vulnerabilities_found} potential vulnerabilities", 
                status="warning"
            )

        return results