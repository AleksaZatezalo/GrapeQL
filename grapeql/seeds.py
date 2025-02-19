"""
Author: Aleksa Zatezalo
Version: 1.0
Date: February 2025
Description: GraphQL Security Testing Module
"""

import aiohttp
import asyncio
from typing import Dict, List, Optional
from grapePrint import grapePrint

class seeds():
    """
    A class for testing GraphQL endpoints for various security vulnerabilities.
    Generates targeted queries based on introspection of the actual schema.
    """
    
    def __init__(self):
        """Initialize the security tester with default settings and printer."""
        self.message = grapePrint()
        self.proxy_url: Optional[str] = None
        self.endpoint: Optional[str] = None
        self.headers = {'Content-Type': 'application/json'}
        self.debug_mode = False
    
    def configureProxy(self, proxy_host: str, proxy_port: int):
        """Configure HTTP proxy settings."""
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"

    def getError(self, response_data: Dict) -> str:
        """Extract error message from GraphQL response."""
        if isinstance(response_data, dict):
            errors = response_data.get('errors', [])
            if errors and isinstance(errors, list):
                return str(errors[0].get('message', ''))
        return ''

    def generateCurl(self) -> str:
        """Generate curl command from request."""
        if not hasattr(self, 'last_response'):
            return ''
            
        method = self.last_response.method
        url = str(self.last_response.url)
        headers = ['{}:{}'.format(k, v) for k, v in self.last_response.request_info.headers.items()]
        command = ['curl', '-X', method, url]
        
        for header in headers:
            command.extend(['-H', f"'{header}'"])
            
        if hasattr(self.last_response, '_body'):
            body = self.last_response._body.decode('utf-8') if isinstance(self.last_response._body, bytes) else str(self.last_response._body)
            command.extend(['-d', f"'{body}'"])
            
        return ' '.join(command)

    async def makeGraphQuery(self, session: aiohttp.ClientSession, payload: str) -> Dict:
        """Make a GraphQL query."""
        async with session.post(
            self.endpoint,
            json={'query': payload},
            headers=self.headers,
            proxy=self.proxy_url,
            ssl=False
        ) as response:
            # Store the response for curl generation
            self.last_response = response
            # Return the JSON response
            return await response.json()

    async def makeRequest(self, session: aiohttp.ClientSession, method: str = 'GET', **kwargs) -> Dict:
        """Make an HTTP request."""
        async with session.request(
            method,
            self.endpoint,
            headers=self.headers,
            proxy=self.proxy_url,
            ssl=False,
            **kwargs
        ) as response:
            self.last_response = response
            return await response.json()

    async def runIntrospection(self, session: aiohttp.ClientSession) -> bool:
        """Run introspection query to validate the GraphQL endpoint."""
        query = """
        query {
            __schema {
                queryType {
                    name
                }
            }
        }
        """
        
        try:
            result = await self.makeGraphQuery(session, query)
            if result.get('data', {}).get('__schema'):
                self.message.printMsg("Starting basic vulnerability scanning", status="success")
                return True
            
            self.message.printMsg("Introspection failed - endpoint might not be GraphQL", status="failed")
            return False
                
        except Exception as e:
            self.message.printMsg(f"Connection error: {str(e)}", status="failed")
            return False

    async def setEndpoint(self, endpoint: str, proxy_string: Optional[str] = None) -> bool:
        """Set the endpoint and configure proxy if provided."""
        self.endpoint = endpoint
        
        if proxy_string:
            try:
                proxy_host, proxy_port = proxy_string.split(':')
                self.configureProxy(proxy_host, int(proxy_port))
            except ValueError:
                self.message.printMsg("Invalid proxy format. Expected host:port", status="failed")
                return False

        async with aiohttp.ClientSession() as session:
            return await self.runIntrospection(session)

    async def checkFieldSuggestions(self, session: aiohttp.ClientSession) -> Dict:
        """Check if field suggestions are enabled."""
        res = {
            'result': False,
            'title': 'Field suggestions are enabled',
            'description': 'Field Suggestions are enabled',
            'impact': 'Information Leakage - /' + self.endpoint.rsplit('/', 1)[-1],
            'severity': 'LOW',
            'color': 'blue',
            'curl_verify': ''
        }

        query = 'query cop { __schema { directive } }'
        if self.debug_mode:
            self.headers['X-GraphQL-Cop-Test'] = res['title']
            
        response_data = await self.makeGraphQuery(session, query)
        res['curl_verify'] = self.generateCurl()
        
        try:
            if 'Did you mean' in str(response_data['errors']):
                res['result'] = True
        except:
            pass
        if res['result']:
            self.message.printMsg(f"Low vulnerability: {res['title']}", status="warning")
        return res

    async def checkGetBasedMutation(self, session: aiohttp.ClientSession) -> Dict:
        """Check if mutations are allowed over GET."""
        res = {
            'result': False,
            'title': 'Mutation is allowed over GET (possible CSRF)',
            'description': 'GraphQL mutations allowed using the GET method',
            'impact': 'Possible Cross Site Request Forgery - /' + self.endpoint.rsplit('/', 1)[-1],
            'severity': 'MEDIUM',
            'color': 'yellow',
            'curl_verify': ''
        }

        query = 'mutation cop {__typename}'
        if self.debug_mode:
            self.headers['X-GraphQL-Cop-Test'] = res['title']
            
        try:
            response_data = await self.makeRequest(session, params={'query': query})
            res['curl_verify'] = self.generateCurl()
            if response_data.get('data', {}).get('__typename'):
                res['result'] = True
        except:
            pass

        if res['result']:
            self.message.printMsg(f"Low vulnerability: {res['title']}", status="warning")
        return res

    async def checkGetMethodSupport(self, session: aiohttp.ClientSession) -> Dict:
        """Check for GET method query support."""
        res = {
            'result': False,
            'title': 'Queries allowed using GET requests (possible CSRF)',
            'description': 'GraphQL queries allowed using the GET method',
            'impact': 'Possible Cross Site Request Forgery (CSRF) - /' + self.endpoint.rsplit('/', 1)[-1],
            'severity': 'MEDIUM',
            'color': 'yellow',
            'curl_verify': ''
        }

        query = 'query cop {__typename}'
        if self.debug_mode:
            self.headers['X-GraphQL-Cop-Test'] = res['title']
            
        try:
            # Test with URL parameters
            response_data = await self.makeRequest(session, method='GET', params={'query': query})
            res['curl_verify'] = self.generateCurl()
            
            # Check if query was successful
            if response_data and isinstance(response_data, dict):
                if response_data.get('data', {}).get('__typename') is not None:
                    res['result'] = True
                elif 'errors' in response_data and not any(
                    'method not allowed' in str(err.get('message', '')).lower() 
                    for err in response_data.get('errors', [])
                ):
                    res['result'] = True
                    
        except Exception as e:
            self.message.printMsg(f"Error in GET method check: {str(e)}", status="failed")

        if res['result']:
            self.message.printMsg(f"Low vulnerability: {res['title']}", status="warning")
        return res

    async def checkPostBasedCsrf(self, session: aiohttp.ClientSession) -> Dict:
        """Check for POST-based CSRF vulnerabilities."""
        res = {
            'result': False,
            'title': 'POST based url-encoded query (possible CSRF)',
            'description': 'GraphQL accepts non-JSON queries over POST',
            'impact': 'Possible Cross Site Request Forgery - /' + self.endpoint.rsplit('/', 1)[-1],
            'severity': 'MEDIUM',
            'color': 'yellow',
            'curl_verify': ''
        }

        query = 'query cop { __typename }'
        if self.debug_mode:
            self.headers['X-GraphQL-Cop-Test'] = res['title']
        
        # Save original content type
        original_content_type = self.headers.get('Content-Type')
        
        try:
            # Test with form-urlencoded content type
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'
            form_data = {'query': query}
            
            response_data = await self.makeRequest(session, method='POST', data=form_data)
            res['curl_verify'] = self.generateCurl()
            
            # Check if query was successful
            if response_data and isinstance(response_data, dict):
                if response_data.get('data', {}).get('__typename') is not None:
                    res['result'] = True
                elif 'errors' in response_data and not any(
                    'content type not supported' in str(err.get('message', '')).lower() 
                    for err in response_data.get('errors', [])
                ):
                    res['result'] = True
                    
        except Exception as e:
            self.message.printMsg(f"Error in POST CSRF check: {str(e)}", status="failed")
        finally:
            # Restore original content type
            if original_content_type:
                self.headers['Content-Type'] = original_content_type
            else:
                del self.headers['Content-Type']

        if res['result']:
            self.message.printMsg(f"Low vulnerability: {res['title']}", status="warning")
        return res

    async def runAllChecks(self) -> List[Dict]:
        """Run all security checks and return results."""
        if not self.endpoint:
            self.message.printMsg("Endpoint not set", status="failed")
            return []
        
        async with aiohttp.ClientSession() as session:
            checks = await asyncio.gather(
                self.checkFieldSuggestions(session),
                self.checkGetBasedMutation(session),
                self.checkGetMethodSupport(session),
                self.checkPostBasedCsrf(session),
            )
        
        vulnerabilities = [check for check in checks if check['result']]
        
        return vulnerabilities