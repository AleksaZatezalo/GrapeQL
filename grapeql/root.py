"""
Version: 1.0
Author: Aleksa Zatezalo
Date: February 2025
Description: GraphQL DoS testing module with schema-aware query generation
"""

import aiohttp
from typing import Dict, List, Optional
from grapePrint import grapePrint


class EngineInfo:
    """Information about a GraphQL engine implementation"""

    name: str
    url: str
    ref: str
    technology: List[str]


class root:
    """
    A class for testing GraphQL endpoints for various Denial of Service vulnerabilities.
    Generates targeted queries based on introspection of the actual schema.
    """

    def __init__(self):
        """Initialize the DoS tester with default settings and printer."""
        self.message = grapePrint()
        self.proxy_url: Optional[str] = None
        self.endpoint: Optional[str] = None
        self.headers = {"Content-Type": "application/json"}

    def configureProxy(self, proxy_host: str, proxy_port: int):
        """Configure HTTP proxy settings."""
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"

    async def runIntrospection(self, session: aiohttp.ClientSession) -> bool:
        """
        Run introspection query to validate the GraphQL endpoint.

        Args:
            session: The aiohttp client session to use

        Returns:
            bool: True if introspection succeeded
        """
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
            async with session.post(
                self.endpoint,
                json={"query": query},
                headers=self.headers,
                proxy=self.proxy_url,
                ssl=False,
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    if result.get("data", {}).get("__schema"):
                        self.message.printMsg("Fingerprinting server", status="success")
                        return True

                self.message.printMsg(
                    "Introspection failed - endpoint might not be GraphQL",
                    status="error",
                )
                return False

        except Exception as e:
            return False

    async def setEndpoint(
        self, endpoint: str, proxy_string: Optional[str] = None
    ) -> bool:
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
                proxy_host, proxy_port = proxy_string.split(":")
                self.configureProxy(proxy_host, int(proxy_port))
            except ValueError:
                self.message.printMsg(
                    "Invalid proxy format. Expected host:port", status="error"
                )
                return False

        # Run introspection
        async with aiohttp.ClientSession() as session:
            return await self.runIntrospection(session)

    async def fingerprintEngine(self) -> Optional[str]:
        """
        Identify the GraphQL engine implementation being used.

        Returns:
            Optional[str]: Engine identifier if detected
        """
        if not self.endpoint:
            self.message.printMsg(
                "No endpoint set. Call setEndpoint first.", status="error"
            )
            return None

        try:
            async with aiohttp.ClientSession() as session:
                # Test all implementations
                tests = [
                    (self.testYoga, "graphql-yoga"),
                    (self.testApollo, "apollo"),
                    (self.testAwsAppsync, "aws-appsync"),
                    (self.testGraphene, "graphene"),
                    (self.testHasura, "hasura"),
                    (self.testGraphqlPhp, "graphql-php"),
                    (self.testRuby, "ruby-graphql"),
                    (self.testHyperGraphql, "hypergraphql"),
                    (self.testGraphqlJava, "graphql-java"),
                    (self.testAriadne, "ariadne"),
                    (self.testGraphqlApiForWp, "graphql-api-for-wp"),
                    (self.testWpGraphql, "wp-graphql"),
                    (self.testGqlgen, "gqlgen"),
                    (self.testGraphqlGo, "graphql-go"),
                    (self.testJuniper, "juniper"),
                    (self.testSangria, "sangria"),
                    (self.testFlutter, "flutter"),
                    (self.testDianaJl, "diana-jl"),
                    (self.testStrawberry, "strawberry"),
                    (self.testTartiflette, "tartiflette"),
                    (self.testTailcall, "tailcall"),
                    (self.testDgraph, "dgraph"),
                    (self.testDirectus, "directus"),
                    (self.testLighthouse, "lighthouse"),
                    (self.testAgoo, "agoo"),
                    (self.testMercurius, "mercurius"),
                    (self.testMorpheus, "morpheus"),
                    (self.testLacinia, "lacinia"),
                    (self.testJaal, "jaal"),
                    (self.testCaliban, "caliban"),
                ]
                for test_func, engine_name in tests:
                    if await test_func(session):
                        self.message.printMsg(
                            f"Detected {engine_name} implementation", status="log"
                        )
                        return engine_name

            self.message.printMsg(
                "Could not identify GraphQL implementation", status="warning"
            )
            return None

        except Exception as e:
            self.message.printMsg(
                f"Error during engine fingerprinting: {str(e)}", status="error"
            )
            return None

    async def testYoga(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running GraphQL Yoga."""
        query = """subscription { __typename }"""
        response = await self._graphql_request(session, query)
        return self._error_contains(
            response, "asyncExecutionResult[Symbol.asyncIterator] is not a function"
        ) or self._error_contains(response, "Unexpected error.")

    async def testApollo(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Apollo Server."""
        query = "query @skip { __typename }"
        response = await self._graphql_request(session, query)
        if self._error_contains(
            response, 'Directive "@skip" argument "if" of type "Boolean!" is required'
        ):
            return True

        query = "query @deprecated { __typename }"
        response = await self._graphql_request(session, query)
        return self._error_contains(
            response, 'Directive "@deprecated" may not be used on QUERY'
        )

    async def testAwsAppsync(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running AWS AppSync."""
        query = "query @skip { __typename }"
        response = await self._graphql_request(session, query)
        return self._error_contains(response, "MisplacedDirective")

    async def testGraphene(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Graphene."""
        query = "aaa"
        response = await self._graphql_request(session, query)
        return self._error_contains(response, "Syntax Error GraphQL (1:1)")

    async def testHasura(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Hasura."""
        query = """query @cached { __typename }"""
        response = await self._graphql_request(session, query)
        if response.get("data", {}).get("__typename") == "query_root":
            return True

        query = "query { aaa }"
        response = await self._graphql_request(session, query)
        if self._error_contains(
            response, "field \"aaa\" not found in type: 'query_root'"
        ):
            return True

        query = "query @skip { __typename }"
        response = await self._graphql_request(session, query)
        if self._error_contains(response, 'directive "skip" is not allowed on a query'):
            return True

        query = "query { __schema }"
        response = await self._graphql_request(session, query)
        return self._error_contains(response, 'missing selection set for "__Schema"')

    async def testGraphqlPhp(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running GraphQL PHP."""
        query = "query ! { __typename }"
        response = await self._graphql_request(session, query)
        if self._error_contains(
            response, 'Syntax Error: Cannot parse the unexpected character "?"'
        ):
            return True

        query = "query @deprecated { __typename }"
        response = await self._graphql_request(session, query)
        return self._error_contains(
            response, 'Directive "deprecated" may not be used on "QUERY"'
        )

    async def testRuby(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Ruby GraphQL."""
        query = "query @skip { __typename }"
        response = await self._graphql_request(session, query)
        if self._error_contains(response, "'@skip' can't be applied to queries"):
            return True
        elif self._error_contains(
            response, "Directive 'skip' is missing required arguments: if"
        ):
            return True

        query = "query @deprecated { __typename }"
        response = await self._graphql_request(session, query)
        if self._error_contains(response, "'@deprecated' can't be applied to queries"):
            return True

        query = """query { __typename { }"""
        response = await self._graphql_request(session, query)
        return self._error_contains(response, 'Parse error on "}" (RCURLY)')

    async def testHyperGraphql(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running HyperGraphQL."""
        query = "zzz { __typename }"
        response = await self._graphql_request(session, query)
        if self._error_contains(
            response, "Validation error of type InvalidSyntax: Invalid query syntax."
        ):
            return True

        query = "query { alias1:__typename @deprecated }"
        response = await self._graphql_request(session, query)
        return self._error_contains(
            response,
            "Validation error of type UnknownDirective: Unknown directive deprecated",
        )

    async def testGraphqlJava(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running GraphQL Java."""
        query = "queryy { __typename }"
        response = await self._graphql_request(session, query)
        if self._error_contains(response, "Invalid Syntax : offending token 'queryy'"):
            return True

        query = "query @aaa@aaa { __typename }"
        response = await self._graphql_request(session, query)
        if self._error_contains(
            response, "Validation error of type DuplicateDirectiveName"
        ):
            return True

        query = ""
        response = await self._graphql_request(session, query)
        return self._error_contains(
            response, "Invalid Syntax : offending token '<EOF>'"
        )

    async def testAriadne(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Ariadne."""
        query = "query { __typename @abc }"
        response = await self._graphql_request(session, query)
        if (
            self._error_contains(response, "Unknown directive '@abc'.")
            and "data" not in response
        ):
            return True

        query = ""
        response = await self._graphql_request(session, query)
        return self._error_contains(response, "The query must be a string.")

    async def testGraphqlApiForWp(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running GraphQL API for WP."""
        query = "query { alias1$1:__typename }"
        response = await self._graphql_request(session, query)
        if response.get("data", {}).get("alias1$1") == "QueryRoot":
            return True

        query = "query aa#aa { __typename }"
        response = await self._graphql_request(session, query)
        if self._error_contains(response, 'Unexpected token "END"'):
            return True

        query = "query @skip { __typename }"
        response = await self._graphql_request(session, query)
        return self._error_contains(response, "Argument 'if' cannot be empty")

    async def testWpGraphql(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running WPGraphQL."""
        query = ""
        response = await self._graphql_request(session, query)
        if self._error_contains(
            response,
            'GraphQL Request must include at least one of those two parameters: "query" or "queryId"',
        ):
            return True

        query = "query { alias1$1:__typename }"
        response = await self._graphql_request(session, query)
        try:
            debug_msg = response["extensions"]["debug"][0]
            return debug_msg["type"] == "DEBUG_LOGS_INACTIVE"
        except KeyError:
            return False

    async def testGqlgen(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running gqlgen."""
        query = "query { __typename { }"
        response = await self._graphql_request(session, query)
        if self._error_contains(response, "expected at least one definition"):
            return True

        query = "query { alias^_:__typename { }"
        response = await self._graphql_request(session, query)
        return self._error_contains(response, "Expected Name, found <Invalid>")

    async def testGraphqlGo(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running graphql-go."""
        query = "query { __typename { }"
        response = await self._graphql_request(session, query)
        if self._error_contains(response, "Unexpected empty IN"):
            return True

        query = ""
        response = await self._graphql_request(session, query)
        if self._error_contains(response, "Must provide an operation."):
            return True

        query = "query { __typename }"
        response = await self._graphql_request(session, query)
        return response.get("data", {}).get("__typename") == "RootQuery"

    async def testJuniper(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Juniper."""
        query = "queryy { __typename }"
        response = await self._graphql_request(session, query)
        if self._error_contains(response, 'Unexpected "queryy"'):
            return True

        query = ""
        response = await self._graphql_request(session, query)
        return self._error_contains(response, "Unexpected end of input")

    async def testSangria(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Sangria."""
        query = "queryy { __typename }"
        response = await self._graphql_request(session, query)
        return (
            'Syntax error while parsing GraphQL query. Invalid input "queryy"'
            in response.get("syntaxError", "")
        )

    async def testFlutter(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Flutter."""
        query = "query { __typename @deprecated }"
        response = await self._graphql_request(session, query)
        return self._error_contains(
            response, 'Directive "deprecated" may not be used on FIELD.'
        )

    async def testDianaJl(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Diana.jl."""
        query = "queryy { __typename }"
        response = await self._graphql_request(session, query)
        return self._error_contains(
            response, 'Syntax Error GraphQL request (1:1) Unexpected Name "queryy"'
        )

    async def testStrawberry(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Strawberry."""
        query = "query @deprecated { __typename }"
        response = await self._graphql_request(session, query)
        return (
            self._error_contains(
                response, "Directive '@deprecated' may not be used on query."
            )
            and "data" in response
        )

    async def testTartiflette(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Tartiflette."""
        query = "query @a { __typename }"
        response = await self._graphql_request(session, query)
        if self._error_contains(response, "Unknow Directive < @a >."):
            return True

        query = "query @skip { __typename }"
        response = await self._graphql_request(session, query)
        return self._error_contains(
            response, "Missing mandatory argument < if > in directive < @skip >."
        )

    async def testTailcall(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Tailcall."""
        query = "aa { __typename }"
        response = await self._graphql_request(session, query)
        return self._error_contains(response, "expected executable_definition")

    async def testDgraph(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Dgraph."""
        query = "query { __typename @cascade }"
        response = await self._graphql_request(session, query)
        if response.get("data", {}).get("__typename") == "Query":
            return True

        query = "query { __typename }"
        response = await self._graphql_request(session, query)
        return self._error_contains(
            response, "Not resolving __typename. There's no GraphQL schema in Dgraph."
        )

    async def testDirectus(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Directus."""
        query = ""
        response = await self._graphql_request(session, query)
        errors = response.get("errors", [])
        return (
            errors and errors[0].get("extensions", {}).get("code") == "INVALID_PAYLOAD"
        )

    async def testLighthouse(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Lighthouse."""
        query = "query { __typename @include(if: falsee) }"
        response = await self._graphql_request(session, query)
        return self._error_contains(
            response, "Internal server error"
        ) or self._error_contains(response, "internal", part="category")

    async def testAgoo(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Agoo."""
        query = "query { zzz }"
        response = await self._graphql_request(session, query)
        return self._error_contains(response, "eval error", part="code")

    async def testMercurius(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Mercurius."""
        query = ""
        response = await self._graphql_request(session, query)
        return self._error_contains(response, "Unknown query")

    async def testMorpheus(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Morpheus."""
        query = "queryy { __typename }"
        response = await self._graphql_request(session, query)
        return self._error_contains(
            response, "expecting white space"
        ) or self._error_contains(response, "offset")

    async def testLacinia(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Lacinia."""
        query = "query { graphw00f }"
        response = await self._graphql_request(session, query)
        return self._error_contains(
            response, "Cannot query field `graphw00f' on type `QueryRoot'."
        )

    async def testJaal(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Jaal."""
        query = "{}"
        response = await self._graphql_request(session, query, operation="{}")
        return self._error_contains(response, "must have a single query")

    async def testCaliban(self, session: aiohttp.ClientSession) -> bool:
        """Test if the endpoint is running Caliban."""
        query = """
        query {
            __typename
        }
        fragment woof on __Schema {
            directives { name }
        }
        """
        response = await self._graphql_request(session, query)
        return self._error_contains(
            response, "Fragment 'woof' is not used in any spread"
        )

    async def _graphql_request(
        self, session: aiohttp.ClientSession, query: str, operation: str = None
    ) -> Dict:
        """Helper method to make GraphQL requests."""
        payload = {"query": query}
        if operation:
            payload["operation"] = operation

        try:
            async with session.post(
                self.endpoint,
                json=payload,
                headers=self.headers,
                proxy=self.proxy_url,
                ssl=False,
            ) as response:
                return await response.json()
        except Exception as e:
            return {"errors": [{"message": str(e)}]}

    def _error_contains(self, response_data: Dict, error_text: str) -> bool:
        """Helper method to check if a response contains a specific error message."""
        errors = response_data.get("errors", [])
        return any(error_text in error.get("message", "") for error in errors)
