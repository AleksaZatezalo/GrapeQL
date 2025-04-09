"""
Version: 2.0
Author: Aleksa Zatezalo
Date: March 2025
Description: GraphQL fingerprinting module with schema-aware query generation
"""

from typing import Dict, List, Optional, Tuple
from .base_tester import BaseTester


class EngineInfo:
    """Information about a GraphQL engine implementation"""

    name: str
    url: str
    ref: str
    technology: List[str]


class root(BaseTester):
    """
    A class for fingerprinting GraphQL server implementations.
    Uses specific query patterns to identify which GraphQL engine is running.
    """

    def __init__(self):
        """Initialize the fingerprinter with default settings."""
        super().__init__()

    async def fingerprintEngine(self) -> Optional[Dict]:
        """
        Identify the GraphQL engine implementation being used.

        Returns:
            Optional[Dict]: Engine information if detected
        """
        if not self.client.endpoint:
            self.message.printMsg(
                "No endpoint set. Call set_endpoint first.", status="error"
            )
            return None

        try:
            # Test all implementations
            tests = [
                (self.testYoga, "graphql-yoga", "https://the-guild.dev/graphql/yoga-server"),
                (self.testApollo, "apollo", "https://www.apollographql.com/"),
                (self.testAwsAppsync, "aws-appsync", "https://aws.amazon.com/appsync/"),
                (self.testGraphene, "graphene", "https://graphene-python.org/"),
                (self.testHasura, "hasura", "https://hasura.io/"),
                (self.testGraphqlPhp, "graphql-php", "https://github.com/webonyx/graphql-php"),
                (self.testRuby, "ruby-graphql", "https://github.com/rmosolgo/graphql-ruby"),
                (self.testHyperGraphql, "hypergraphql", "https://www.hypergraphql.org/"),
                (self.testGraphqlJava, "graphql-java", "https://www.graphql-java.com/"),
                (self.testAriadne, "ariadne", "https://ariadnegraphql.org/"),
                (self.testGraphqlApiForWp, "graphql-api-for-wp", "https://github.com/leoloso/graphql-api-for-wp"),
                (self.testWpGraphql, "wp-graphql", "https://www.wpgraphql.com/"),
                (self.testGqlgen, "gqlgen", "https://gqlgen.com/"),
                (self.testGraphqlGo, "graphql-go", "https://github.com/graphql-go/graphql"),
                (self.testJuniper, "juniper", "https://github.com/graphql-rust/juniper"),
                (self.testSangria, "sangria", "https://sangria-graphql.github.io/"),
                (self.testFlutter, "flutter", "https://flutter.dev/"),
                (self.testDianaJl, "diana-jl", "https://github.com/neomatrixcode/Diana.jl"),
                (self.testStrawberry, "strawberry", "https://strawberry.rocks/"),
                (self.testTartiflette, "tartiflette", "https://tartiflette.io/"),
                (self.testTailcall, "tailcall", "https://tailcall.run/"),
                (self.testDgraph, "dgraph", "https://dgraph.io/"),
                (self.testDirectus, "directus", "https://directus.io/"),
                (self.testLighthouse, "lighthouse", "https://lighthouse-php.com/"),
                (self.testAgoo, "agoo", "https://github.com/ohler55/agoo"),
                (self.testMercurius, "mercurius", "https://mercurius.dev/"),
                (self.testMorpheus, "morpheus", "https://github.com/morpheusgraphql/morpheus-graphql"),
                (self.testLacinia, "lacinia", "https://lacinia.readthedocs.io/"),
                (self.testJaal, "jaal", "https://github.com/ansh-saini/jaal"),
                (self.testCaliban, "caliban", "https://ghostdogpr.github.io/caliban/"),
            ]
            
            for test_func, engine_name, engine_url in tests:
                if await test_func():
                    self.message.printMsg(
                        f"Detected {engine_name} implementation", status="success"
                    )
                    
                    engine_info = {
                        "name": engine_name,
                        "url": engine_url,
                        "engine_id": engine_name
                    }
                    
                    # Add technology info based on engine
                    if engine_name in ["graphene", "ariadne", "strawberry"]:
                        engine_info["technology"] = ["Python"]
                    elif engine_name in ["graphql-php", "lighthouse"]:
                        engine_info["technology"] = ["PHP"]
                    elif engine_name in ["apollo", "graphql-yoga"]:
                        engine_info["technology"] = ["Node.js", "JavaScript"]
                    elif engine_name in ["ruby-graphql"]:
                        engine_info["technology"] = ["Ruby"]
                    elif engine_name in ["graphql-java"]:
                        engine_info["technology"] = ["Java"]
                    elif engine_name in ["gqlgen", "graphql-go"]:
                        engine_info["technology"] = ["Go"]
                    elif engine_name in ["juniper"]:
                        engine_info["technology"] = ["Rust"]
                    elif engine_name in ["sangria", "caliban"]:
                        engine_info["technology"] = ["Scala"]
                    elif engine_name in ["diana-jl"]:
                        engine_info["technology"] = ["Julia"]
                    elif engine_name in ["lacinia"]:
                        engine_info["technology"] = ["Clojure"]
                    else:
                        engine_info["technology"] = ["Unknown"]
                        
                    return engine_info

            self.message.printMsg(
                "Could not identify GraphQL implementation", status="warning"
            )
            return {
                "name": "unknown",
                "url": "",
                "engine_id": "unknown",
                "technology": ["Unknown"]
            }

        except Exception as e:
            self.message.printMsg(
                f"Error during engine fingerprinting: {str(e)}", status="error"
            )
            return None

    async def testYoga(self) -> bool:
        """Test if the endpoint is running GraphQL Yoga."""
        query = """subscription { __typename }"""
        response = await self.client.graphql(query)
        return self._error_contains(
            response, "asyncExecutionResult[Symbol.asyncIterator] is not a function"
        ) or self._error_contains(response, "Unexpected error.")

    async def testApollo(self) -> bool:
        """Test if the endpoint is running Apollo Server."""
        query = "query @skip { __typename }"
        response = await self.client.graphql(query)
        if self._error_contains(
            response, 'Directive "@skip" argument "if" of type "Boolean!" is required'
        ):
            return True

        query = "query @deprecated { __typename }"
        response = await self.client.graphql(query)
        return self._error_contains(
            response, 'Directive "@deprecated" may not be used on QUERY'
        )

    async def testAwsAppsync(self) -> bool:
        """Test if the endpoint is running AWS AppSync."""
        query = "query @skip { __typename }"
        response = await self.client.graphql(query)
        return self._error_contains(response, "MisplacedDirective")

    async def testGraphene(self) -> bool:
        """Test if the endpoint is running Graphene."""
        query = "aaa"
        response = await self.client.graphql(query)
        return self._error_contains(response, "Syntax Error GraphQL (1:1)")

    async def testHasura(self) -> bool:
        """Test if the endpoint is running Hasura."""
        query = """query @cached { __typename }"""
        response = await self.client.graphql(query)
        if response.get("data", {}).get("__typename") == "query_root":
            return True

        query = "query { aaa }"
        response = await self.client.graphql(query)
        if self._error_contains(
            response, "field \"aaa\" not found in type: 'query_root'"
        ):
            return True

        query = "query @skip { __typename }"
        response = await self.client.graphql(query)
        if self._error_contains(response, 'directive "skip" is not allowed on a query'):
            return True

        query = "query { __schema }"
        response = await self.client.graphql(query)
        return self._error_contains(response, 'missing selection set for "__Schema"')

    async def testGraphqlPhp(self) -> bool:
        """Test if the endpoint is running GraphQL PHP."""
        query = "query ! { __typename }"
        response = await self.client.graphql(query)
        if self._error_contains(
            response, 'Syntax Error: Cannot parse the unexpected character "?"'
        ):
            return True

        query = "query @deprecated { __typename }"
        response = await self.client.graphql(query)
        return self._error_contains(
            response, 'Directive "deprecated" may not be used on "QUERY"'
        )

    async def testRuby(self) -> bool:
        """Test if the endpoint is running Ruby GraphQL."""
        query = "query @skip { __typename }"
        response = await self.client.graphql(query)
        if self._error_contains(response, "'@skip' can't be applied to queries"):
            return True
        elif self._error_contains(
            response, "Directive 'skip' is missing required arguments: if"
        ):
            return True

        query = "query @deprecated { __typename }"
        response = await self.client.graphql(query)
        if self._error_contains(response, "'@deprecated' can't be applied to queries"):
            return True

        query = """query { __typename { }"""
        response = await self.client.graphql(query)
        return self._error_contains(response, 'Parse error on "}" (RCURLY)')

    async def testHyperGraphql(self) -> bool:
        """Test if the endpoint is running HyperGraphQL."""
        query = "zzz { __typename }"
        response = await self.client.graphql(query)
        if self._error_contains(
            response, "Validation error of type InvalidSyntax: Invalid query syntax."
        ):
            return True

        query = "query { alias1:__typename @deprecated }"
        response = await self.client.graphql(query)
        return self._error_contains(
            response,
            "Validation error of type UnknownDirective: Unknown directive deprecated",
        )

    async def testGraphqlJava(self) -> bool:
        """Test if the endpoint is running GraphQL Java."""
        query = "queryy { __typename }"
        response = await self.client.graphql(query)
        if self._error_contains(response, "Invalid Syntax : offending token 'queryy'"):
            return True

        query = "query @aaa@aaa { __typename }"
        response = await self.client.graphql(query)
        if self._error_contains(
            response, "Validation error of type DuplicateDirectiveName"
        ):
            return True

        query = ""
        response = await self.client.graphql(query)
        return self._error_contains(
            response, "Invalid Syntax : offending token '<EOF>'"
        )

    async def testAriadne(self) -> bool:
        """Test if the endpoint is running Ariadne."""
        query = "query { __typename @abc }"
        response = await self.client.graphql(query)
        if (
            self._error_contains(response, "Unknown directive '@abc'.")
            and "data" not in response
        ):
            return True

        query = ""
        response = await self.client.graphql(query)
        return self._error_contains(response, "The query must be a string.")

    async def testGraphqlApiForWp(self) -> bool:
        """Test if the endpoint is running GraphQL API for WP."""
        query = "query { alias1$1:__typename }"
        response = await self.client.graphql(query)
        if response.get("data", {}).get("alias1$1") == "QueryRoot":
            return True

        query = "query aa#aa { __typename }"
        response = await self.client.graphql(query)
        if self._error_contains(response, 'Unexpected token "END"'):
            return True

        query = "query @skip { __typename }"
        response = await self.client.graphql(query)
        return self._error_contains(response, "Argument 'if' cannot be empty")

    async def testWpGraphql(self) -> bool:
        """Test if the endpoint is running WPGraphQL."""
        query = ""
        response = await self.client.graphql(query)
        if self._error_contains(
            response,
            'GraphQL Request must include at least one of those two parameters: "query" or "queryId"',
        ):
            return True

        query = "query { alias1$1:__typename }"
        response = await self.client.graphql(query)
        try:
            debug_msg = response.get("extensions", {}).get("debug", [{}])[0]
            return debug_msg.get("type") == "DEBUG_LOGS_INACTIVE"
        except (KeyError, IndexError, TypeError):
            return False

    async def testGqlgen(self) -> bool:
        """Test if the endpoint is running gqlgen."""
        query = "query { __typename { }"
        response = await self.client.graphql(query)
        if self._error_contains(response, "expected at least one definition"):
            return True

        query = "query { alias^_:__typename { }"
        response = await self.client.graphql(query)
        return self._error_contains(response, "Expected Name, found <Invalid>")

    async def testGraphqlGo(self) -> bool:
        """Test if the endpoint is running graphql-go."""
        query = "query { __typename { }"
        response = await self.client.graphql(query)
        if self._error_contains(response, "Unexpected empty IN"):
            return True

        query = ""
        response = await self.client.graphql(query)
        if self._error_contains(response, "Must provide an operation."):
            return True

        query = "query { __typename }"
        response = await self.client.graphql(query)
        return response.get("data", {}).get("__typename") == "RootQuery"

    async def testJuniper(self) -> bool:
        """Test if the endpoint is running Juniper."""
        query = "queryy { __typename }"
        response = await self.client.graphql(query)
        if self._error_contains(response, 'Unexpected "queryy"'):
            return True

        query = ""
        response = await self.client.graphql(query)
        return self._error_contains(response, "Unexpected end of input")

    async def testSangria(self) -> bool:
        """Test if the endpoint is running Sangria."""
        query = "queryy { __typename }"
        response = await self.client.graphql(query)
        return (
            'Syntax error while parsing GraphQL query. Invalid input "queryy"'
            in response.get("syntaxError", "")
        )

    async def testFlutter(self) -> bool:
        """Test if the endpoint is running Flutter."""
        query = "query { __typename @deprecated }"
        response = await self.client.graphql(query)
        return self._error_contains(
            response, 'Directive "deprecated" may not be used on FIELD.'
        )

    async def testDianaJl(self) -> bool:
        """Test if the endpoint is running Diana.jl."""
        query = "queryy { __typename }"
        response = await self.client.graphql(query)
        return self._error_contains(
            response, 'Syntax Error GraphQL request (1:1) Unexpected Name "queryy"'
        )

    async def testStrawberry(self) -> bool:
        """Test if the endpoint is running Strawberry."""
        query = "query @deprecated { __typename }"
        response = await self.client.graphql(query)
        return (
            self._error_contains(
                response, "Directive '@deprecated' may not be used on query."
            )
            and "data" in response
        )

    async def testTartiflette(self) -> bool:
        """Test if the endpoint is running Tartiflette."""
        query = "query @a { __typename }"
        response = await self.client.graphql(query)
        if self._error_contains(response, "Unknow Directive < @a >."):
            return True

        query = "query @skip { __typename }"
        response = await self.client.graphql(query)
        return self._error_contains(
            response, "Missing mandatory argument < if > in directive < @skip >."
        )

    async def testTailcall(self) -> bool:
        """Test if the endpoint is running Tailcall."""
        query = "aa { __typename }"
        response = await self.client.graphql(query)
        return self._error_contains(response, "expected executable_definition")

    async def testDgraph(self) -> bool:
        """Test if the endpoint is running Dgraph."""
        query = "query { __typename @cascade }"
        response = await self.client.graphql(query)
        if response.get("data", {}).get("__typename") == "Query":
            return True

        query = "query { __typename }"
        response = await self.client.graphql(query)
        return self._error_contains(
            response, "Not resolving __typename. There's no GraphQL schema in Dgraph."
        )

    async def testDirectus(self) -> bool:
        """Test if the endpoint is running Directus."""
        query = ""
        response = await self.client.graphql(query)
        errors = response.get("errors", [])
        return (
            errors and errors[0].get("extensions", {}).get("code") == "INVALID_PAYLOAD"
        )

    async def testLighthouse(self) -> bool:
        """Test if the endpoint is running Lighthouse."""
        query = "query { __typename @include(if: falsee) }"
        response = await self.client.graphql(query)
        return self._error_contains(
            response, "Internal server error"
        ) or self._error_contains(response, "internal", part="category")

    async def testAgoo(self) -> bool:
        """Test if the endpoint is running Agoo."""
        query = "query { zzz }"
        response = await self.client.graphql(query)
        return self._error_contains(response, "eval error", part="code")

    async def testMercurius(self) -> bool:
        """Test if the endpoint is running Mercurius."""
        query = ""
        response = await self.client.graphql(query)
        return self._error_contains(response, "Unknown query")

    async def testMorpheus(self) -> bool:
        """Test if the endpoint is running Morpheus."""
        query = "queryy { __typename }"
        response = await self.client.graphql(query)
        return self._error_contains(
            response, "expecting white space"
        ) or self._error_contains(response, "offset")

    async def testLacinia(self) -> bool:
        """Test if the endpoint is running Lacinia."""
        query = "query { graphw00f }"
        response = await self.client.graphql(query)
        return self._error_contains(
            response, "Cannot query field `graphw00f' on type `QueryRoot'."
        )

    async def testJaal(self) -> bool:
        """Test if the endpoint is running Jaal."""
        query = "{}"
        response = await self.client.graphql(query, operation_name="{}")
        return self._error_contains(response, "must have a single query")

    async def testCaliban(self) -> bool:
        """Test if the endpoint is running Caliban."""
        query = """
        query {
            __typename
        }
        fragment woof on __Schema {
            directives { name }
        }
        """
        response = await self.client.graphql(query)
        return self._error_contains(
            response, "Fragment 'woof' is not used in any spread"
        )

    def _error_contains(self, response_data: Dict, error_text: str, part: str = "message") -> bool:
        """Helper method to check if a response contains a specific error message."""
        errors = response_data.get("errors", [])
        if part == "message":
            return any(error_text.lower() in str(error.get("message", "")).lower() for error in errors)
        elif part == "category":
            return any(error_text.lower() in str(error.get("category", "")).lower() for error in errors)
        elif part == "code":
            return any(error_text.lower() in str(error.get("code", "")).lower() for error in errors)
        return False