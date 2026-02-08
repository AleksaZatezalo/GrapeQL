"""
GrapeQL HTTP Client
Author: Aleksa Zatezalo
Version: 3.2
Date: February 2025
Description: Core HTTP client for GrapeQL with consistent request handling, structured logging,
             response caching, and batch query support.
             v3.2: Added batch query support and response caching for improved performance.
"""

import aiohttp
import asyncio
import json
import time
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from .utils import GrapePrinter
from .logger import GrapeLogger


class GraphQLClient:
    """
    Unified HTTP client for all GrapeQL modules providing consistent
    request handling, proxy support, header/cookie management, and
    structured logging of every request/response pair.
    """

    def __init__(self, logger: Optional[GrapeLogger] = None, session: Optional[aiohttp.ClientSession] = None):
        self.printer = GrapePrinter()
        self.logger = logger
        self.session = session  # Optional shared session for connection pooling
        self.endpoint: Optional[str] = None
        self.proxy_url: Optional[str] = None
        self.headers: Dict[str, str] = {"Content-Type": "application/json"}
        self.cookies: Dict[str, str] = {}
        self.auth_token: Optional[str] = None
        self.last_response: Optional[aiohttp.ClientResponse] = None
        self.timeout = aiohttp.ClientTimeout(total=10)
        self.schema: Optional[Dict] = None
        self.query_fields: Dict[str, Dict] = {}
        self.mutation_fields: Dict[str, Dict] = {}

        self._log_module: str = "GraphQLClient"
        self._log_test: str = "-"
        
        # Response cache: key is hash of (query, variables); value is response
        self._response_cache: Dict[str, Any] = {}
        self._cache_hits: int = 0
        self._cache_misses: int = 0

    def set_log_context(self, module: str, test: str = "-") -> None:
        self._log_module = module
        self._log_test = test

    # ------------------------------------------------------------------ #
    # Cache management
    # ------------------------------------------------------------------ #

    def _cache_key(self, query: str, variables: Optional[Dict] = None) -> str:
        """Generate a cache key from query and variables."""
        key_str = f"{query}:{json.dumps(variables or {}, sort_keys=True)}"
        return hashlib.md5(key_str.encode()).hexdigest()

    def _get_cached(self, query: str, variables: Optional[Dict] = None) -> Optional[Any]:
        """Retrieve a cached response if available."""
        key = self._cache_key(query, variables)
        if key in self._response_cache:
            self._cache_hits += 1
            return self._response_cache[key]
        self._cache_misses += 1
        return None

    def _cache_response(self, query: str, variables: Optional[Dict], response: Any) -> None:
        """Store a response in the cache."""
        key = self._cache_key(query, variables)
        self._response_cache[key] = response

    def clear_cache(self) -> None:
        """Clear the response cache."""
        self._response_cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0

    def cache_stats(self) -> Dict[str, int]:
        """Return cache hit/miss statistics."""
        return {"hits": self._cache_hits, "misses": self._cache_misses}

    def configure_proxy(self, proxy_host: str, proxy_port: int) -> None:
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"
        self.printer.print_msg(f"Proxy configured: {self.proxy_url}", status="success")

    def set_endpoint(self, endpoint: str) -> None:
        self.endpoint = endpoint
        self.printer.print_msg(f"Endpoint set: {endpoint}", status="success")

    def set_header(self, name: str, value: str) -> None:
        self.headers[name] = value

    def set_headers(self, headers: Dict[str, str]) -> None:
        self.headers.update(headers)

    def set_cookie(self, name: str, value: str) -> None:
        self.cookies[name] = value

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        self.cookies.update(cookies)

    def set_authorization(self, token: str, prefix: str = "Bearer") -> None:
        self.headers["Authorization"] = f"{prefix} {token}" if prefix else token
        self.auth_token = token

    def clear_headers(self) -> None:
        self.headers = {"Content-Type": "application/json"}

    def clear_cookies(self) -> None:
        self.cookies = {}

    # ------------------------------------------------------------------ #
    # Core request methods
    # ------------------------------------------------------------------ #

    async def make_request(
        self,
        method: str,
        url: Optional[str] = None,
        *,
        _log_parameter: str = "-",
        _log_payload: str = "-",
        **kwargs,
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """Make a generic HTTP request with consistent error handling and logging."""
        if not url and not self.endpoint:
            error_msg = "No endpoint URL provided"
            self.printer.print_msg(error_msg, status="error")
            return None, error_msg

        target_url = url or self.endpoint

        request_kwargs = {
            "headers": self.headers,
            "cookies": self.cookies,
            "proxy": self.proxy_url,
            "ssl": False,
            "timeout": self.timeout,
        }
        request_kwargs.update(kwargs)

        start = time.time()
        try:
            # Use shared session if available, otherwise create a temporary one
            session_to_use = self.session
            should_close = False
            if session_to_use is None:
                session_to_use = aiohttp.ClientSession()
                should_close = True

            try:
                async with session_to_use.request(
                    method, target_url, **request_kwargs
                ) as response:
                    self.last_response = response
                    duration = time.time() - start

                    if response.content_type == "application/json":
                        result = await response.json()
                    else:
                        text = await response.text()
                        try:
                            result = json.loads(text)
                        except json.JSONDecodeError:
                            result = {"text": text}

                    if self.logger:
                        self.logger.log_request(
                            module=self._log_module,
                            test=self._log_test,
                            parameter=_log_parameter,
                            payload=_log_payload,
                            verb=method,
                            status="success",
                            response=result,
                            duration=duration,
                        )

                    return result, None
            finally:
                if should_close:
                    await session_to_use.close()

        except asyncio.TimeoutError:
            duration = time.time() - start
            error_msg = f"Request to {target_url} timed out"
            self.printer.print_msg(error_msg, status="error")
            if self.logger:
                self.logger.log_timeout(
                    module=self._log_module,
                    test=self._log_test,
                    parameter=_log_parameter,
                    payload=_log_payload,
                    verb=method,
                    duration=duration,
                )
            return None, error_msg

        except Exception as e:
            duration = time.time() - start
            error_msg = f"Error making request to {target_url}: {str(e)}"
            self.printer.print_msg(error_msg, status="error")
            if self.logger:
                self.logger.log_error(
                    module=self._log_module,
                    test=self._log_test,
                    parameter=_log_parameter,
                    message=error_msg,
                )
            return None, error_msg

    async def graphql_query(
        self,
        query: str,
        variables: Optional[Dict] = None,
        operation_name: Optional[str] = None,
        *,
        _log_parameter: str = "-",
        _log_payload: str = "-",
        use_cache: bool = True,
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """Execute a GraphQL query with caching support."""
        if not self.endpoint:
            error_msg = "No GraphQL endpoint set"
            self.printer.print_msg(error_msg, status="error")
            return None, error_msg

        # Check cache first
        if use_cache:
            cached = self._get_cached(query, variables)
            if cached:
                return cached, None

        payload_body: Dict[str, Any] = {"query": query}
        if variables:
            payload_body["variables"] = variables
        if operation_name:
            payload_body["operationName"] = operation_name

        result, error = await self.make_request(
            "POST",
            json=payload_body,
            _log_parameter=_log_parameter,
            _log_payload=_log_payload or query[:120],
        )

        if error is None and result is not None and use_cache:
            self._cache_response(query, variables, result)

        return result, error

    async def graphql_batch(
        self,
        queries: List[Tuple[str, Optional[Dict], Optional[str]]],
        *,
        _log_parameter: str = "-",
    ) -> Tuple[Optional[List[Dict]], Optional[str]]:
        """
        Execute multiple GraphQL queries in a single batch request.
        
        Args:
            queries: List of (query, variables, operation_name) tuples
            _log_parameter: Parameter name for logging
        
        Returns:
            Tuple of (list of results, error message)
        """
        if not self.endpoint:
            error_msg = "No GraphQL endpoint set"
            self.printer.print_msg(error_msg, status="error")
            return None, error_msg

        # Build batch payload
        batch_payload = []
        for query, variables, op_name in queries:
            item: Dict[str, Any] = {"query": query}
            if variables:
                item["variables"] = variables
            if op_name:
                item["operationName"] = op_name
            batch_payload.append(item)

        start = time.time()
        try:
            session_to_use = self.session
            should_close = False
            if session_to_use is None:
                session_to_use = aiohttp.ClientSession()
                should_close = True

            try:
                request_kwargs = {
                    "headers": self.headers,
                    "cookies": self.cookies,
                    "proxy": self.proxy_url,
                    "ssl": False,
                    "timeout": self.timeout,
                    "json": batch_payload,
                }

                async with session_to_use.request(
                    "POST", self.endpoint, **request_kwargs
                ) as response:
                    self.last_response = response
                    duration = time.time() - start

                    if response.content_type == "application/json":
                        result = await response.json()
                    else:
                        text = await response.text()
                        try:
                            result = json.loads(text)
                        except json.JSONDecodeError:
                            result = {"text": text}

                    if self.logger:
                        self.logger.log_request(
                            module=self._log_module,
                            test=self._log_test,
                            parameter=_log_parameter,
                            payload=f"batch[{len(queries)}]",
                            verb="POST",
                            status="success",
                            response=f"batch response ({len(queries)} queries)",
                            duration=duration,
                        )

                    return result, None
            finally:
                if should_close:
                    await session_to_use.close()

        except asyncio.TimeoutError:
            duration = time.time() - start
            error_msg = f"Batch request to {self.endpoint} timed out"
            self.printer.print_msg(error_msg, status="error")
            if self.logger:
                self.logger.log_timeout(
                    module=self._log_module,
                    test=self._log_test,
                    parameter=_log_parameter,
                    payload=f"batch[{len(queries)}]",
                    verb="POST",
                    duration=duration,
                )
            return None, error_msg

        except Exception as e:
            duration = time.time() - start
            error_msg = f"Error making batch request to {self.endpoint}: {str(e)}"
            self.printer.print_msg(error_msg, status="error")
            if self.logger:
                self.logger.log_error(
                    module=self._log_module,
                    test=self._log_test,
                    parameter=_log_parameter,
                    message=error_msg,
                )
            return None, error_msg

    # ------------------------------------------------------------------ #
    # Schema helpers (shared by introspection + file load)
    # ------------------------------------------------------------------ #

    def _extract_fields(self, schema_data: Dict) -> None:
        """Parse queryType/mutationType fields from a schema dict into lookup maps."""
        self.schema = schema_data
        self.query_fields.clear()
        self.mutation_fields.clear()

        for type_key, target in [
            ("queryType", self.query_fields),
            ("mutationType", self.mutation_fields),
        ]:
            if schema_data.get(type_key):
                for field in schema_data[type_key].get("fields", []):
                    target[field["name"]] = {"args": field.get("args", [])}

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #

    async def introspection_query(self) -> bool:
        """Run introspection query to validate the endpoint and cache schema info."""
        query = """
        query {
            __schema {
                queryType {
                    name
                    fields {
                        name
                        args {
                            name
                            type {
                                name
                                kind
                                ofType {
                                    name
                                    kind
                                }
                            }
                        }
                    }
                }
                mutationType {
                    name
                    fields {
                        name
                        args {
                            name
                            type {
                                name
                                kind
                                ofType {
                                    name
                                    kind
                                }
                            }
                        }
                    }
                }
                types {
                    name
                    kind
                    fields {
                        name
                        type {
                            name
                            kind
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

        response, error = await self.graphql_query(
            query, _log_parameter="introspection", _log_payload="__schema"
        )

        if error or not response:
            self.printer.print_msg(
                "Introspection failed - endpoint might not be GraphQL", status="failed"
            )
            return False

        schema_data = response.get("data", {}).get("__schema")
        if not schema_data:
            self.printer.print_msg(
                "Introspection failed - no schema data returned", status="failed"
            )
            return False

        self._extract_fields(schema_data)
        self.printer.print_msg("Introspection successful", status="success")
        return True

    def load_schema_from_dict(self, schema_data: Dict) -> bool:
        """
        Load schema from a pre-existing dict (e.g. read from a JSON file).

        Args:
            schema_data: The ``__schema`` portion of an introspection response.

        Returns:
            True if schema was loaded successfully.
        """
        if not schema_data:
            return False

        self._extract_fields(schema_data)
        self.printer.print_msg("Schema loaded from file", status="success")
        return True

    async def setup_endpoint(self, endpoint: str, proxy: Optional[str] = None) -> bool:
        """Set the endpoint, configure proxy if provided, and run introspection."""
        self.set_endpoint(endpoint)

        if proxy:
            try:
                proxy_host, proxy_port = proxy.split(":")
                self.configure_proxy(proxy_host, int(proxy_port))
            except ValueError:
                self.printer.print_msg(
                    "Invalid proxy format. Expected host:port", status="error"
                )
                return False

        return await self.introspection_query()

    async def test_connectivity(self, host: str, port: int) -> bool:
        """Test connectivity to a target server."""
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=2)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            pass

        try:
            test_url = f"http://{host}:{port}"
            response, error = await self.make_request("GET", test_url)
            return error is None
        except Exception:
            return False