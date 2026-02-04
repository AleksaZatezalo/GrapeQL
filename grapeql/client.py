"""
GrapeQL HTTP Client
Author: Aleksa Zatezalo
Version: 3.1
Date: February 2025
Description: Core HTTP client for GrapeQL with consistent request handling and structured logging.
"""

import aiohttp
import asyncio
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from .utils import GrapePrinter
from .logger import GrapeLogger


class GraphQLClient:
    """
    Unified HTTP client for all GrapeQL modules providing consistent
    request handling, proxy support, header/cookie management, and
    structured logging of every request/response pair.
    """

    def __init__(self, logger: Optional[GrapeLogger] = None):
        self.printer = GrapePrinter()
        self.logger = logger
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

    def set_log_context(self, module: str, test: str = "-") -> None:
        self._log_module = module
        self._log_test = test

    # ------------------------------------------------------------------ #
    # Configuration helpers
    # ------------------------------------------------------------------ #

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
            async with aiohttp.ClientSession() as session:
                async with session.request(
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
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """Execute a GraphQL query with proper formatting."""
        if not self.endpoint:
            error_msg = "No GraphQL endpoint set"
            self.printer.print_msg(error_msg, status="error")
            return None, error_msg

        payload_body: Dict[str, Any] = {"query": query}
        if variables:
            payload_body["variables"] = variables
        if operation_name:
            payload_body["operationName"] = operation_name

        return await self.make_request(
            "POST",
            json=payload_body,
            _log_parameter=_log_parameter,
            _log_payload=_log_payload or query[:120],
        )

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