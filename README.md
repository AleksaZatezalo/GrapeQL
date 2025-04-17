# GrapeQL

A comprehensive GraphQL security testing tool for detecting vulnerabilities in GraphQL APIs.

## Overview

GrapeQL is a powerful, modular GraphQL security testing tool designed to identify common vulnerabilities and security misconfigurations in GraphQL endpoints. It provides both a command-line interface for quick scans and a flexible Python library for integration into your security testing workflows.

## Features

- **GraphQL Fingerprinting**: Identify the underlying GraphQL engine
- **Information Disclosure Testing**: Detect schema leaks, field suggestions, and insecure configurations
- **Injection Testing**: Test for command injection vulnerabilities
- **SQL Injection:** Tests for SQL injection in GraphQL queries and mutations
- **Denial of Service Testing**: Identify DoS vulnerabilities through circular queries, deeply nested queries, and more
- **Comprehensive Reporting**: Generate detailed reports in Markdown or JSON formats

## Installation

### From Source

To install GrapeQL directly from the source code:

```bash
# Clone the repository
git clone https://github.com/AleksaZatezalo/grapeql.git

# Navigate to the project directory
cd grapeql

# Install for regular use
pip install .
```

This method is useful for accessing the latest features or if you want to contribute to the development.

## Command Line Usage

GrapeQL comes with a powerful command-line interface for quick security assessments:

```bash
# Basic GraphQL endpoint test
python -m grapeql --api https://example.com/graphql
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--api URL` | URL of the GraphQL endpoint to test (required) |
| `--dos` | Include Denial of Service testing (may impact target performance) |
| `--proxy HOST:PORT` | Proxy address (e.g., 127.0.0.1:8080) |
| `--auth TOKEN` | Authorization token to include in requests |
| `--auth-type TYPE` | Authorization token type (Bearer, Basic, etc.) |
| `--cookie NAME:VALUE` | Cookie in format 'name:value' |
| `--report FILENAME` | Output file for the report (e.g., report.md) |
| `--report-format FORMAT` | Report format (markdown or json) |
| `--username USERNAME` | Username for injection testing (default: admin) |
| `--password PASSWORD` | Password for injection testing (default: changeme) |

### CLI Examples

```bash
# Basic endpoint test
python -m grapeql --api https://example.com/graphql

# Include DoS testing
python -m grapeql --api https://example.com/graphql --dos

# Use a proxy
python -m grapeql --api https://example.com/graphql --proxy 127.0.0.1:8080

# Add authentication
python -m grapeql --api https://example.com/graphql --auth "your_token_here" --auth-type Bearer

# Include a session cookie
python -m grapeql --api https://example.com/graphql --cookie "session:abc123"

# Generate a markdown report
python -m grapeql --api https://example.com/graphql --report report.md

# Generate a JSON report
python -m grapeql --api https://example.com/graphql --report report.json --report-format json

# Custom injection testing credentials
python -m grapeql --api https://example.com/graphql --username test_user --password test_pass

# Comprehensive example
python -m grapeql --api https://example.com/graphql --dos --proxy 127.0.0.1:8080 --auth "token" --cookie "session:value" --report report.md --username admin --password s3cr3t
```

## Using GrapeQL as a Library

GrapeQL can be integrated into your Python applications as a library. This approach provides more flexibility and allows for custom testing workflows.

### Basic Usage

Here's a simple example of using GrapeQL as a library:

```python
import asyncio
from grapeql import GraphQLClient, Fingerprinter, InfoTester, InjectionTester, Reporter

async def test_endpoint():
    # Initialize components
    client = GraphQLClient()
    fingerprinter = Fingerprinter()
    info_tester = InfoTester()
    injection_tester = InjectionTester()
    reporter = Reporter()
    
    # Set target
    endpoint = "https://example.com/graphql"
    reporter.set_target(endpoint)
    
    # Fingerprint the GraphQL engine
    if await fingerprinter.setup_endpoint(endpoint):
        await fingerprinter.fingerprint()
        reporter.add_findings(fingerprinter.get_findings())
    
    # Run information disclosure tests
    if await info_tester.setup_endpoint(endpoint):
        await info_tester.run_test()
        reporter.add_findings(info_tester.get_findings())
    
    # Run injection tests
    if await injection_tester.setup_endpoint(endpoint):
        await injection_tester.run_test()
        reporter.add_findings(injection_tester.get_findings())
    
    # Print summary of findings
    reporter.print_summary()
    
    # Generate a report
    reporter.generate_report(output_format="markdown", output_file="report.md")

# Run the async function
asyncio.run(test_endpoint())
```

### Building a Custom Testing Pipeline

You can build a custom testing pipeline by selectively using GrapeQL components:

```python
import asyncio
from grapeql import GraphQLClient, DosTester, Reporter

async def custom_dos_test():
    dos_tester = DosTester()
    reporter = Reporter()
    
    endpoint = "https://example.com/graphql"
    reporter.set_target(endpoint)
    
    # Configure proxy if needed
    if await dos_tester.setup_endpoint(endpoint, proxy="127.0.0.1:8080"):
        # Set custom client configuration
        dos_tester.client.set_header("Authorization", "Bearer your-token-here")
        dos_tester.client.set_cookie("session", "your-session-cookie")
        
        # Run DoS tests
        await dos_tester.run_test()
        reporter.add_findings(dos_tester.get_findings())
    
    # Generate JSON report
    reporter.generate_report(output_format="json", output_file="dos_report.json")

asyncio.run(custom_dos_test())
```

### Working with the GraphQL Client Directly

For lower-level control, you can use the GraphQLClient directly:

```python
import asyncio
from grapeql import GraphQLClient

async def direct_client_usage():
    client = GraphQLClient()
    
    # Setup the client
    if await client.setup_endpoint("https://example.com/graphql"):
        # Add custom headers
        client.set_header("User-Agent", "Custom User Agent")
        client.set_authorization("your-auth-token", "Bearer")
        
        # Run an introspection query to get schema information
        await client.introspection_query()
        
        # Execute a custom GraphQL query
        query = """
        query {
          users {
            id
            username
          }
        }
        """
        
        response, error = await client.graphql_query(query)
        
        if error:
            print(f"Error: {error}")
        else:
            print(f"Response: {response}")

asyncio.run(direct_client_usage())
```

### Core Components

GrapeQL's modular design includes these key components:

1. **GraphQLClient**: Handles HTTP requests, headers, cookies, and proxy configuration
2. **Fingerprinter**: Identifies the GraphQL engine implementation
3. **InfoTester**: Tests for information disclosure vulnerabilities
4. **InjectionTester**: Tests for command injection vulnerabilities
5. **DosTester**: Tests for denial of service vulnerabilities
6. **Reporter**: Generates reports and summaries

Each component can be used independently or combined into custom testing workflows.

## Advanced Configuration

### Using a Proxy

```python
client = GraphQLClient()
client.configure_proxy("127.0.0.1", 8080)
```

### Setting Custom Headers and Cookies

```python
client = GraphQLClient()
client.set_header("X-Custom-Header", "value")
client.set_cookie("session", "cookie-value")
```

### Authentication

```python
client = GraphQLClient()
client.set_authorization("your-token", "Bearer")  # Default is Bearer
```

### Custom Injection Testing Credentials

```python
injection_tester = InjectionTester()
injection_tester.set_credentials("admin", "p@ssw0rd")
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Aleksa Zatezalo
