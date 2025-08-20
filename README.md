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
pip install -e .
```

This method is useful for accessing the latest features or if you want to contribute to the development.

## Command Line Usage

GrapeQL comes with a powerful command-line interface for quick security assessments:

```bash
# Basic GraphQL endpoint test
grapeql --api https://example.com/graphql
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
grapeql --api https://example.com/graphql

# Include DoS testing
grapeql --api https://example.com/graphql --dos

# Use a proxy
grapeql --api https://example.com/graphql --proxy 127.0.0.1:8080

# Add authentication
grapeql --api https://example.com/graphql --auth "your_token_here" --auth-type Bearer

# Include a session cookie
grapeql --api https://example.com/graphql --cookie "session:abc123"

# Generate a markdown report
grapeql --api https://example.com/graphql --report report.md

# Generate a JSON report
grapeql --api https://example.com/graphql --report report.json --report-format json

# Custom injection testing credentials
grapeql --api https://example.com/graphql --username test_user --password test_pass
```

## Using GrapeQL as a Library

GrapeQL can be integrated into your Python applications as a library. This approach provides more flexibility and allows for custom testing workflows.

### Core Components

GrapeQL's modular design includes these key components:

1. **GraphQLClient**: Handles HTTP requests, headers, cookies, and proxy configuration
2. **Fingerprinter**: Identifies the GraphQL engine implementation
3. **InfoTester**: Tests for information disclosure vulnerabilities
4. **InjectionTester**: Tests for command injection vulnerabilities
5. **DosTester**: Tests for denial of service vulnerabilities
6. **Reporter**: Generates reports and summaries

Each component can be used independently or combined into custom testing workflows.

## Author

Aleksa Zatezalo
