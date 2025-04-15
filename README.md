# GrapeQL

A GraphQL Security Testing Tool for analyzing and identifying vulnerabilities in GraphQL APIs.

## Features

- Port scanning and GraphQL endpoint discovery
- GraphQL engine fingerprinting
- Schema introspection and analysis
- Vulnerability testing:
  - SQL and command injection detection
  - Denial of Service (DoS) vulnerability testing
  - Information disclosure vulnerability detection
- Detailed reporting in multiple formats

## Installation

### From PyPI

```bash
pip install grapeql
```

### From Source

```bash
git clone https://github.com/aleksazatezalo/grapeql.git
cd grapeql
pip install -e .
```

## Usage

### Command Line Interface

```bash
# Test a specific GraphQL endpoint
grapeql --api https://example.com/graphql

# Scan a target IP for GraphQL endpoints and test them
grapeql --target 192.168.1.1

# Run specific test modules
grapeql --api https://example.com/graphql --modules info,injection,dos

# Use a proxy for requests
grapeql --api https://example.com/graphql --proxy 127.0.0.1:8080

# Generate a report
grapeql --api https://example.com/graphql --report --report-format markdown
```

For full usage options:

```bash
grapeql --help
```

### Using as a Library

```python
import asyncio
from grapeql import InfoTester, InjectionTester, Reporter

async def main():

    # Find GraphQL endpoints
    endpoints = await scanner.scan_url("https://example.com/graphql")
    
    # Run information disclosure tests
    info_tester = InfoTester()
    await info_tester.setup_endpoint(endpoints[0])
    await info_tester.run_test()
    
    # Run injection tests
    injection_tester = InjectionTester()
    await injection_tester.setup_endpoint(endpoints[0])
    await injection_tester.run_test()
    
    # Generate report
    reporter = Reporter()
    reporter.set_target("https://example.com/graphql")
    reporter.add_findings(info_tester.get_findings())
    reporter.add_findings(injection_tester.get_findings())
    reporter.generate_report("markdown", "report.md")

if __name__ == "__main__":
    asyncio.run(main())
```

## Test Modules

GrapeQL includes several test modules:

- **info**: Tests for information disclosure vulnerabilities
- **injection**: Tests for SQL and command injection vulnerabilities
- **dos**: Tests for Denial of Service vulnerabilities
- **fingerprint**: Identifies the GraphQL engine implementation

## License

MIT

## Author

Aleksa Zatezalo
