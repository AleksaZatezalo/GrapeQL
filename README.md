# GrapeQL - GraphQL Security Testing Tool

GrapeQL is a comprehensive GraphQL security testing tool designed to identify vulnerabilities in GraphQL endpoints. The tool combines port scanning, directory enumeration, GraphQL schema analysis, and various security tests to provide a complete security assessment of GraphQL implementations.

## Features

- **Endpoint Discovery**: Port scanning and directory busting to find GraphQL endpoints
- **Server Fingerprinting**: Identify the GraphQL server implementation (Apollo, Hasura, etc.)
- **Schema Analysis**: Extract and analyze schema information through introspection
- **Vulnerability Testing**:
  - Introspection vulnerability detection
  - Cross-Site Request Forgery (CSRF) vulnerability testing
  - Command injection testing
  - Denial of Service (DoS) attack simulation
- **Reporting**: Generate comprehensive reports in Markdown or JSON format

## Architecture

The codebase follows a modular architecture with several key components:

### Core Components

- **GraphQLClient**: Unified HTTP client for all GraphQL requests
- **SchemaManager**: Central schema parsing and management
- **BaseTester**: Common base class for all testing modules

### Testing Modules

- **vine**: Endpoint discovery through port scanning and directory busting
- **root**: GraphQL server fingerprinting
- **seeds**: Basic security vulnerability checks
- **juice**: Command and SQL injection testing
- **crush**: Denial of Service testing

## Setup

```bash
# Clone the repository
git clone https://github.com/username/grapeql.git
cd grapeql

# Install the package
pip install -e .
```

## Usage

```bash
# Basic usage with direct API endpoint
grapeql --api https://example.com/graphql

# Full scan with port scanning and directory busting
grapeql -t 192.168.1.1

# With proxy (useful for Burp Suite integration)
grapeql --api https://example.com/graphql -p 127.0.0.1:8080

# Custom headers and authentication
grapeql --api https://example.com/graphql --header "User-Agent:Mozilla/5.0" --auth "your-token"

# Generate a report
grapeql --api https://example.com/graphql --report vulnerability-report.md

# Run DoS testing (use with caution)
grapeql --api https://example.com/graphql -c
```

## Contribution

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Donation Link

If you have benefited from this project and use Monero please consider donanting to the following address:
47RoH3K4j8STLSh8ZQ2vUXZdh7GTK6dBy7uEBopegzkp6kK4fBrznkKjE3doTamn3W7A5DHbWXNdjaz2nbZmSmAk8X19ezQ

## References

[Black Hat GraphQL: Attacking Next Generation APIs](https://www.amazon.ca/Black-Hat-GraphQL-Attacking-Generation/dp/1718502842/ref=sr_1_1?crid=2RWOVMS6ZU37K&dib=eyJ2IjoiMSJ9.zi2F-G8cD7sWGnrOzCNkvFjddnK2D59sNLYKIZ8QJK9V3QbeUo7VBlnzXEGX82jYpv1QMXAC0C_4kj4Y0MXiv3KNl53mvu7qPjJQBM0vOWgc_1Et6Jl2-P6wzubxEb1GsrPwYrpP90ANX0YhXvach8Opmb4sAG5QinlPdH111nP77cxVKPXKbnbNoWtRaF8EqDISUcmgWQncANYpzbCxe3s2_wcco0jgqCC0t5JwLcenRfLWpBZIsYPOc4ze_V7WhN2NRitIJhcRcHeD1WSjkDF6oR82x8ICn5IRe6fcyFk.bieYcTT6FhT1u0tO01xkxQlbB9LSAxe6PJE-MkhLcUM&dib_tag=se&keywords=black+hat+graphql&qid=1729479754&sprefix=blackhat+gra%2Caps%2C237&sr=8-1)

[GraphQL | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)

[So you want to Hack GraphQL APIs ??](https://www.youtube.com/watch?v=OOztEJu0Vts)
