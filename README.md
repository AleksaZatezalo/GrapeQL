# 🍇 GrapeQL: The GraphQL Security Testing Suite
<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.10-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

</div>
Version: 1.0
Last Updated: January 2025

## Overview
GrapeQL is a comprehensive GraphQL security assessment toolkit designed to help security researchers and developers identify vulnerabilities in GraphQL implementations. Named after the fruit that grows in clusters, GrapeQL tests multiple security aspects of your GraphQL endpoint in parallel, providing thorough coverage of potential security issues.

```ascii
   .     .  🍇  .      .
.  .  🍇  .  🍇   .    
  🍇   GrapeQL   🍇  .  
. 🍇  Security  🍇 .   
   .  🍇  .  🍇  .     
      .    .    .      
```

## Features

### 1. Endpoint Harvesting (The Vine)
- Automated GraphQL endpoint discovery
- Common endpoint path enumeration
- Development/staging endpoint detection
- WebSocket endpoint identification
- Custom endpoint pattern matching

### 2. Schema Analysis (The Root)
- Introspection query testing
- Schema validation and analysis
- Deprecated field detection
- Type consistency checking
- Permission boundary testing
- Schema drift detection

### 3. Authentication Testing (The Guard)
- Authentication bypass detection
- Token validation and testing
- Session management analysis
- Role-based access control (RBAC) testing
- OAuth 2.0 and JWT validation

### 4. Query Testing (The Juice)
- Nested query vulnerability detection
- Circular fragment testing
- Field duplication attacks
- Resource exhaustion tests
- Query complexity analysis
- Batch query testing
- Operation name validation

### 5. Mutation Testing (The Seeds)
- Input validation testing
- File upload vulnerability testing
- SQL injection via mutations
- Cross-site scripting (XSS) detection
- Remote code execution attempts
- Mass assignment vulnerability testing

### 6. DoS Protection Testing (The Crush)
- Rate limiting validation
- Query depth analysis
- Cost analysis
- Timeout handling
- Resource allocation testing
- Batch operation stress testing

## Installation

### Prerequisites
```bash
# Required
Python 3.7+
pip package manager

# Optional
Docker (for isolated testing)
Burp Suite (for proxy integration)
```

### Basic Installation
```bash
pip install grapeql
```

### Development Installation
```bash
git clone https://github.com/your-repo/grapeql
cd grapeql
pip install -e ".[dev]"
```

## Usage

### Quick Start
```bash
grapeql http://target.com/graphql
```

### Advanced Usage
```bash
grapeql http://target.com/graphql \
  --auth-token "Bearer token" \
  --depth 15 \
  --rate-limit 100 \
  --proxy http://localhost:8080 \
  --output report.json \
  --modules all
```

### Command Line Arguments
```
Required Arguments:
  url                   GraphQL endpoint URL

Optional Arguments:
  --auth-token          Authorization token
  --depth               Maximum query depth (default: 10)
  --rate-limit          Requests per second (default: 50)
  --proxy               Proxy URL for requests
  --output              Output file path
  --timeout             Request timeout in seconds
  --verbose             Enable verbose output
  --no-introspection    Skip introspection queries
  --custom-headers      Add custom HTTP headers
  --modules             Specify modules to run (comma-separated)
```

## Test Modules

### Authentication and Authorization (auth)
```graphql
# Example test for unauthorized access
query unauthorized {
  sensitiveData {
    id
    content
  }
}
```

### Query Depth Testing (depth)
```graphql
# Example of nested query test
query deep {
  user {
    friends {
      friends {
        # Continues nesting...
      }
    }
  }
}
```

### Data Exposure (exposure)
```graphql
# Example of field exposure test
query exposure {
  users {
    id
    email
    password
    internalNotes
  }
}
```

## Output Format

### JSON Format
```json
{
  "scan_info": {
    "target": "http://example.com/graphql",
    "timestamp": "2025-01-18T10:00:00",
    "duration": "120s",
    "grapeql_version": "1.0"
  },
  "vulnerabilities": [
    {
      "type": "Authentication Bypass",
      "severity": "High",
      "description": "Unauthorized access to sensitive data",
      "proof": "Query returned sensitive data without authentication"
    }
  ],
  "recommendations": [
    {
      "title": "Implement Authentication",
      "description": "Add proper authentication checks",
      "priority": "High"
    }
  ]
}
```

## Security Recommendations

### Implementation Guidelines
1. Enable authentication for all sensitive queries
2. Implement proper rate limiting
3. Set query depth limits
4. Use query complexity analysis
5. Implement proper error handling
6. Enable logging and monitoring

### Code Examples

#### Query Depth Limiting (Node.js)
```javascript
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  validationRules: [depthLimit(5)]
});
```

#### Rate Limiting (Python)
```python
from graphql import GraphQLError
from datetime import datetime, timedelta

def rate_limit_directive(max_requests=100, window_seconds=60):
    def rate_limit(resolver, *args, **kwargs):
        # Rate limiting logic here
        return resolver(*args, **kwargs)
    return rate_limit
```

## Best Practices

### Testing Methodology
1. Start with non-intrusive tests
2. Gradually increase test complexity
3. Monitor system response
4. Document all findings
5. Validate results manually

### Risk Mitigation
1. Test in staging environments first
2. Have rollback procedures ready
3. Monitor system resources
4. Maintain audit logs
5. Have incident response plans

## Contributing
We welcome contributions to GrapeQL! Please follow these steps:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request
5. Follow our code of conduct

## License
GrapeQL is licensed under the MIT License. See LICENSE file for details.

## A Note on Responsible Testing
GrapeQL is a powerful testing tool. Always ensure you have explicit permission to test target systems and use the tool responsibly.

## Why GrapeQL?
Like a bunch of grapes, GraphQL endpoints have many interconnected parts that need to be tested thoroughly. GrapeQL tests each "grape" (component) while understanding how they connect to form the whole cluster (API). Our tool is designed to be sweet and simple to use, while providing comprehensive coverage.
## Donation Link

If you have benefited from this project and use Monero please consider donanting to the following address:
47RoH3K4j8STLSh8ZQ2vUXZdh7GTK6dBy7uEBopegzkp6kK4fBrznkKjE3doTamn3W7A5DHbWXNdjaz2nbZmSmAk8X19ezQ

## References

[Black Hat GraphQL: Attacking Next Generation APIs](https://www.amazon.ca/Black-Hat-GraphQL-Attacking-Generation/dp/1718502842/ref=sr_1_1?crid=2RWOVMS6ZU37K&dib=eyJ2IjoiMSJ9.zi2F-G8cD7sWGnrOzCNkvFjddnK2D59sNLYKIZ8QJK9V3QbeUo7VBlnzXEGX82jYpv1QMXAC0C_4kj4Y0MXiv3KNl53mvu7qPjJQBM0vOWgc_1Et6Jl2-P6wzubxEb1GsrPwYrpP90ANX0YhXvach8Opmb4sAG5QinlPdH111nP77cxVKPXKbnbNoWtRaF8EqDISUcmgWQncANYpzbCxe3s2_wcco0jgqCC0t5JwLcenRfLWpBZIsYPOc4ze_V7WhN2NRitIJhcRcHeD1WSjkDF6oR82x8ICn5IRe6fcyFk.bieYcTT6FhT1u0tO01xkxQlbB9LSAxe6PJE-MkhLcUM&dib_tag=se&keywords=black+hat+graphql&qid=1729479754&sprefix=blackhat+gra%2Caps%2C237&sr=8-1)

[GraphQL | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)

[So you want to Hack GraphQL APIs ??](https://www.youtube.com/watch?v=OOztEJu0Vts)
