# GraphQL DoS Vulnerability Scanner
Version: 1.0
Author: Initial documentation prepared January 2025

## Overview
The GraphQL DoS Vulnerability Scanner is a security testing tool designed to identify potential Denial of Service (DoS) vulnerabilities in GraphQL endpoints. It performs automated testing for common attack vectors that could lead to service degradation or disruption.

## Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Required Packages
```bash
pip install aiohttp
```

## Usage

### Basic Usage
```bash
python graphql-dos.py http://example.com/graphql
```

### Advanced Options
```bash
python graphql-dos.py http://example.com/graphql --max-depth 15 --max-aliases 2000
```

### Command Line Arguments
- `url`: Required. The GraphQL endpoint URL to test
- `--max-depth`: Optional. Maximum query depth for nested attack testing (default: 10)
- `--max-aliases`: Optional. Maximum number of aliases for duplication attack testing (default: 1000)

## Attack Vectors Tested

### 1. Nested Query Attacks
Tests the endpoint's resilience against deeply nested queries that could cause excessive resource consumption.

Example of a nested query:
```graphql
query NestedQuery {
  user {
    friends {
      friends {
        friends {
          # Continues nesting...
        }
      }
    }
  }
}
```

### 2. Circular Fragment Attacks
Tests for proper handling of circular fragment references that could cause infinite recursion.

Example of a circular fragment:
```graphql
query CircularQuery {
  ...FragmentA
}
fragment FragmentA on Query {
  ...FragmentB
}
fragment FragmentB on Query {
  ...FragmentA
}
```

### 3. Field Duplication Attacks
Tests for vulnerabilities to field aliasing attacks that could cause excessive resource usage.

Example of field duplication:
```graphql
query DuplicateQuery {
  field_1: user
  field_2: user
  field_3: user
  # Continues duplicating...
}
```

## Test Results

### Success Criteria
The tool considers a potential vulnerability present if any of the following occur:
- Response time exceeds 5 seconds
- Server returns a 500 error
- Query execution times out
- Server becomes unresponsive

### Output Format
```
=== Vulnerability Scan Summary ===
[!] Potential DoS vulnerabilities found:
  - Nested Query
  - Field Duplication

Recommendations:
- Implement query depth limiting
- Add query complexity analysis
- Set timeouts for query execution
- Implement rate limiting
```

## Mitigation Recommendations

### Query Depth Limiting
Implement maximum depth restrictions for GraphQL queries to prevent nested query attacks.

Example configuration (using graphql-depth-limit):
```javascript
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  validationRules: [depthLimit(5)]
});
```

### Query Complexity Analysis
Implement query complexity scoring to reject queries that exceed computational limits.

Example (using graphql-query-complexity):
```javascript
import queryComplexity from 'graphql-query-complexity';

const server = new ApolloServer({
  validationRules: [
    queryComplexity({
      maximumComplexity: 1000,
      variables: {},
      onComplete: (complexity) => {
        console.log('Query Complexity:', complexity);
      }
    })
  ]
});
```

### Timeout Implementation
Set appropriate timeouts for query execution to prevent resource exhaustion.

Example:
```javascript
const server = new ApolloServer({
  plugins: [
    {
      requestDidStart: () => ({
        willSendResponse: async (requestContext) => {
          if (requestContext.operationName === 'LongRunningQuery') {
            setTimeout(() => {
              throw new Error('Query timeout');
            }, 5000);
          }
        },
      }),
    },
  ],
});
```

## Security Considerations

### Legal Compliance
- Only use this tool on systems you have explicit permission to test
- Be aware that DoS testing could impact system availability
- Document and communicate testing windows with system owners

### Best Practices
1. Test in staging environments first
2. Monitor system resources during testing
3. Have rollback procedures ready
4. Maintain logs of all testing activities

## Limitations
- The tool may produce false positives
- Not all GraphQL implementations support introspection
- Some vulnerabilities may only manifest under specific conditions
- Tool effectiveness depends on server-side implementation details

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## License
This tool is released under the MIT License. See LICENSE file for details.