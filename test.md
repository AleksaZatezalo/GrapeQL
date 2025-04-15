# GrapeQL Security Report

Date: 2025-04-15 21:59:36

## Endpoint: http://127.0.0.1:5013/graphql

###  Medium Severity Vulnerabilities

#### Introspection Enabled

**Description**: GraphQL introspection allows clients to query the schema structure

**Details**: The server has introspection enabled, which can expose sensitive schema information

#### CSRF Vulnerability

**Description**: Server accepts form-encoded requests, enabling potential CSRF

**Details**: The server accepts form-encoded requests, which may enable CSRF attacks

### Summary

- Total tests run: 7
- Vulnerabilities found: 2
  - High severity: 0
  - Medium severity: 2
  - Low severity: 0

---



*This report was generated automatically by GrapeQL*
