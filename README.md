# 🍇 GrapeQL: The GraphQL Security Testing Suite

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

Let me analyze the code and rewrite the Features section to accurately reflect the implemented classes.



## Features

### 1. The Vine: Endpoint Discovery and Enumeration

- Automated port scanning with direct connection capabilities
- Concurrent directory busting for GraphQL endpoints
- Configurable endpoint path enumeration
- Built-in common GraphQL endpoint path detection
- Proxy support for HTTP operations through Burp Suite
- Introspection query testing to identify vulnerable endpoints
- Custom endpoint list configuration

### 2. Root Analysis: GraphQL Engine Detection

- Comprehensive GraphQL server implementation fingerprinting
- Support for detecting 25+ GraphQL engines including:
  - Apollo Server
  - GraphQL Yoga
  - AWS AppSync
  - Hasura
  - GraphQL PHP
  - Ruby GraphQL
  - And many more
- Detailed error message analysis
- Custom query generation for engine identification
- Proxy-aware implementation testing

### 3. Seeds: CSRF and Method Testing

- Field suggestion vulnerability detection
- GET-based mutation testing for CSRF vulnerabilities
- Query method support analysis
- POST-based CSRF testing with different content types
- Detailed vulnerability reporting including:
- Severity classification
- Impact assessment
- Verification commands (curl)
- Vulnerability descriptions

### 4. Juice: Command Injection Testing

- Schema-aware query generation for targeted testing
- Authenticated command injection testing

### 5. Crush: DoS Vulnerability Testing

- Schema-aware query generation for targeted testing
- Circular query vulnerability detection
- Field duplication attack testing
- Array batching vulnerability assessment
- Response time analysis for DoS detection
- Detailed vulnerability reporting
- Proxy support for request routing
- Introspection-based query customization
- Configurable test parameters

Each module is designed to work independently or as part of the complete suite, with built-in proxy support for integration with security testing tools like Burp Suite. The tools use asynchronous operations for efficient testing and provide detailed output through a custom printing system.

## Why GrapeQL?

Like a bunch of grapes, GraphQL endpoints have many interconnected parts that need to be tested thoroughly. GrapeQL tests each "grape" (component) while understanding how they connect to form the whole cluster (API). Our tool is designed to be sweet and simple to use, while providing comprehensive coverage.

## Donation Link

If you have benefited from this project and use Monero please consider donanting to the following address:
47RoH3K4j8STLSh8ZQ2vUXZdh7GTK6dBy7uEBopegzkp6kK4fBrznkKjE3doTamn3W7A5DHbWXNdjaz2nbZmSmAk8X19ezQ

## References

[Black Hat GraphQL: Attacking Next Generation APIs](https://www.amazon.ca/Black-Hat-GraphQL-Attacking-Generation/dp/1718502842/ref=sr_1_1?crid=2RWOVMS6ZU37K&dib=eyJ2IjoiMSJ9.zi2F-G8cD7sWGnrOzCNkvFjddnK2D59sNLYKIZ8QJK9V3QbeUo7VBlnzXEGX82jYpv1QMXAC0C_4kj4Y0MXiv3KNl53mvu7qPjJQBM0vOWgc_1Et6Jl2-P6wzubxEb1GsrPwYrpP90ANX0YhXvach8Opmb4sAG5QinlPdH111nP77cxVKPXKbnbNoWtRaF8EqDISUcmgWQncANYpzbCxe3s2_wcco0jgqCC0t5JwLcenRfLWpBZIsYPOc4ze_V7WhN2NRitIJhcRcHeD1WSjkDF6oR82x8ICn5IRe6fcyFk.bieYcTT6FhT1u0tO01xkxQlbB9LSAxe6PJE-MkhLcUM&dib_tag=se&keywords=black+hat+graphql&qid=1729479754&sprefix=blackhat+gra%2Caps%2C237&sr=8-1)

[GraphQL | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)

[So you want to Hack GraphQL APIs ??](https://www.youtube.com/watch?v=OOztEJu0Vts)
