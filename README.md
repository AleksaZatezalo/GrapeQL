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

## Features

### 1. Endpoint Harvesting (The Vine)

- Automated port scanning
- Automated GraphQL endpoint discovery
- Common endpoint path enumeration

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

## Why GrapeQL?

Like a bunch of grapes, GraphQL endpoints have many interconnected parts that need to be tested thoroughly. GrapeQL tests each "grape" (component) while understanding how they connect to form the whole cluster (API). Our tool is designed to be sweet and simple to use, while providing comprehensive coverage.

## Donation Link

If you have benefited from this project and use Monero please consider donanting to the following address:
47RoH3K4j8STLSh8ZQ2vUXZdh7GTK6dBy7uEBopegzkp6kK4fBrznkKjE3doTamn3W7A5DHbWXNdjaz2nbZmSmAk8X19ezQ

## References

[Black Hat GraphQL: Attacking Next Generation APIs](https://www.amazon.ca/Black-Hat-GraphQL-Attacking-Generation/dp/1718502842/ref=sr_1_1?crid=2RWOVMS6ZU37K&dib=eyJ2IjoiMSJ9.zi2F-G8cD7sWGnrOzCNkvFjddnK2D59sNLYKIZ8QJK9V3QbeUo7VBlnzXEGX82jYpv1QMXAC0C_4kj4Y0MXiv3KNl53mvu7qPjJQBM0vOWgc_1Et6Jl2-P6wzubxEb1GsrPwYrpP90ANX0YhXvach8Opmb4sAG5QinlPdH111nP77cxVKPXKbnbNoWtRaF8EqDISUcmgWQncANYpzbCxe3s2_wcco0jgqCC0t5JwLcenRfLWpBZIsYPOc4ze_V7WhN2NRitIJhcRcHeD1WSjkDF6oR82x8ICn5IRe6fcyFk.bieYcTT6FhT1u0tO01xkxQlbB9LSAxe6PJE-MkhLcUM&dib_tag=se&keywords=black+hat+graphql&qid=1729479754&sprefix=blackhat+gra%2Caps%2C237&sr=8-1)

[GraphQL | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)

[So you want to Hack GraphQL APIs ??](https://www.youtube.com/watch?v=OOztEJu0Vts)
