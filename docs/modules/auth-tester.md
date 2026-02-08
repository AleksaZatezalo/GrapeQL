# AuthTester

## Purpose
The AuthTester module evaluates authentication and authorization controls within GraphQL endpoints. Its objective is to identify weaknesses that could allow unauthorized access, privilege escalation, or unintended data exposure.

## Responsibilities
- Detect authentication bypass opportunities  
- Identify insecure direct object reference (IDOR) patterns  
- Test unauthenticated access to protected operations  
- Evaluate header-based authorization behavior  
- Highlight access control misconfigurations  
- Contribute response timing data to the baseline tracker  

## How It Works
The AuthTester executes YAML-defined test cases designed to simulate adversarial access patterns. These tests manipulate authorization headers, tokens, and object identifiers to observe how the server enforces access restrictions.

The module compares responses from authenticated and unauthenticated requests to detect inconsistencies that may indicate broken access controls.

Where applicable, enumeration techniques are used to determine whether object identifiers can be iterated to access data belonging to other users.

Because access control flaws often result in severe data breaches, this module plays a critical role in the overall security assessment.

## Inputs
- Target endpoint configured in the GraphQL Client  
- Authorization tokens (optional)  
- Authentication test cases loaded from YAML  
- Logger instance  
- Baseline tracker  

## Outputs
- Confirmed authentication or authorization weaknesses  
- Severity-tagged findings  
- Evidence supporting detection  
- Structured telemetry logs  
- Timing metrics for baseline analysis  

## Dependencies
The AuthTester relies on shared scanning infrastructure:

- **GraphQL Client** — sends authenticated and unauthenticated requests  
- **TestCaseLoader** — supplies bypass and enumeration strategies  
- **GrapeLogger** — records request and response metadata  
- **BaselineTracker** — aggregates response timing  

## Execution Flow
1. Load authentication test cases  
2. Establish request contexts (authenticated vs. unauthenticated)  
3. Execute access control probes  
4. Compare server responses for enforcement gaps  
5. Attempt identifier enumeration where applicable  
6. Record confirmed weaknesses  
7. Forward timing data to the baseline tracker  
8. Log findings for centralized reporting  

## Failure Handling
The module is designed for resilient operation:

- Missing credentials trigger unauthenticated-only checks  
- Invalid tokens are logged without interrupting the scan  
- Unexpected authorization responses are captured for review  
- Network failures do not halt downstream modules  

These safeguards ensure consistent scan progression.

## Extension Points
Developers can enhance access control testing by:

- Adding new bypass strategies to YAML  
- Expanding identifier enumeration techniques  
- Supporting emerging authentication schemes  
- Introducing role-based testing logic  
- Refining detection heuristics  

This flexibility allows the module to evolve alongside modern authorization models.
