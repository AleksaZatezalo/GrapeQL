# InjectionTester

## Purpose
The InjectionTester module identifies injection-based vulnerabilities within GraphQL queries and mutations. By systematically testing input arguments with malicious payloads, the module helps detect weaknesses that could allow attackers to execute unintended commands, manipulate databases, or access sensitive data.

## Responsibilities
- Test GraphQL arguments for SQL injection indicators  
- Detect OS command injection vectors  
- Evaluate argument handling across queries and mutations  
- Record evidence supporting vulnerability detection  
- Contribute response timing data for baseline analysis  

## How It Works
The InjectionTester leverages YAML-defined payloads to conduct dynamic testing against the target endpoint. Payloads are injected into String and ID arguments to observe how the server processes untrusted input.

For injection detection, the module analyzes response patterns, error messages, and behavioral anomalies.

Because injection flaws often lead to critical compromise, this module plays a central role in the scanner’s security assessment capabilities.

## Inputs
- Target endpoint configured in the GraphQL Client  
- Injection payload definitions from YAML test cases  
- Authentication credentials (if provided)  
- Logger instance  
- Baseline tracker  

## Outputs
- Confirmed injection findings  
- Severity classifications (e.g., High or Critical)  
- Supporting payload evidence  
- Structured logs  
- Response timing metrics  

## Dependencies
The InjectionTester relies on shared infrastructure components:

- **GraphQL Client** — sends payload-bearing queries  
- **TestCaseLoader** — provides injection definitions  
- **GrapeLogger** — captures detailed telemetry  
- **BaselineTracker** — aggregates response times  

## Execution Flow
1. Load injection payloads from YAML files  
2. Enumerate eligible query and mutation arguments  
3. Inject payloads into each argument  
4. Send requests through the GraphQL Client  
5. Analyze responses for indicators of compromise  
6. Record confirmed findings  
7. Forward timing metrics to the baseline tracker  
8. Log all activity for reporting  

## Failure Handling
The module is engineered to maintain scan stability:

- Network interruptions are logged without halting execution  
- Non-deterministic responses are recorded for analyst review  
- Authentication failures surface clear diagnostic signals  

These safeguards ensure reliable operation across diverse environments.

## Extension Points
Developers can enhance injection coverage by:

- Adding new payload definitions to YAML  
- Expanding detection indicators  
- Supporting emerging injection techniques  
- Introducing adaptive payload strategies  

This extensibility ensures the module remains effective against evolving attack methods.
