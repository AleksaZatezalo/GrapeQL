# InfoTester

## Purpose
The InfoTester module detects unintended information exposure within GraphQL endpoints. By identifying configuration weaknesses and excessive schema visibility, the module helps organizations reduce reconnaissance opportunities for attackers.

## Responsibilities
- Detect enabled introspection in production environments  
- Identify field suggestion leaks in error responses  
- Verify GraphiQL or interactive IDE exposure  
- Test support for batch queries and alternate transports  
- Highlight misconfigurations that may aid attacker discovery  

## How It Works
The InfoTester executes a collection of YAML-defined checks designed to safely probe the target endpoint for information disclosure risks.

Each test sends carefully crafted queries that trigger responses revealing schema behavior, validation hints, or developer tooling exposure. The module then analyzes responses for predefined detection indicators such as verbose error messages or suggestion prompts.

Because these weaknesses often precede more serious attacks, early identification improves the effectiveness of downstream vulnerability testing modules.

## Inputs
- Target endpoint from the GraphQL Client  
- Information disclosure test cases loaded from YAML  
- Logger instance  
- Baseline tracker for response timing  

## Outputs
- Identified disclosure risks  
- Severity-tagged findings  
- Structured log entries  
- Timing metrics contributing to baseline calculations  

## Dependencies
The module relies on shared scanning infrastructure:

- **GraphQL Client** — executes disclosure probes  
- **TestCaseLoader** — supplies YAML-based checks  
- **GrapeLogger** — records telemetry  
- **BaselineTracker** — aggregates response timing  

## Execution Flow
1. Load information disclosure test cases  
2. Send probe queries to the endpoint  
3. Evaluate responses against detection indicators  
4. Record confirmed exposures  
5. Forward timing data to the baseline tracker  
6. Log findings for centralized reporting  

## Failure Handling
The module is designed to operate non-disruptively:

- If introspection is disabled, related checks are skipped gracefully  
- Unexpected response formats are logged for analysis  
- Network failures do not interrupt the broader scan lifecycle  

These safeguards ensure consistent scan execution even in hardened environments.

## Extension Points
Developers can expand disclosure coverage by:

- Adding new YAML-based checks  
- Updating detection indicators  
- Supporting emerging GraphQL tooling exposures  
- Enhancing validation heuristics  

This modular approach allows the InfoTester to adapt as disclosure techniques evolve.
