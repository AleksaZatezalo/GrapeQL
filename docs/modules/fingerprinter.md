# Fingerprinter

## Purpose
The Fingerprinter module identifies the underlying GraphQL engine powering the target endpoint. Understanding the server technology enables more accurate vulnerability testing and allows subsequent modules to tailor payload strategies based on platform-specific behaviors.

## Responsibilities
- Detect the GraphQL implementation (e.g., Apollo, Hasura, Graphene)
- Execute behavioral probes against the endpoint
- Analyze error messages and response patterns
- Establish environmental context for downstream testing modules
- Contribute response timing data to the baseline tracker

## How It Works
The Fingerprinter uses predefined YAML-based probes designed to trigger distinctive responses from various GraphQL engines. These probes are sent to the endpoint through the shared GraphQL client.

Responses are evaluated for identifiable characteristics such as error structures, directive handling, validation messages, and execution behavior. When a match is detected, the module records the likely engine along with supporting evidence.

Because the module runs at the beginning of the scan lifecycle, it helps inform later testing decisions and improves the overall accuracy of vulnerability detection.

## Inputs
- Target endpoint configured in the GraphQL Client  
- Fingerprinting probe definitions from YAML test cases  
- Logger instance for structured telemetry  
- Baseline tracker for timing metrics  

## Outputs
- Identified GraphQL engine (when detectable)  
- Supporting probe results  
- Structured log entries  
- Response timing data for baseline analysis  

## Dependencies
The Fingerprinter relies on shared infrastructure:

- **GraphQL Client** — executes probe queries  
- **TestCaseLoader** — supplies fingerprinting probes  
- **GrapeLogger** — records request and response metadata  
- **BaselineTracker** — aggregates response timing  

## Execution Flow
1. Load fingerprinting probes from YAML definitions  
2. Send probe queries to the target endpoint  
3. Analyze returned responses for engine-specific indicators  
4. Record detection results  
5. Forward timing data to the baseline tracker  
6. Log findings for downstream reporting  

## Failure Handling
The module is designed to operate safely even when fingerprinting is inconclusive:

- If responses lack identifiable traits, the engine is marked as unknown  
- Network or timeout errors are logged without interrupting the scan  
- Unexpected response formats are captured for diagnostic review  

These safeguards ensure the broader scan can proceed regardless of fingerprinting success.

## Extension Points
Developers can enhance fingerprint coverage by:

- Adding new probe definitions to the YAML test cases  
- Expanding detection indicators  
- Supporting emerging GraphQL server implementations  
- Refining response analysis techniques  

This approach allows the module to evolve alongside the GraphQL ecosystem.
