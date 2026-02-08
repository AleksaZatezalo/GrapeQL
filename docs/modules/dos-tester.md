# DosTester

## Purpose
The DosTester module evaluates the resilience of a GraphQL endpoint against denial-of-service (DoS) attacks. Its objective is to identify query patterns capable of exhausting server resources, degrading performance, or causing service disruption.

## Responsibilities
- Detect query complexity vulnerabilities  
- Test deep nesting and recursive query structures  
- Identify fragment-based amplification attacks  
- Evaluate field duplication and batching abuse  
- Measure response latency under stress conditions  
- Leverage statistical baselines to distinguish anomalies from normal behavior  

## How It Works
The DosTester executes specialized YAML-defined attack patterns designed to stress the GraphQL execution engine. These patterns intentionally increase computational cost by generating complex queries that require excessive resolver activity.

Unlike simple threshold-based approaches, the module relies on response timing data gathered during earlier scan phases. Using this baseline, it identifies statistically significant latency deviations that may indicate resource exhaustion risks.

Because the module depends on prior timing analysis, it always runs after other testing modules have populated the baseline tracker.

## Inputs
- Target endpoint configured in the GraphQL Client  
- DoS attack definitions loaded from YAML  
- Response timing baseline  
- Logger instance  

## Outputs
- Identified performance degradation risks  
- Baseline deviation metrics  
- Severity-tagged findings  
- Structured logs documenting stress tests  

## Dependencies
The DosTester relies heavily on shared infrastructure:

- **GraphQL Client** — executes complex queries  
- **TestCaseLoader** — supplies DoS attack configurations  
- **BaselineTracker** — provides statistical response thresholds  
- **GrapeLogger** — records performance telemetry  

## Execution Flow
1. Retrieve the established response-time baseline  
2. Load DoS attack configurations  
3. Generate high-complexity queries  
4. Send stress queries to the endpoint  
5. Measure response latency  
6. Compare results against baseline thresholds  
7. Identify statistically significant deviations  
8. Record confirmed risks  
9. Log performance data for reporting  

## Failure Handling
Given the sensitive nature of stress testing, the module incorporates protective safeguards:

- Avoids uncontrolled traffic generation  
- Logs abnormal termination conditions  
- Handles timeout events gracefully  
- Prevents cascading failures across modules  

If the target becomes unstable, the module captures available telemetry without compromising scan integrity.

## Extension Points
Developers can expand DoS testing capabilities by:

- Adding new complexity attack patterns  
- Refining statistical detection models  
- Supporting adaptive query generation  
- Introducing concurrency-based stress techniques  
- Enhancing resolver cost estimation  

This extensibility ensures continued effectiveness as GraphQL performance strategies evolve.
