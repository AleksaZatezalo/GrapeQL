# Module Overview

## Purpose
This document provides a high-level overview of the modules that compose the GrapeQL security scanner. It is intended to help developers, security engineers, and contributors quickly understand the system structure, module responsibilities, and execution relationships without needing to review each component individually.

GrapeQL is designed using a modular architecture that separates transport, detection, analysis, and reporting responsibilities. This approach promotes extensibility, maintainability, and predictable execution behavior.

---

## Architectural Philosophy

GrapeQL follows a layered design where specialized modules collaborate through shared infrastructure. Each module performs a focused role while relying on common services such as logging, test case loading, and response baseline tracking.

Key architectural goals include:

- **Modularity** — Components can evolve independently  
- **Extensibility** — New security tests can be added without modifying core logic  
- **Observability** — Structured logging supports traceability  
- **Reliability** — Statistical baselines reduce false positives  
- **Clarity** — Predictable execution order simplifies analysis  

---

## Module Categories

To simplify system understanding, modules can be grouped by functional responsibility.

---

### Core Transport Layer

**GraphQL Client**

The GraphQL Client acts as the communication gateway between GrapeQL and the target endpoint. It manages HTTP interactions, authentication, proxy support, and telemetry capture.

All scanning activity flows through this component.

---

### Security Testing Modules

These modules actively evaluate the security posture of the target GraphQL API.

**Fingerprinter**  
Identifies the underlying GraphQL engine to provide environmental context for subsequent tests.

**InfoTester**  
Detects information disclosure risks such as introspection exposure, verbose error messaging, and developer tooling availability.

**InjectionTester**  
Performs dynamic payload testing to uncover SQL injection, command injection, and blind exploitation vectors.

**AuthTester**  
Evaluates authentication and authorization controls to identify bypass opportunities and access control weaknesses.

**DosTester**  
Assesses service resilience by executing query complexity attacks and comparing latency against a statistical baseline.

---

### Analytical Components

**BaselineTracker**  
Aggregates response timing data to establish performance norms, enabling anomaly-based detection during stress testing.

**AI Agent**  
Transforms vulnerability findings into structured risk insights, executive summaries, and remediation guidance.

---

### Execution Support Infrastructure

**TestCaseLoader**  
Discovers and parses YAML-defined security tests, enabling rapid expansion of scanning capabilities without altering application code.

**GrapeLogger**  
Captures structured telemetry across modules, supporting auditability, diagnostics, and operational transparency.

---

### Output Layer

**Reporter**  
Consolidates findings from all modules and generates structured reports in Markdown or JSON formats suitable for technical and executive audiences.

---

## Module Interaction Model

GrapeQL modules collaborate through shared infrastructure rather than direct coupling. This promotes loose dependencies and improves maintainability.

Typical interaction pattern:

1. The GraphQL Client establishes communication with the target.
2. Test cases are loaded and distributed to scanning modules.
3. Security modules execute tests and generate findings.
4. Response timings feed into the BaselineTracker.
5. The AI Agent optionally analyzes aggregated results.
6. The Reporter produces the final output.

This coordinated workflow ensures consistent scan behavior while allowing modules to remain independently extensible.

---

## Execution Order

Modules execute in a deterministic sequence to maximize testing accuracy:

1. Fingerprinter  
2. InfoTester  
3. InjectionTester  
4. AuthTester  
5. DosTester  
6. AI Agent (optional)  
7. Reporter  

Early modules establish environmental awareness and baseline metrics, enabling later modules to perform more intelligent analysis.

---

## Extensibility Model

GrapeQL is designed to support continuous evolution. Developers can enhance platform capabilities by:

- Adding YAML-based test definitions  
- Expanding detection techniques  
- Introducing new scanning modules  
- Enhancing statistical models  
- Integrating additional analysis providers  

This architecture allows the scanner to adapt alongside emerging GraphQL attack techniques.

---

## Navigating the Documentation

For deeper technical detail, refer to the individual module documentation located in:

```
/docs/modules
```

Recommended reading order:

1. GraphQL Client  
2. Security Testing Modules  
3. BaselineTracker  
4. Reporter  
5. Supporting Infrastructure  

Following this sequence provides a natural progression from transport to detection to analysis.

---

## Summary

The GrapeQL architecture emphasizes modular design, shared infrastructure, and intelligent analysis to deliver a flexible and scalable GraphQL security testing platform.

By organizing functionality into clearly defined modules, the system remains easy to extend, simple to reason about, and well-suited for modern security workflows.
