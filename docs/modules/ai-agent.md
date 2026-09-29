# AI Agent

## Purpose
The AI Agent enhances GrapeQL’s analytical capabilities by transforming raw vulnerability findings into structured security insights. Its objective is to help security teams quickly understand risk posture, prioritize remediation efforts, and identify potential attack paths.

## Responsibilities
- Analyze aggregated scan findings  
- Generate executive-level security summaries  
- Provide contextual risk assessments  
- Recommend prioritized remediation steps  
- Identify potential gaps in testing coverage  
- Improve interpretability of scan results  

## How It Works
After all scanning modules complete execution, the AI Agent receives a structured dataset containing vulnerability findings (and the schema, when available). It processes this data using a local **Qwen** model served over an OpenAI-compatible API (default: [Ollama](https://ollama.com)) to produce a human-readable analysis. No API keys are required for a local server.

The generated output typically includes a high-level security overview, schema analysis, detailed risk commentary, and recommended next actions. This allows organizations to move from detection to decision-making faster.

The AI Agent operates as a post-processing component and does not interfere with the scanning lifecycle.

## Inputs
- Consolidated findings from the Reporter pipeline  
- Target endpoint context  
- GraphQL schema (when available)  
- Qwen connection config (`QWEN_BASE_URL` / `QWEN_MODEL`, optional `QWEN_API_KEY`)  

## Outputs
- Executive security summary  
- Schema analysis and risk narratives  
- Recommended remediation actions  
- Coverage gap insights  

These outputs are surfaced in the console summary (CLI) and the web UI.

## Dependencies
The AI Agent interacts with:

- **Reporter** — supplies aggregated findings  
- **`grapeql.qwen`** — shared OpenAI-compatible client for the Qwen model  

It operates independently of the scanning infrastructure.

## Execution Flow
1. Receive structured vulnerability findings and schema  
2. Submit them to the configured Qwen model via `grapeql.qwen`  
3. Process the returned analysis  
4. Structure the output into defined sections  
5. Hand the analysis back to the Reporter for the summary  

## Failure Handling
Because the AI Agent is optional, it is designed with safe fallback behavior:

- An unreachable endpoint or model errors do not interrupt the scan  
- On any failure the agent returns nothing and the summary prints without AI  
- Network errors and endpoint errors are reported clearly  

Scanning functionality remains fully operational without AI support.

## Extension Points
Developers can expand AI capabilities by:

- Supporting additional AI providers  
- Customizing prompt strategies  
- Introducing organization-specific risk models  
- Automating remediation suggestions  
- Enabling multilingual reporting  

This flexibility allows the AI Agent to evolve alongside advances in security-focused artificial intelligence.
