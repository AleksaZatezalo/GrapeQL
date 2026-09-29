# Findings Collector

## Purpose
The Reporter module consolidates findings generated across all testing modules
into a single, deduplicated set and prints a console summary. Its objective is
to turn raw scan data into clear, actionable intelligence. As of v3.0, file-based
report generation has been removed — findings are surfaced through the console
summary (CLI) and the web UI.

## Responsibilities
- Aggregate findings from all modules
- Deduplicate findings (by title + endpoint)
- Attach severity classifications and counts
- Incorporate AI-generated analysis when available
- Print a consistent, coloured console summary

## How It Works
After all testing modules complete execution, the Reporter collects their
findings, deduplicates them, and organizes them by severity.

Each finding carries metadata such as vulnerability type, severity, description,
impact, and remediation. When AI-assisted analysis is enabled, the module also
holds the AI summary for inclusion in the console output.

## Inputs
- Findings from scanning modules
- Target endpoint metadata
- Optional AI-generated summary

## Outputs
- Deduplicated, severity-sorted findings (consumed by the CLI summary and the
  web API)
- Severity counts
- A coloured console summary

## Dependencies
- **Testing Modules** — supply vulnerability findings
- **AI Agent** — provides an optional post-scan analysis summary

## Execution Flow
1. Collect findings from all completed modules
2. Deduplicate into a standard structure
3. Assign severity indicators and counts
4. Hold AI analysis when configured
5. Print the console summary (or return data to the web API)

## Failure Handling
- Missing findings produce a valid "no vulnerabilities found" summary
- AI service failures do not prevent the summary from printing
- Partial data is preserved whenever possible

## Extension Points
- Consuming the aggregated findings from the web API for custom exports
- Integrating with ticketing or SIEM platforms downstream
- Adjusting severity ordering or summary formatting
