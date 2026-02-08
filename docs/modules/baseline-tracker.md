# BaselineTracker

## Purpose
The BaselineTracker establishes a statistical performance reference for the target GraphQL endpoint. Its objective is to differentiate normal response behavior from anomalies that may indicate performance degradation or denial-of-service risk.

## Responsibilities
- Collect response timing data across scanning modules  
- Compute statistical performance metrics  
- Establish dynamic response-time thresholds  
- Support anomaly detection for stress-based testing  
- Improve the accuracy of DoS vulnerability identification  

## How It Works
As scanning modules execute, they forward response timing measurements to the BaselineTracker. The tracker aggregates this data to calculate statistical indicators such as mean latency and variance.

These metrics form a behavioral baseline representing normal service conditions. Later, the DoS testing module compares stress-test latency against this baseline to determine whether deviations are statistically significant rather than incidental.

By relying on observed performance rather than arbitrary thresholds, the BaselineTracker reduces false positives and improves detection reliability.

## Inputs
- Response timing data from scanning modules  
- Execution metadata  
- Logger telemetry (optional)  

## Outputs
- Calculated latency baseline  
- Statistical deviation thresholds  
- Performance insights supporting DoS analysis  

## Dependencies
The BaselineTracker operates alongside:

- **Scanning Modules** — supply response timing data  
- **DosTester** — consumes baseline thresholds  
- **GrapeLogger** — records telemetry when enabled  

## Execution Flow
1. Receive response timing metrics from active modules  
2. Aggregate measurements in a thread-safe manner  
3. Compute statistical indicators (e.g., mean latency)  
4. Establish acceptable performance thresholds  
5. Provide baseline data to the DoS testing module  

## Failure Handling
The tracker is designed for resilient operation:

- Limited datasets produce conservative thresholds  
- Irregular timing spikes are absorbed into statistical calculations  
- Data collection failures do not interrupt scan execution  

These safeguards ensure baseline generation remains reliable under varying scan conditions.

## Extension Points
Developers can enhance baseline analysis by:

- Introducing advanced statistical models  
- Supporting percentile-based thresholds  
- Tracking endpoint-specific baselines  
- Incorporating adaptive learning techniques  
- Visualizing performance trends  

This extensibility enables increasingly intelligent performance analysis as the platform evolves.
