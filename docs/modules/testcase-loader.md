# TestCaseLoader

## Purpose
The TestCaseLoader is responsible for discovering, parsing, and supplying YAML-defined test cases to scanning modules. Its objective is to enable flexible and extensible security testing without requiring modifications to the core scanning engine.

## Responsibilities
- Discover test case files within configured directories  
- Parse YAML definitions into executable structures  
- Support selective test execution via include filters  
- Provide standardized test data to scanning modules  
- Enable rapid expansion of testing coverage  

## How It Works
The TestCaseLoader scans predefined directories for YAML files that contain security test definitions. Once located, these files are parsed and converted into structured objects that scanning modules can consume during execution.

The loader supports filtering mechanisms that allow operators to restrict scans to specific test cases. This is particularly useful for targeted assessments or specialized testing scenarios.

By separating test logic from application code, the loader promotes a modular architecture where new security checks can be introduced without altering the scanner itself.

## Inputs
- Path to the test cases directory  
- YAML test definitions  
- Optional include filters  
- Logger instance (when enabled)  

## Outputs
- Parsed test case objects  
- Filtered test datasets  
- Structured inputs for scanning modules  

## Dependencies
The TestCaseLoader operates alongside:

- **Scanning Modules** — consume loaded test cases  
- **GrapeLogger** — records parsing activity when enabled  

## Execution Flow
1. Identify configured test case directories  
2. Discover YAML files within each module scope  
3. Parse file contents into structured definitions  
4. Apply include filters if specified  
5. Validate test case structure  
6. Provide datasets to requesting modules  

## Failure Handling
The loader is designed to maintain scan stability:

- Invalid YAML files are skipped with diagnostic logging  
- Parsing errors do not interrupt overall execution  
- Missing directories generate clear warnings  
- Partial datasets remain usable  

These safeguards ensure that individual test definition issues do not compromise the scan lifecycle.

## Extension Points
Developers can enhance loader capabilities by:

- Supporting additional file formats  
- Introducing schema validation  
- Enabling remote test case repositories  
- Implementing version control for test definitions  
- Adding caching for performance optimization  

This flexibility allows the scanner to evolve alongside emerging security techniques.
