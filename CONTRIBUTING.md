# Contributing to GrapeQL

Thank you for your interest in contributing to GrapeQL! This document provides guidelines and information for contributors.

## Development Philosophy

GrapeQL follows a modular, top-down architectural design where each component has a clear responsibility and well-defined interfaces. When contributing, please maintain this architectural approach and ensure your changes fit within the existing module structure.

## Getting Started

### Prerequisites

- Python 3.8+
- Git
- Basic understanding of GraphQL and security testing concepts

### Setting Up the Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/GrapeQL.git
   cd GrapeQL
   ```
3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. Install the package in development mode:
   ```bash
   pip install -e .
   pip install -r requirements-dev.txt  # If it exists
   ```

### Running Tests

```bash
# Run all tests
python -m pytest

# Run tests with coverage
python -m pytest --cov=grapeql

# Run specific test file
python -m pytest tests/test_fingerprinter.py
```

## Architecture Overview

GrapeQL is built with the following modular components:

- **GraphQLClient**: Core HTTP client for GraphQL endpoint communication
- **Fingerprinter**: Engine identification module
- **InfoTester**: Information disclosure vulnerability testing
- **InjectionTester**: Command injection vulnerability testing  
- **DosTester**: Denial of Service vulnerability testing
- **Reporter**: Report generation and output formatting

## Contribution Guidelines

### Code Style

- Follow Black style guidelines
- Use type hints for all function parameters and return values
- Write docstrings for all classes and public methods
- Keep line length under 88 characters (Black formatter compatible)

### Commit Messages

Use conventional commit format:
- `feat:` new features
- `fix:` bug fixes
- `docs:` documentation changes
- `test:` adding/updating tests
- `refactor:` code refactoring
- `perf:` performance improvements

Example: `feat: add OAuth 2.0 authentication support to GraphQLClient`

### Pull Request Process

**Note:** All Pull Requests must be attached to a specific issue. 

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Make your changes following the coding standards
3. Add tests for new functionality
4. Update documentation if needed
5. Ensure all tests pass
6. Create a pull request with:
   - Clear title and description
   - Reference any related issues
   - Include screenshots/examples if applicable

### Adding New Security Tests

When adding new vulnerability tests:

1. Create a new tester class inheriting from appropriate base classes
2. Follow the existing pattern of `setup_endpoint()` and `run_test()` methods
3. Ensure findings are properly formatted for the Reporter
4. Add comprehensive test coverage
5. Update the CLI interface if the test should be exposed there

### Testing Guidelines

- Write unit tests for all new functionality
- Use pytest fixtures for common test setup
- Mock external HTTP requests using `responses` or similar
- Include both positive and negative test cases
- Test error handling and edge cases

### Documentation

- Update README.md for user-facing changes
- Add docstrings following Google or NumPy style
- Include code examples in docstrings where helpful
- Update CLI help text for new options

### Bug Reports

Please include:
- GrapeQL version
- Python version and OS
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Error messages or logs
- Minimal code example if applicable

### Feature Requests

Feature requests should include:
- Clear description of the feature
- Use case and motivation
- Proposed API or interface
- Compatibility considerations

## Development Tips

### Testing Against Live GraphQL Endpoints

Be cautious when testing against live endpoints:
- Always get permission before testing
- Use the `--proxy` option with tools like Burp Suite for analysis
- Be aware that DoS tests can impact target performance
- Consider setting up local test environments

### Module Development Pattern

When adding new modules, follow this pattern:

```python
class NewTester:
    def __init__(self):
        self.client = None
        self.findings = []
    
    async def setup_endpoint(self, endpoint: str, **kwargs) -> bool:
        """Setup and validate the endpoint connection."""
        # Implementation
        
    async def run_test(self) -> None:
        """Execute the security tests."""
        # Implementation
        
    def get_findings(self) -> List[Dict]:
        """Return structured findings for reporting."""
        return self.findings
```

## Code of Conduct

Please note that this project follows a Code of Conduct. By participating in this project, you agree to abide by its terms.

## Questions?

Feel free to open a discussion on GitHub or reach out to the maintainers if you have questions about contributing.

## License

By contributing to GrapeQL, you agree that your contributions will be licensed under the same license as the project.