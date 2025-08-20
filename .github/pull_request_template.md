## Pull Request Description

### Summary
<!-- Provide a clear and concise description of what this PR accomplishes -->

### Type of Change
<!-- Check all that apply -->
- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🔧 Refactoring (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] 🧪 Test coverage improvement

### Components Modified
<!-- Check all GrapeQL components that were modified -->
- [ ] `GraphQLClient` (HTTP handling, headers, cookies, proxy)
- [ ] `Fingerprinter` (GraphQL engine identification)
- [ ] `InfoTester` (Information disclosure testing)
- [ ] `InjectionTester` (Command/SQL injection testing)
- [ ] `DosTester` (Denial of Service testing)
- [ ] `Reporter` (Report generation and summaries)
- [ ] CLI interface (`__main__.py`)
- [ ] Core library architecture
- [ ] Documentation/README
- [ ] Tests
- [ ] Other: _____________

### Testing Strategy
<!-- Describe how you tested your changes -->

#### Manual Testing
- [ ] Tested against live GraphQL endpoints
- [ ] Verified CLI functionality with various options
- [ ] Tested library integration examples
- [ ] Validated report generation (Markdown/JSON)

#### Automated Testing
- [ ] Added/updated unit tests
- [ ] All existing tests pass
- [ ] Integration tests pass
- [ ] Security tests validate expected behavior

#### Test Endpoints
<!-- List any GraphQL endpoints or test scenarios used -->
- Endpoint 1: `https://example.com/graphql` - Description
- Endpoint 2: `https://test.api/graphql` - Description

### Security Considerations
<!-- Critical for a security testing tool -->
- [ ] Changes do not introduce new security vulnerabilities
- [ ] Testing methodology follows responsible disclosure practices
- [ ] No hardcoded credentials or sensitive information
- [ ] Rate limiting and DoS testing are appropriately controlled
- [ ] Error handling prevents information leakage

### Breaking Changes
<!-- If this is a breaking change, describe the impact and migration path -->
- [ ] This PR introduces no breaking changes
- [ ] **Breaking change details:**
  - What breaks: _______________
  - Migration required: _______________
  - Version impact: _______________

### Related Issues
<!-- Link to related issues -->
Closes #___
Relates to #___

### Code Quality Checklist
- [ ] Code follows the project's architectural patterns
- [ ] Async/await patterns are used consistently
- [ ] Error handling is comprehensive
- [ ] Code is modular and follows single responsibility principle
- [ ] Documentation strings are added/updated for new functions
- [ ] Type hints are included where appropriate

### Performance Impact
- [ ] No performance impact
- [ ] Performance improvement (describe): _______________
- [ ] Potential performance impact (justify): _______________

### Documentation
- [ ] README updated if needed
- [ ] Code examples updated/added
- [ ] CLI usage documentation updated
- [ ] Library integration examples updated

### Additional Notes
<!-- Any additional information, concerns, or context for reviewers -->

---

### For Maintainers
<!-- This section is for maintainer use -->
- [ ] Version bump required
- [ ] Changelog entry needed
- [ ] Security advisory needed
- [ ] Example configurations updated