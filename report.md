# GrapeQL Security Assessment Report

## Target: http://localhost:5013/graphql
## Date: 2026-02-03 20:28:57

## Executive Summary

GrapeQL conducted a security assessment of the GraphQL API at http://localhost:5013/graphql. This report details the findings and recommendations.

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 15 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 0 |
| INFO | 0 |

Total: 15 findings

## Detailed Findings

### 1. SQLi in pastes.filter

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in pastes.filter with payload: " OR ""="

**Impact:** Database access, data extraction, authentication bypass

**Remediation:** Use parameterized queries and ORM sanitization

---

### 2. Command Injection in pastes.filter

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in pastes.filter with payload: {"$ne": null}

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

### 3. Command Injection in paste.title

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in paste.title with payload: {"$ne": null}

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

### 4. Command Injection in systemDiagnostics.username

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in systemDiagnostics.username with payload: {"$ne": "definitely_not_this_value_12345"}

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

### 5. Command Injection in systemDiagnostics.password

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in systemDiagnostics.password with payload: {"$ne": "definitely_not_this_value_12345"}

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

### 6. Command Injection in systemDiagnostics.cmd

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in systemDiagnostics.cmd with payload: uname -a

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

### 7. Command Injection in systemDebug.arg

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in systemDebug.arg with payload: {"$ne": null}

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

### 8. Command Injection in search.keyword

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in search.keyword with payload: {"$ne": null}

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

### 9. Command Injection in me.token

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in me.token with payload: {"$ne": null}

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

### 10. Command Injection in createPaste.content

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in createPaste.content with payload: {"$ne": null}

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

### 11. Command Injection in createPaste.title

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in createPaste.title with payload: {"$ne": null}

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

### 12. Command Injection in editPaste.content

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in editPaste.content with payload: {"$ne": null}

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

### 13. Command Injection in editPaste.title

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in editPaste.title with payload: {"$ne": null}

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

### 14. Command Injection in login.password

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in login.password with payload: {"$ne": null}

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

### 15. Command Injection in login.username

**Severity:** CRITICAL

**Endpoint:** http://localhost:5013/graphql

**Description:** Possible injection in login.username with payload: {"$ne": null}

**Impact:** Arbitrary command execution on the server

**Remediation:** Never pass user input to shell commands

---

## Remediation Summary

### Use parameterized queries and ORM sanitization

Applies to:

- SQLi in pastes.filter

### Never pass user input to shell commands

Applies to:

- Command Injection in pastes.filter
- Command Injection in paste.title
- Command Injection in systemDiagnostics.username
- Command Injection in systemDiagnostics.password
- Command Injection in systemDiagnostics.cmd
- Command Injection in systemDebug.arg
- Command Injection in search.keyword
- Command Injection in me.token
- Command Injection in createPaste.content
- Command Injection in createPaste.title
- Command Injection in editPaste.content
- Command Injection in editPaste.title
- Command Injection in login.password
- Command Injection in login.username

