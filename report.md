# GrapeQL Security Assessment Report

## Target: http://localhost:5013/graphql
## Date: 2026-02-04 17:18:53

## Executive Summary

GrapeQL conducted a security assessment of the GraphQL API at http://localhost:5013/graphql. This report details the findings and recommendations.

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 15 |
| HIGH | 0 |
| MEDIUM | 4 |
| LOW | 2 |
| INFO | 1 |

Total: 22 findings

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

### 16. URL-encoded POST Queries Enabled (Possible CSRF)

**Severity:** MEDIUM

**Endpoint:** http://localhost:5013/graphql

**Description:** The GraphQL server accepts queries via URL-encoded form data, which may enable cross-site request forgery (CSRF) attacks

**Impact:** Attackers may be able to execute operations using the victim's credentials

**Remediation:** Only accept application/json content type for GraphQL operations

---

### 17. Introspection Enabled

**Severity:** MEDIUM

**Endpoint:** http://localhost:5013/graphql

**Description:** The GraphQL server has introspection enabled, which exposes detailed schema information

**Impact:** Attackers can map the entire GraphQL schema and discover available operations

**Remediation:** Disable introspection in production environments or implement authorization controls

---

### 18. Unauth Access: unauth_introspection

**Severity:** MEDIUM

**Endpoint:** http://localhost:5013/graphql

**Description:** Introspection query with no authentication. Query returned data without authentication. Evidence: {"data": {"__schema": {"types": [{"name": "Query"}, {"name": "PasteObject"}, {"name": "ID"}, {"name": "String"}, {"name": "Boolean"}, {"name": "Int"}, {"name": "OwnerObject"}, {"name": "UserObject"}, {"name": "SearchResult"}, {"name": "AuditObject"}, {"name": "DateTime"}, {"name": "Mutations"}, {"name": "CreatePaste"}, {"name": "EditPaste"}, {"name": "DeletePaste"}, {"name": "UploadPaste"}, {"name": "ImportPaste"}, {"name": "CreateUser"}, {"name": "UserInput"}, {"name": "Login"}, {"name": "Subsc

---

### 19. Unauth Access: unauth_typename

**Severity:** MEDIUM

**Endpoint:** http://localhost:5013/graphql

**Description:** __typename probe with no authentication. Query returned data without authentication. Evidence: {"data": {"__typename": "Query"}}

---

### 20. Field Suggestions Enabled

**Severity:** LOW

**Endpoint:** http://localhost:5013/graphql

**Description:** The GraphQL server is providing field suggestions in error messages, which can help attackers discover schema information

**Impact:** Information Leakage - Schema details are being disclosed

**Remediation:** Disable field suggestions in production environments

---

### 21. Query Batching Enabled

**Severity:** LOW

**Endpoint:** http://localhost:5013/graphql

**Description:** The GraphQL server supports query batching, which can be used to amplify attacks

**Impact:** Attackers can send multiple operations in a single request, potentially bypassing rate limits

**Remediation:** Implement per-operation rate limiting and set maximum batch size limits

---

### 22. GraphQL Engine Identified: Graphene

**Severity:** INFO

**Endpoint:** http://localhost:5013/graphql

**Description:** The GraphQL engine was identified as Graphene.

**Impact:** None - informational only

**Remediation:** None required

---

## Remediation Summary

### None required

Applies to:

- GraphQL Engine Identified: Graphene

### Disable field suggestions in production environments

Applies to:

- Field Suggestions Enabled

### Only accept application/json content type for GraphQL operations

Applies to:

- URL-encoded POST Queries Enabled (Possible CSRF)

### Disable introspection in production environments or implement authorization controls

Applies to:

- Introspection Enabled

### Implement per-operation rate limiting and set maximum batch size limits

Applies to:

- Query Batching Enabled

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


---

## AI Analysis

### Executive Summary
The target presents a severe security risk with multiple critical vulnerabilities that could lead to complete system compromise. The API suffers from widespread command injection vulnerabilities across nearly all input parameters, combined with a SQL injection flaw and exposed introspection capabilities. These vulnerabilities collectively enable attackers to execute arbitrary commands on the server, extract sensitive data, and bypass authentication mechanisms.

### Risk Analysis

The most critical concern is the extensive command injection vulnerability surface affecting 14 different parameters across queries, mutations, and system diagnostic functions. The `systemDiagnostics` and `systemDebug` operations are particularly dangerous as they appear designed for administrative purposes and accept direct command input. An attacker could chain these command injection vulnerabilities with the SQL injection in `pastes.filter` to first extract database credentials or user information, then escalate to full system access through command execution.

The SQL injection vulnerability in the `pastes.filter` parameter compounds the risk by potentially exposing authentication credentials, user data, or application secrets that could facilitate lateral movement. The presence of URL-encoded POST support creates additional attack vectors for CSRF-based exploitation, allowing attackers to execute these severe vulnerabilities through victim browsers.

The combination of enabled introspection and field suggestions provides attackers with complete schema visibility, making it trivial to identify and exploit the injection vulnerabilities. The lack of authentication requirements for basic schema queries suggests weak access controls throughout the application.

### Recommended Next Steps

1. **Immediate Command Injection Testing**: Manually verify the `systemDiagnostics.cmd` parameter with payloads like `"whoami"`, `"id"`, or `"cat /etc/passwd"` to confirm arbitrary command execution capabilities.

2. **SQL Injection Exploitation**: Test the `pastes.filter` parameter with union-based payloads such as `" UNION SELECT username,password FROM users--"` to extract authentication data.

3. **Authentication Bypass Testing**: Attempt to access the `systemDiagnostics` and `systemDebug` operations without authentication to determine if administrative functions are exposed to unauthenticated users.

4. **Privilege Escalation Assessment**: Use confirmed command injection to enumerate system users, running services, and network configuration with commands like `"ps aux"`, `"netstat -tulpn"`, and `"find / -perm -4000 2>/dev/null"`.

5. **Data Exfiltration Testing**: Leverage the SQL injection to map database structure and extract sensitive application data beyond user credentials.

### Gaps in Coverage

The automated scan may have missed business logic flaws in paste sharing mechanisms, potential file upload vulnerabilities in the `uploadPaste` and `importPaste` mutations, and subscription-based denial of service attacks. Role-based access control weaknesses between different user types should be manually tested, particularly around paste ownership and administrative functions. Additionally, the scan likely did not assess query complexity limits or nested query attacks that could cause resource exhaustion.
