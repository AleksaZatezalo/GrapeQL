# GrapeQL Security Assessment Report

## Target: http://localhost:5013/graphql
## Date: 2026-02-08 17:23:38

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

The target GraphQL API presents a critical security posture with numerous severe vulnerabilities that enable immediate compromise. Multiple fields across queries and mutations are vulnerable to command injection attacks, while administrative debugging endpoints are exposed without proper authentication controls. The combination of enabled introspection, weak injection protections, and dangerous system-level operations creates an extremely high-risk environment requiring urgent remediation.

### Schema Analysis

The schema reveals several concerning security anti-patterns that indicate a lack of security-first design. The most alarming discovery is the presence of multiple system administration fields that accept direct user input without apparent sanitization. The `systemDiagnostics` query accepts `username`, `password`, and `cmd` parameters, essentially providing a direct command execution interface. Similarly, `systemDebug` accepts an `arg` parameter that appears to be passed to system-level operations.

The `UserObject` type exposes a non-null `password` field, indicating that password hashes (or worse, plaintext passwords) may be returned in query responses. The `PasteObject` contains sensitive metadata fields like `ipAddr` and `userAgent` that could facilitate user tracking and profiling. The presence of `deleteAllPastes` as a query operation (rather than a mutation) violates GraphQL best practices and suggests potential state-changing side effects in read operations.

Authentication mechanisms appear weak, with the `me` query accepting a raw `token` parameter and the `login` mutation returning both access and refresh tokens. The `importPaste` mutation accepts arbitrary host/path combinations, potentially enabling Server-Side Request Forgery (SSRF) attacks. Several mutations like `uploadPaste` and `importPaste` handle file operations that could be vectors for additional attacks.

### Risk Analysis

The command injection vulnerabilities represent an immediate and critical threat, as they appear to affect multiple input fields across both queries and mutations. An attacker could leverage the `systemDiagnostics.cmd` parameter to execute arbitrary commands on the server, potentially achieving full system compromise. The fact that similar injection patterns appear in login fields suggests that even authentication attempts could be weaponized for command execution.

The exposed `systemDiagnostics` and `systemDebug` fields combined with the lack of authentication controls create a perfect storm for privilege escalation. An attacker could use these endpoints to gather system information, modify configurations, or establish persistence mechanisms. The SQL injection vulnerability in `pastes.filter` could be chained with command injection to extract database credentials and escalate access across the entire data layer.

The presence of CSRF-enabling URL-encoded POST acceptance, combined with dangerous mutations like `deletePaste` and `deleteAllPastes`, means that attackers could potentially trick authenticated users into performing destructive actions. The unrestricted introspection access provides attackers with a complete attack surface map, making targeted exploitation significantly easier.

### Recommended Next Steps

1. **Immediately test command injection in systemDiagnostics.cmd** using: `query { systemDiagnostics(cmd: "id; whoami; uname -a") }`
2. **Verify SQL injection in pastes.filter** with: `query { pastes(filter: "' UNION SELECT 1,2,3,4,5,6,7,8--") { id title } }`
3. **Test unauthorized access to sensitive system operations**: `query { systemHealth systemUpdate }`
4. **Attempt privilege escalation via deleteAllPastes**: `query { deleteAllPastes }`
5. **Extract user credentials via password field**: `query { users { id username password } }`
6. **Test SSRF through importPaste mutation**: `mutation { importPaste(scheme: "http", host: "internal-service", path: "/admin", port: 80) { result } }`
7. **Verify token-based authentication bypass**: `query { me(token: "invalid_token") { id username } }`
8. **Test file upload vulnerabilities**: `mutation { uploadPaste(filename: "../../../etc/passwd", content: "malicious") { result } }`

### Suggested Additional Payloads

```yaml
test_cases:
  - name: system_command_chain
    payload: "id && cat /etc/passwd && ps aux"
    indicators:
      - "uid="
      - "root:x:"
      - "bash"
      
  - name: sql_union_user_extract
    payload: "' UNION SELECT id,username,password,NULL,NULL,NULL,NULL,NULL FROM users--"
    indicators:
      - "admin"
      - "hash"
      - "bcrypt"
      
  - name: nosql_injection_bypass
    payload: "{\"$regex\": \".*\"}"
    indicators:
      - "data"
      - "users"
      - "pastes"
      
  - name: system_info_gathering
    payload: "cat /proc/version && env && ls -la /"
    indicators:
      - "Linux version"
      - "PATH="
      - "total"
      
  - name: ssrf_internal_network
    strategy: mutation_test
    mutation: "importPaste"
    args:
      scheme: "http"
      host: "127.0.0.1"
      path: "/admin/config"
      port: 8080
    description: "Tests for SSRF against internal services"
    
  - name: directory_traversal_upload
    payload: "../../../../etc/shadow"
    indicators:
      - "root:"
      - "encrypted"
      - "permission denied"
      
  - name: batch_token_enumeration
    strategy: header_bypass
    headers:
      Authorization: "Bearer aaaaaaaaaaaaaaaa"
    description: "Tests for weak token validation patterns"
    
  - name: audit_log_injection
    payload: "\"; DROP TABLE audits; --"
    indicators:
      - "syntax error"
      - "table"
      - "permission"
```

### Gaps in Coverage

The automated scan may have missed several critical attack vectors specific to this pastebin application. Business logic flaws around paste ownership validation, read-and-burn functionality bypass, and audit log manipulation should be tested manually. The subscription endpoint could be vulnerable to denial-of-service through resource exhaustion or unauthorized data streaming. Field-level authorization between different user roles appears absent from the schema, suggesting horizontal privilege escalation opportunities. Rate limiting effectiveness against batch operations and nested query depth limits should be validated through manual testing. Additionally, the custom DateTime scalar type and UserInput object may contain unmarked injection points that require targeted payload crafting.
