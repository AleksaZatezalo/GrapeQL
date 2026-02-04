# GrapeQL Security Assessment Report

## Target: http://localhost:5013/graphql
## Date: 2026-02-03 21:01:22

## Executive Summary

GrapeQL conducted a security assessment of the GraphQL API at http://localhost:5013/graphql. This report details the findings and recommendations.

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 2 |
| LOW | 0 |
| INFO | 0 |

Total: 2 findings

## Detailed Findings

### 1. Unauth Access: unauth_introspection

**Severity:** MEDIUM

**Endpoint:** http://localhost:5013/graphql

**Description:** Introspection query with no authentication. Query returned data without authentication. Evidence: {"data": {"__schema": {"types": [{"name": "Query"}, {"name": "PasteObject"}, {"name": "ID"}, {"name": "String"}, {"name": "Boolean"}, {"name": "Int"}, {"name": "OwnerObject"}, {"name": "UserObject"}, {"name": "SearchResult"}, {"name": "AuditObject"}, {"name": "DateTime"}, {"name": "Mutations"}, {"name": "CreatePaste"}, {"name": "EditPaste"}, {"name": "DeletePaste"}, {"name": "UploadPaste"}, {"name": "ImportPaste"}, {"name": "CreateUser"}, {"name": "UserInput"}, {"name": "Login"}, {"name": "Subsc

---

### 2. Unauth Access: unauth_typename

**Severity:** MEDIUM

**Endpoint:** http://localhost:5013/graphql

**Description:** __typename probe with no authentication. Query returned data without authentication. Evidence: {"data": {"__typename": "Query"}}

---

## Remediation Summary

