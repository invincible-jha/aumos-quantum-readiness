# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Report security vulnerabilities to security@aumos.ai.

Do NOT open public GitHub issues for security vulnerabilities.

**Response SLA:** 48 hours for acknowledgment, 7 days for initial assessment.

## Security Considerations for This Service

This service handles cryptographic operations and PQC migration workflows.
Key security considerations:

1. **No private key storage** — This service records key exchange metadata only.
   Private keys must never be logged, stored, or transmitted via API responses.

2. **PQC algorithm validation** — Only NIST-standardized algorithms are accepted.
   Attempts to use non-approved algorithms are rejected at the service boundary.

3. **Tenant isolation** — All records are RLS-isolated per tenant. Cross-tenant
   data access requires explicit `get_db_session_no_tenant` with documented justification.

4. **Harvest risk data** — Risk assessments may contain sensitive asset information.
   Ensure proper access controls on all `/quantum/harvest/` endpoints.

5. **liboqs integration** — When integrating the PQC engine with liboqs-python,
   ensure the library version is pinned and audited for side-channel vulnerabilities.
