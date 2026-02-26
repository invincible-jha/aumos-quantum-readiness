# CLAUDE.md — AumOS Quantum Readiness

## Project Overview

AumOS Enterprise is a composable enterprise AI platform. This repo (`aumos-quantum-readiness`) is part of **Tier C: Innovation Extensions**:
Post-quantum cryptography migration, crypto-agility framework, harvest-now-decrypt-later defense, and NIST PQC compliance.

**Release Tier:** C: Proprietary
**Product Mapping:** Security & Compliance Extensions
**Phase:** 5 (Months 18-24)

## Repo Purpose

Provides enterprise tooling for the quantum security transition: orchestrating migration from classical to post-quantum cryptographic algorithms (CRYSTALS-Kyber/ML-KEM, CRYSTALS-Dilithium/ML-DSA), assessing crypto-agility posture, quantifying harvest-now-decrypt-later exposure risk, and evaluating compliance against NIST PQC standards (FIPS-203, FIPS-204, FIPS-205).

## Architecture Position

```
aumos-platform-core → aumos-auth-gateway → THIS REPO
aumos-secrets-vault ←────────────────────── THIS REPO (key exchange events)
aumos-governance-engine ←──────────────── THIS REPO (compliance findings)
aumos-security-runtime ←───────────────── THIS REPO (PQC migration events)
```

**Upstream dependencies (this repo IMPORTS from):**
- `aumos-common` — auth, database, events, errors, config, health, pagination
- `aumos-proto` — Protobuf message definitions for Kafka events

**Downstream dependents (other repos IMPORT from this):**
- `aumos-secrets-vault` — consumes key exchange completion events
- `aumos-governance-engine` — consumes compliance check findings
- `aumos-security-runtime` — consumes PQC migration events for security posture tracking

## Tech Stack (DO NOT DEVIATE)

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.11+ | Runtime |
| FastAPI | 0.110+ | REST API framework |
| SQLAlchemy | 2.0+ (async) | Database ORM |
| asyncpg | 0.29+ | PostgreSQL async driver |
| Pydantic | 2.6+ | Data validation, settings, API schemas |
| confluent-kafka | 2.3+ | Kafka producer/consumer |
| structlog | 24.1+ | Structured JSON logging |
| OpenTelemetry | 1.23+ | Distributed tracing |
| pytest | 8.0+ | Testing framework |
| ruff | 0.3+ | Linting and formatting |
| mypy | 1.8+ | Type checking |
| liboqs-python | 0.10+ | Open Quantum Safe PQC library (integrate in pqc_engine.py) |

## Coding Standards

### ABSOLUTE RULES (violations will break integration with other repos)

1. **Import aumos-common, never reimplement.** If aumos-common provides it, use it.
2. **Type hints on EVERY function.** No exceptions.
3. **Pydantic models for ALL API inputs/outputs.** Never return raw dicts.
4. **RLS tenant isolation via aumos-common.** Never write raw SQL that bypasses RLS.
5. **Structured logging via structlog.** Never use print() or logging.getLogger().
6. **Publish domain events to Kafka after state changes.**
7. **Async by default.** All I/O operations must be async.
8. **Google-style docstrings** on all public classes and functions.

### Repo-Specific Rules

- **Never log private key material.** The PQC engine handles key bytes — log only fingerprints and sizes.
- **Only NIST-standardized PQC algorithms** are accepted in the service layer. Validate against `SUPPORTED_KEMS` and `SUPPORTED_SIGNATURES` frozensets in `PQCEngine`.
- **Harvest risk scores** use a [0.0, 1.0] scale. Risk level thresholds are defined in `HarvestDefenseService.RISK_SCORE_THRESHOLDS` — do not hardcode in routes.
- **Compliance checks** map to NIST controls. Do not add proprietary controls without updating `ComplianceCheckService.NIST_PQC_CONTROLS`.
- **PQCEngine** in `adapters/pqc_engine.py` is a stub. All TODO blocks must be implemented with liboqs-python before production deployment. Never replace with a homebrew crypto implementation.

## API Conventions

- All endpoints under `/api/v1/quantum/` prefix
- Auth: Bearer JWT token (validated by aumos-common)
- Tenant: `X-Tenant-ID` header (set by auth middleware)
- Errors: Standard `ErrorResponse` from aumos-common
- Content-Type: `application/json` (always)

## Database Conventions

- Table prefix: `qrd_` (e.g., `qrd_migrations`, `qrd_compliance_checks`)
- ALL tenant-scoped tables: extend `AumOSModel`
- RLS policy on every tenant table (created in migration)

## Kafka Events Published

| Event | Topic | Trigger |
|-------|-------|---------|
| PQCMigrationStarted | quantum.migration.started | Migration created |
| PQCMigrationCompleted | quantum.migration.completed | Migration marked complete |
| CryptoAgilityAssessed | quantum.agility.assessed | Assessment created |
| HarvestRiskIdentified | quantum.harvest.risk_identified | Critical/high risk found |
| QuantumKeyExchangeCompleted | quantum.keys.exchange_completed | Key exchange created |
| NISTComplianceChecked | quantum.compliance.checked | Compliance check run |

## What Claude Code Should NOT Do

1. **Do NOT store or log private key bytes.** Only fingerprints and sizes are safe to persist.
2. **Do NOT implement PQC algorithms from scratch.** Use the `PQCEngine` adapter with liboqs-python.
3. **Do NOT accept non-NIST-approved algorithms** without explicit validation.
4. **Do NOT bypass harvest risk scoring logic** — the formula in `_calculate_risk_score` is intentional.
5. **Do NOT reimplement anything in aumos-common.**
6. **Do NOT return raw dicts from API endpoints.** Use Pydantic models.
7. **Do NOT skip type hints.** Every function signature must be typed.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUMOS_QUANTUM_PQC_KYBER_KEY_SIZE` | 1024 | Kyber key size (512, 768, 1024) |
| `AUMOS_QUANTUM_PQC_DILITHIUM_SECURITY_LEVEL` | 3 | Dilithium security level (2, 3, 5) |
| `AUMOS_QUANTUM_PQC_HYBRID_MODE_ENABLED` | true | Enable hybrid classical+PQC mode |
| `AUMOS_QUANTUM_HARVEST_RISK_THRESHOLD` | 0.75 | Minimum score to trigger Kafka alert |
| `AUMOS_QUANTUM_HARVEST_SCAN_INTERVAL_HOURS` | 24 | Hours between automated harvest scans |
| `AUMOS_QUANTUM_NIST_PQC_STANDARD_VERSION` | FIPS-203 | Default compliance standard version |
| `AUMOS_QUANTUM_COMPLIANCE_CHECK_TIMEOUT_SECONDS` | 30 | Max seconds for a compliance check |
