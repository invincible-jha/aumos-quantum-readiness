# aumos-quantum-readiness

Post-quantum cryptography migration, crypto-agility framework, harvest-now-decrypt-later defense, and NIST PQC compliance for AumOS Enterprise.

## Overview

This service provides enterprise-grade tooling for the quantum security transition:

- **PQC Migration** — Orchestrate migration from classical to quantum-safe algorithms (CRYSTALS-Kyber, CRYSTALS-Dilithium)
- **Crypto-Agility** — Assess and score cryptographic agility, generate phased migration plans
- **Harvest Defense** — Identify and quantify harvest-now-decrypt-later exposure risk
- **Quantum-Safe Key Exchange** — Manage ML-KEM (Kyber) key encapsulation operations
- **NIST PQC Compliance** — Evaluate posture against FIPS-203, FIPS-204, FIPS-205

## Quick Start

```bash
pip install -e ".[dev]"
cp .env.example .env
uvicorn aumos_quantum_readiness.main:app --reload
```

API docs: `http://localhost:8000/docs`

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/quantum/pqc/migrate` | Start PQC migration |
| GET | `/api/v1/quantum/pqc/status` | Migration status |
| POST | `/api/v1/quantum/agility/assess` | Crypto-agility assessment |
| GET | `/api/v1/quantum/agility/plan` | Migration plan |
| POST | `/api/v1/quantum/harvest/assess` | Harvest risk assessment |
| GET | `/api/v1/quantum/harvest/risks` | Identified risks |
| POST | `/api/v1/quantum/keys/exchange` | Quantum-safe key exchange |
| GET | `/api/v1/quantum/compliance` | NIST PQC compliance status |
| POST | `/api/v1/quantum/compliance/check` | Run compliance check |

## Architecture

Hexagonal architecture following AumOS conventions:

```
api/          FastAPI routes (thin, delegates to services)
core/         Business logic, ORM models, interfaces
adapters/     Repositories, Kafka publisher, PQC engine adapter
```

## Supported Algorithms

**Key Encapsulation (KEM):**
- ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS-203 / CRYSTALS-Kyber)

**Digital Signatures:**
- ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS-204 / CRYSTALS-Dilithium)
- SLH-DSA-SHA2-128s/192s/256s (FIPS-205 / SPHINCS+)
- FALCON-512, FALCON-1024

## Database Tables

| Table | Purpose |
|-------|---------|
| `qrd_migrations` | PQC migration tracking |
| `qrd_agility_assessments` | Crypto-agility assessment results |
| `qrd_harvest_risks` | Harvest-now-decrypt-later risk records |
| `qrd_key_exchanges` | Quantum-safe key exchange records |
| `qrd_compliance_checks` | NIST PQC compliance check results |

## Environment Variables

See `.env.example` for all required variables. Repo-specific variables use the `AUMOS_QUANTUM_` prefix.

## License

Apache-2.0 — see [LICENSE](LICENSE).
