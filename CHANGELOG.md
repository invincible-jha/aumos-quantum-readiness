# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of aumos-quantum-readiness
- `PQCMigrationService` — orchestrates CRYSTALS-Kyber and CRYSTALS-Dilithium migrations
- `CryptoAgilityService` — assesses crypto-agility and generates migration plans
- `HarvestDefenseService` — evaluates harvest-now-decrypt-later risk
- `KeyExchangeService` — manages quantum-safe key exchange operations (ML-KEM)
- `ComplianceCheckService` — evaluates NIST PQC compliance (FIPS-203/204/205)
- REST API endpoints under `/api/v1/quantum/`
- ORM models: `qrd_migrations`, `qrd_agility_assessments`, `qrd_harvest_risks`, `qrd_key_exchanges`, `qrd_compliance_checks`
- `PQCEngine` adapter stub for liboqs-python integration
- `QuantumReadinessEventPublisher` for Kafka domain events
- Hexagonal architecture with full interface/protocol separation
- Standard AumOS deliverables: Dockerfile, CI/CD workflow, docker-compose.dev.yml
