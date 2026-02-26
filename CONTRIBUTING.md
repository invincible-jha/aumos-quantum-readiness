# Contributing to aumos-quantum-readiness

## Development Setup

```bash
git clone <repo-url>
cd aumos-quantum-readiness
pip install -e ".[dev]"
cp .env.example .env
# Edit .env with your local values
```

## Running Tests

```bash
make test          # Full test suite with coverage
make test-quick    # Fast run, stop on first failure
```

## Code Quality

```bash
make lint          # Check linting and formatting
make format        # Auto-fix linting and formatting
make typecheck     # Run mypy strict type checking
make all           # lint + typecheck + test
```

## Architecture

This service follows AumOS hexagonal architecture:

- `api/` — FastAPI routes (thin layer, delegates to services)
- `core/` — Business logic services and ORM models (no framework dependencies)
- `adapters/` — SQLAlchemy repositories, Kafka publishers, PQC engine adapter

## PQC Algorithm Support

Currently supports NIST-standardized algorithms:
- **KEM**: ML-KEM-512/768/1024 (CRYSTALS-Kyber)
- **Signatures**: ML-DSA-44/65/87 (CRYSTALS-Dilithium), SLH-DSA (SPHINCS+)

The `PQCEngine` adapter in `adapters/pqc_engine.py` is stubbed for liboqs-python
integration. Implement the TODO blocks with your chosen PQC library.

## Pull Request Guidelines

- Feature branches: `feature/`, fix branches: `fix/`
- Conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`
- All PRs must pass `make all` before merge
- Add tests for new service methods
