"""Abstract interfaces (Protocol classes) for aumos-quantum-readiness.

Defining interfaces as Protocol classes enables:
  - Dependency injection in services
  - Easy mocking in tests
  - Clear contracts between layers

Services depend on interfaces, not concrete implementations.
"""

import uuid
from typing import Protocol, runtime_checkable

from aumos_common.auth import TenantContext

from aumos_quantum_readiness.core.models import (
    AgilityAssessment,
    ComplianceCheck,
    HarvestRisk,
    KeyExchange,
    PQCMigration,
)


@runtime_checkable
class IPQCMigrationRepository(Protocol):
    """Repository interface for PQCMigration records."""

    async def get_by_id(
        self, migration_id: uuid.UUID, tenant: TenantContext
    ) -> PQCMigration | None: ...

    async def list_all(self, tenant: TenantContext) -> list[PQCMigration]: ...

    async def create(
        self,
        algorithm_from: str,
        algorithm_to: str,
        asset_type: str,
        asset_identifier: str,
        initiated_by: uuid.UUID,
        migration_metadata: dict,
        tenant: TenantContext,
    ) -> PQCMigration: ...

    async def update_status(
        self,
        migration_id: uuid.UUID,
        status: str,
        tenant: TenantContext,
        error_message: str | None = None,
    ) -> PQCMigration: ...


@runtime_checkable
class IAgilityAssessmentRepository(Protocol):
    """Repository interface for AgilityAssessment records."""

    async def get_by_id(
        self, assessment_id: uuid.UUID, tenant: TenantContext
    ) -> AgilityAssessment | None: ...

    async def list_all(self, tenant: TenantContext) -> list[AgilityAssessment]: ...

    async def create(
        self,
        scope: str,
        agility_score: float,
        quantum_vulnerable_count: int,
        quantum_safe_count: int,
        hybrid_count: int,
        findings: dict,
        recommendations: list,
        migration_plan: dict,
        assessed_by: uuid.UUID,
        tenant: TenantContext,
    ) -> AgilityAssessment: ...


@runtime_checkable
class IHarvestRiskRepository(Protocol):
    """Repository interface for HarvestRisk records."""

    async def get_by_id(
        self, risk_id: uuid.UUID, tenant: TenantContext
    ) -> HarvestRisk | None: ...

    async def list_all(self, tenant: TenantContext) -> list[HarvestRisk]: ...

    async def list_by_risk_level(
        self, risk_level: str, tenant: TenantContext
    ) -> list[HarvestRisk]: ...

    async def create(
        self,
        asset_type: str,
        asset_identifier: str,
        risk_level: str,
        risk_score: float,
        data_sensitivity: str,
        encryption_algorithm: str,
        estimated_exposure_years: int,
        quantum_threat_timeline_years: int,
        risk_details: dict,
        assessed_by: uuid.UUID,
        tenant: TenantContext,
    ) -> HarvestRisk: ...


@runtime_checkable
class IKeyExchangeRepository(Protocol):
    """Repository interface for KeyExchange records."""

    async def get_by_id(
        self, exchange_id: uuid.UUID, tenant: TenantContext
    ) -> KeyExchange | None: ...

    async def list_all(self, tenant: TenantContext) -> list[KeyExchange]: ...

    async def create(
        self,
        exchange_algorithm: str,
        key_encapsulation_mechanism: str,
        security_level: int,
        public_key_fingerprint: str,
        ciphertext_size_bytes: int,
        shared_secret_size_bytes: int,
        is_hybrid: bool,
        initiated_by: uuid.UUID,
        exchange_metadata: dict,
        tenant: TenantContext,
        hybrid_classical_algorithm: str | None = None,
    ) -> KeyExchange: ...


@runtime_checkable
class IComplianceCheckRepository(Protocol):
    """Repository interface for ComplianceCheck records."""

    async def get_by_id(
        self, check_id: uuid.UUID, tenant: TenantContext
    ) -> ComplianceCheck | None: ...

    async def get_latest(self, tenant: TenantContext) -> ComplianceCheck | None: ...

    async def list_all(self, tenant: TenantContext) -> list[ComplianceCheck]: ...

    async def create(
        self,
        standard: str,
        standard_version: str,
        overall_status: str,
        compliance_score: float,
        controls_passed: int,
        controls_failed: int,
        controls_not_applicable: int,
        findings: list,
        remediation_plan: dict,
        checked_by: uuid.UUID,
        tenant: TenantContext,
    ) -> ComplianceCheck: ...


__all__ = [
    "IPQCMigrationRepository",
    "IAgilityAssessmentRepository",
    "IHarvestRiskRepository",
    "IKeyExchangeRepository",
    "IComplianceCheckRepository",
]
