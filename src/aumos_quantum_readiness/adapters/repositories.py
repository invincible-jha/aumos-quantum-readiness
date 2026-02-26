"""SQLAlchemy repository implementations for aumos-quantum-readiness.

Repositories extend BaseRepository from aumos-common which provides:
  - Automatic RLS tenant isolation (set_tenant_context)
  - Standard CRUD operations (get, list, create, update, delete)
  - Pagination support via paginate()
  - Soft delete support

Only the methods that differ from BaseRepository defaults are implemented here.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.auth import TenantContext
from aumos_common.database import BaseRepository

from aumos_quantum_readiness.core.interfaces import (
    IAgilityAssessmentRepository,
    IComplianceCheckRepository,
    IHarvestRiskRepository,
    IKeyExchangeRepository,
    IPQCMigrationRepository,
)
from aumos_quantum_readiness.core.models import (
    AgilityAssessment,
    ComplianceCheck,
    HarvestRisk,
    KeyExchange,
    PQCMigration,
)


class PQCMigrationRepository(BaseRepository, IPQCMigrationRepository):
    """Repository for PQCMigration records.

    Args:
        session: The async SQLAlchemy session (injected by FastAPI dependency).
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def get_by_id(
        self, migration_id: uuid.UUID, tenant: TenantContext
    ) -> PQCMigration | None:
        """Retrieve a PQC migration by ID within tenant scope.

        Args:
            migration_id: The UUID of the migration.
            tenant: Tenant context for RLS isolation.

        Returns:
            The PQCMigration record or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(PQCMigration).where(PQCMigration.id == migration_id)
        )
        return result.scalar_one_or_none()

    async def list_all(self, tenant: TenantContext) -> list[PQCMigration]:
        """List all PQC migrations for a tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of PQCMigration records.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(PQCMigration).order_by(PQCMigration.created_at.desc())
        )
        return list(result.scalars().all())

    async def create(
        self,
        algorithm_from: str,
        algorithm_to: str,
        asset_type: str,
        asset_identifier: str,
        initiated_by: uuid.UUID,
        migration_metadata: dict,
        tenant: TenantContext,
    ) -> PQCMigration:
        """Create a new PQC migration record.

        Args:
            algorithm_from: Current algorithm being migrated from.
            algorithm_to: Target PQC algorithm.
            asset_type: Type of cryptographic asset.
            asset_identifier: Unique asset identifier.
            initiated_by: UUID of the initiating user.
            migration_metadata: Additional migration context.
            tenant: Tenant context for RLS isolation.

        Returns:
            The newly created PQCMigration record.
        """
        await self.set_tenant_context(tenant)
        migration = PQCMigration(
            tenant_id=tenant.tenant_id,
            algorithm_from=algorithm_from,
            algorithm_to=algorithm_to,
            status="pending",
            asset_type=asset_type,
            asset_identifier=asset_identifier,
            migration_metadata=migration_metadata,
            initiated_by=initiated_by,
            started_at=datetime.now(tz=timezone.utc),
        )
        self.session.add(migration)
        await self.session.flush()
        await self.session.refresh(migration)
        return migration

    async def update_status(
        self,
        migration_id: uuid.UUID,
        status: str,
        tenant: TenantContext,
        error_message: str | None = None,
    ) -> PQCMigration:
        """Update the status of a PQC migration.

        Args:
            migration_id: UUID of the migration to update.
            status: New status value.
            tenant: Tenant context for RLS isolation.
            error_message: Optional error message if migration failed.

        Returns:
            The updated PQCMigration record.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(PQCMigration).where(PQCMigration.id == migration_id)
        )
        migration = result.scalar_one()
        migration.status = status
        if error_message is not None:
            migration.error_message = error_message
        if status == "completed":
            migration.completed_at = datetime.now(tz=timezone.utc)
        await self.session.flush()
        await self.session.refresh(migration)
        return migration


class AgilityAssessmentRepository(BaseRepository, IAgilityAssessmentRepository):
    """Repository for AgilityAssessment records.

    Args:
        session: The async SQLAlchemy session (injected by FastAPI dependency).
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def get_by_id(
        self, assessment_id: uuid.UUID, tenant: TenantContext
    ) -> AgilityAssessment | None:
        """Retrieve an agility assessment by ID within tenant scope.

        Args:
            assessment_id: The UUID of the assessment.
            tenant: Tenant context for RLS isolation.

        Returns:
            The AgilityAssessment record or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(AgilityAssessment).where(AgilityAssessment.id == assessment_id)
        )
        return result.scalar_one_or_none()

    async def list_all(self, tenant: TenantContext) -> list[AgilityAssessment]:
        """List all agility assessments for a tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of AgilityAssessment records.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(AgilityAssessment).order_by(AgilityAssessment.created_at.desc())
        )
        return list(result.scalars().all())

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
    ) -> AgilityAssessment:
        """Create a new agility assessment record.

        Args:
            scope: Assessment scope.
            agility_score: Computed agility score.
            quantum_vulnerable_count: Number of vulnerable assets.
            quantum_safe_count: Number of safe assets.
            hybrid_count: Number of hybrid assets.
            findings: Detailed findings dict.
            recommendations: List of recommendations.
            migration_plan: Structured migration plan.
            assessed_by: UUID of the assessing user.
            tenant: Tenant context for RLS isolation.

        Returns:
            The newly created AgilityAssessment record.
        """
        await self.set_tenant_context(tenant)
        assessment = AgilityAssessment(
            tenant_id=tenant.tenant_id,
            scope=scope,
            agility_score=agility_score,
            quantum_vulnerable_count=quantum_vulnerable_count,
            quantum_safe_count=quantum_safe_count,
            hybrid_count=hybrid_count,
            findings=findings,
            recommendations={"items": recommendations},
            migration_plan=migration_plan,
            assessed_by=assessed_by,
        )
        self.session.add(assessment)
        await self.session.flush()
        await self.session.refresh(assessment)
        return assessment


class HarvestRiskRepository(BaseRepository, IHarvestRiskRepository):
    """Repository for HarvestRisk records.

    Args:
        session: The async SQLAlchemy session (injected by FastAPI dependency).
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def get_by_id(
        self, risk_id: uuid.UUID, tenant: TenantContext
    ) -> HarvestRisk | None:
        """Retrieve a harvest risk by ID within tenant scope.

        Args:
            risk_id: The UUID of the harvest risk.
            tenant: Tenant context for RLS isolation.

        Returns:
            The HarvestRisk record or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(HarvestRisk).where(HarvestRisk.id == risk_id)
        )
        return result.scalar_one_or_none()

    async def list_all(self, tenant: TenantContext) -> list[HarvestRisk]:
        """List all harvest risks for a tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of HarvestRisk records.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(HarvestRisk).order_by(HarvestRisk.risk_score.desc())
        )
        return list(result.scalars().all())

    async def list_by_risk_level(
        self, risk_level: str, tenant: TenantContext
    ) -> list[HarvestRisk]:
        """List harvest risks filtered by risk level.

        Args:
            risk_level: Risk level to filter by.
            tenant: Tenant context for RLS isolation.

        Returns:
            Filtered list of HarvestRisk records.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(HarvestRisk)
            .where(HarvestRisk.risk_level == risk_level)
            .order_by(HarvestRisk.risk_score.desc())
        )
        return list(result.scalars().all())

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
    ) -> HarvestRisk:
        """Create a new harvest risk record.

        Args:
            asset_type: Type of data asset.
            asset_identifier: Unique asset identifier.
            risk_level: Classified risk level.
            risk_score: Numeric risk score.
            data_sensitivity: Data sensitivity level.
            encryption_algorithm: Current encryption algorithm.
            estimated_exposure_years: Duration of data exposure.
            quantum_threat_timeline_years: Years until quantum threat.
            risk_details: Additional risk context.
            assessed_by: UUID of the assessing user.
            tenant: Tenant context for RLS isolation.

        Returns:
            The newly created HarvestRisk record.
        """
        await self.set_tenant_context(tenant)
        risk = HarvestRisk(
            tenant_id=tenant.tenant_id,
            asset_type=asset_type,
            asset_identifier=asset_identifier,
            risk_level=risk_level,
            risk_score=risk_score,
            data_sensitivity=data_sensitivity,
            encryption_algorithm=encryption_algorithm,
            estimated_exposure_years=estimated_exposure_years,
            quantum_threat_timeline_years=quantum_threat_timeline_years,
            risk_details=risk_details,
            assessed_by=assessed_by,
        )
        self.session.add(risk)
        await self.session.flush()
        await self.session.refresh(risk)
        return risk


class KeyExchangeRepository(BaseRepository, IKeyExchangeRepository):
    """Repository for KeyExchange records.

    Args:
        session: The async SQLAlchemy session (injected by FastAPI dependency).
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def get_by_id(
        self, exchange_id: uuid.UUID, tenant: TenantContext
    ) -> KeyExchange | None:
        """Retrieve a key exchange by ID within tenant scope.

        Args:
            exchange_id: The UUID of the key exchange.
            tenant: Tenant context for RLS isolation.

        Returns:
            The KeyExchange record or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(KeyExchange).where(KeyExchange.id == exchange_id)
        )
        return result.scalar_one_or_none()

    async def list_all(self, tenant: TenantContext) -> list[KeyExchange]:
        """List all key exchanges for a tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of KeyExchange records.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(KeyExchange).order_by(KeyExchange.created_at.desc())
        )
        return list(result.scalars().all())

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
        expires_at: datetime | None = None,
    ) -> KeyExchange:
        """Create a new key exchange record.

        Args:
            exchange_algorithm: Key exchange algorithm.
            key_encapsulation_mechanism: KEM variant.
            security_level: NIST security level.
            public_key_fingerprint: Fingerprint of the recipient's public key.
            ciphertext_size_bytes: KEM ciphertext size.
            shared_secret_size_bytes: Shared secret size.
            is_hybrid: Whether hybrid mode is used.
            initiated_by: UUID of the initiating user.
            exchange_metadata: Additional context.
            tenant: Tenant context for RLS isolation.
            hybrid_classical_algorithm: Classical algorithm for hybrid mode.
            expires_at: Optional expiry timestamp.

        Returns:
            The newly created KeyExchange record.
        """
        await self.set_tenant_context(tenant)
        exchange = KeyExchange(
            tenant_id=tenant.tenant_id,
            exchange_algorithm=exchange_algorithm,
            key_encapsulation_mechanism=key_encapsulation_mechanism,
            security_level=security_level,
            public_key_fingerprint=public_key_fingerprint,
            ciphertext_size_bytes=ciphertext_size_bytes,
            shared_secret_size_bytes=shared_secret_size_bytes,
            is_hybrid=is_hybrid,
            hybrid_classical_algorithm=hybrid_classical_algorithm,
            exchange_metadata=exchange_metadata,
            expires_at=expires_at,
            initiated_by=initiated_by,
        )
        self.session.add(exchange)
        await self.session.flush()
        await self.session.refresh(exchange)
        return exchange


class ComplianceCheckRepository(BaseRepository, IComplianceCheckRepository):
    """Repository for ComplianceCheck records.

    Args:
        session: The async SQLAlchemy session (injected by FastAPI dependency).
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def get_by_id(
        self, check_id: uuid.UUID, tenant: TenantContext
    ) -> ComplianceCheck | None:
        """Retrieve a compliance check by ID within tenant scope.

        Args:
            check_id: The UUID of the compliance check.
            tenant: Tenant context for RLS isolation.

        Returns:
            The ComplianceCheck record or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(ComplianceCheck).where(ComplianceCheck.id == check_id)
        )
        return result.scalar_one_or_none()

    async def get_latest(self, tenant: TenantContext) -> ComplianceCheck | None:
        """Retrieve the most recent compliance check for a tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            The most recent ComplianceCheck or None.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(ComplianceCheck).order_by(ComplianceCheck.created_at.desc()).limit(1)
        )
        return result.scalar_one_or_none()

    async def list_all(self, tenant: TenantContext) -> list[ComplianceCheck]:
        """List all compliance checks for a tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of ComplianceCheck records.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(ComplianceCheck).order_by(ComplianceCheck.created_at.desc())
        )
        return list(result.scalars().all())

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
    ) -> ComplianceCheck:
        """Create a new compliance check record.

        Args:
            standard: Compliance standard checked.
            standard_version: Standard version.
            overall_status: Compliance status.
            compliance_score: Numeric compliance score.
            controls_passed: Number of passed controls.
            controls_failed: Number of failed controls.
            controls_not_applicable: Number of N/A controls.
            findings: List of compliance findings.
            remediation_plan: Structured remediation plan.
            checked_by: UUID of the checking user.
            tenant: Tenant context for RLS isolation.

        Returns:
            The newly created ComplianceCheck record.
        """
        await self.set_tenant_context(tenant)
        check = ComplianceCheck(
            tenant_id=tenant.tenant_id,
            standard=standard,
            standard_version=standard_version,
            overall_status=overall_status,
            compliance_score=compliance_score,
            controls_passed=controls_passed,
            controls_failed=controls_failed,
            controls_not_applicable=controls_not_applicable,
            findings=findings,
            remediation_plan=remediation_plan,
            checked_by=checked_by,
        )
        self.session.add(check)
        await self.session.flush()
        await self.session.refresh(check)
        return check
