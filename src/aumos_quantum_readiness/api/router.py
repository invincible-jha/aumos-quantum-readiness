"""API router for aumos-quantum-readiness.

All endpoints are registered here and included in main.py under /api/v1.
Routes delegate all logic to service layer — no business logic in routes.
"""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.auth import TenantContext, get_current_user
from aumos_common.database import get_db_session

from aumos_quantum_readiness.adapters.kafka import QuantumReadinessEventPublisher
from aumos_quantum_readiness.adapters.repositories import (
    AgilityAssessmentRepository,
    ComplianceCheckRepository,
    HarvestRiskRepository,
    KeyExchangeRepository,
    PQCMigrationRepository,
)
from aumos_quantum_readiness.api.schemas import (
    AgilityAssessmentRequest,
    AgilityAssessmentResponse,
    ComplianceCheckRequest,
    ComplianceCheckResponse,
    HarvestAssessmentRequest,
    HarvestRiskResponse,
    KeyExchangeRequest,
    KeyExchangeResponse,
    MigrationPlanResponse,
    PQCMigrationRequest,
    PQCMigrationResponse,
)
from aumos_quantum_readiness.core.services import (
    ComplianceCheckService,
    CryptoAgilityService,
    HarvestDefenseService,
    KeyExchangeService,
    PQCMigrationService,
)

router = APIRouter(tags=["quantum-readiness"])


def _get_publisher() -> QuantumReadinessEventPublisher:
    """Create a QuantumReadinessEventPublisher instance.

    Returns:
        Configured event publisher.
    """
    return QuantumReadinessEventPublisher(publisher=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# PQC Migration endpoints
# ---------------------------------------------------------------------------


@router.post("/quantum/pqc/migrate", response_model=PQCMigrationResponse, status_code=201)
async def start_pqc_migration(
    request: PQCMigrationRequest,
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> PQCMigrationResponse:
    """Start a post-quantum cryptography migration for a cryptographic asset.

    Args:
        request: PQC migration parameters.
        tenant: Authenticated tenant context.
        session: Database session.

    Returns:
        The newly created PQC migration record.
    """
    repository = PQCMigrationRepository(session)
    publisher = _get_publisher()
    service = PQCMigrationService(repository=repository, publisher=publisher)

    migration = await service.start_migration(
        algorithm_from=request.algorithm_from,
        algorithm_to=request.algorithm_to,
        asset_type=request.asset_type,
        asset_identifier=request.asset_identifier,
        initiated_by=tenant.user_id,
        migration_metadata=request.migration_metadata,
        tenant=tenant,
    )

    return PQCMigrationResponse.model_validate(migration)


@router.get("/quantum/pqc/status", response_model=list[PQCMigrationResponse])
async def get_pqc_migration_status(
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> list[PQCMigrationResponse]:
    """Get all PQC migration statuses for the current tenant.

    Args:
        tenant: Authenticated tenant context.
        session: Database session.

    Returns:
        List of PQC migration records.
    """
    repository = PQCMigrationRepository(session)
    publisher = _get_publisher()
    service = PQCMigrationService(repository=repository, publisher=publisher)

    migrations = await service.list_migrations(tenant=tenant)
    return [PQCMigrationResponse.model_validate(m) for m in migrations]


# ---------------------------------------------------------------------------
# Crypto-agility endpoints
# ---------------------------------------------------------------------------


@router.post("/quantum/agility/assess", response_model=AgilityAssessmentResponse, status_code=201)
async def assess_crypto_agility(
    request: AgilityAssessmentRequest,
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> AgilityAssessmentResponse:
    """Run a crypto-agility assessment on the provided cryptographic inventory.

    Args:
        request: Agility assessment parameters including asset inventory.
        tenant: Authenticated tenant context.
        session: Database session.

    Returns:
        The newly created agility assessment with score and recommendations.
    """
    repository = AgilityAssessmentRepository(session)
    publisher = _get_publisher()
    service = CryptoAgilityService(repository=repository, publisher=publisher)

    inventory_dicts = [asset.model_dump() for asset in request.crypto_inventory]

    assessment = await service.assess_agility(
        scope=request.scope,
        crypto_inventory=inventory_dicts,
        assessed_by=tenant.user_id,
        tenant=tenant,
    )

    return AgilityAssessmentResponse.model_validate(assessment)


@router.get("/quantum/agility/plan", response_model=list[MigrationPlanResponse])
async def get_migration_plan(
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> list[MigrationPlanResponse]:
    """Get migration plans from all agility assessments for the current tenant.

    Args:
        tenant: Authenticated tenant context.
        session: Database session.

    Returns:
        List of migration plans from agility assessments.
    """
    repository = AgilityAssessmentRepository(session)
    assessments = await repository.list_all(tenant)

    return [
        MigrationPlanResponse(
            assessment_id=assessment.id,
            scope=assessment.scope,
            agility_score=assessment.agility_score,
            migration_plan=assessment.migration_plan,
            recommendations=assessment.recommendations,
            created_at=assessment.created_at,
        )
        for assessment in assessments
    ]


# ---------------------------------------------------------------------------
# Harvest defense endpoints
# ---------------------------------------------------------------------------


@router.post("/quantum/harvest/assess", response_model=HarvestRiskResponse, status_code=201)
async def assess_harvest_risk(
    request: HarvestAssessmentRequest,
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> HarvestRiskResponse:
    """Assess harvest-now-decrypt-later risk for a data asset.

    Args:
        request: Harvest risk assessment parameters.
        tenant: Authenticated tenant context.
        session: Database session.

    Returns:
        The newly created harvest risk record with risk score and level.
    """
    repository = HarvestRiskRepository(session)
    publisher = _get_publisher()
    service = HarvestDefenseService(repository=repository, publisher=publisher)

    risk = await service.assess_harvest_risk(
        asset_type=request.asset_type,
        asset_identifier=request.asset_identifier,
        data_sensitivity=request.data_sensitivity,
        encryption_algorithm=request.encryption_algorithm,
        estimated_exposure_years=request.estimated_exposure_years,
        assessed_by=tenant.user_id,
        tenant=tenant,
        quantum_threat_timeline_years=request.quantum_threat_timeline_years,
        risk_details=request.risk_details,
    )

    return HarvestRiskResponse.model_validate(risk)


@router.get("/quantum/harvest/risks", response_model=list[HarvestRiskResponse])
async def list_harvest_risks(
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> list[HarvestRiskResponse]:
    """List all harvest-now-decrypt-later risks for the current tenant.

    Args:
        tenant: Authenticated tenant context.
        session: Database session.

    Returns:
        List of harvest risk records.
    """
    repository = HarvestRiskRepository(session)
    publisher = _get_publisher()
    service = HarvestDefenseService(repository=repository, publisher=publisher)

    risks = await service.list_harvest_risks(tenant=tenant)
    return [HarvestRiskResponse.model_validate(r) for r in risks]


# ---------------------------------------------------------------------------
# Key exchange endpoints
# ---------------------------------------------------------------------------


@router.post("/quantum/keys/exchange", response_model=KeyExchangeResponse, status_code=201)
async def initiate_key_exchange(
    request: KeyExchangeRequest,
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> KeyExchangeResponse:
    """Initiate a quantum-safe key exchange operation.

    Args:
        request: Key exchange parameters.
        tenant: Authenticated tenant context.
        session: Database session.

    Returns:
        The newly created key exchange record.
    """
    repository = KeyExchangeRepository(session)
    publisher = _get_publisher()
    service = KeyExchangeService(repository=repository, publisher=publisher)

    exchange = await service.initiate_key_exchange(
        exchange_algorithm=request.exchange_algorithm,
        key_encapsulation_mechanism=request.key_encapsulation_mechanism,
        security_level=request.security_level,
        public_key_fingerprint=request.public_key_fingerprint,
        initiated_by=tenant.user_id,
        tenant=tenant,
        is_hybrid=request.is_hybrid,
        hybrid_classical_algorithm=request.hybrid_classical_algorithm,
        exchange_metadata=request.exchange_metadata,
        expires_at=request.expires_at,
    )

    return KeyExchangeResponse.model_validate(exchange)


# ---------------------------------------------------------------------------
# Compliance endpoints
# ---------------------------------------------------------------------------


@router.get("/quantum/compliance", response_model=ComplianceCheckResponse | None)
async def get_compliance_status(
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ComplianceCheckResponse | None:
    """Get the latest NIST PQC compliance status for the current tenant.

    Args:
        tenant: Authenticated tenant context.
        session: Database session.

    Returns:
        The most recent compliance check, or None if no checks have been run.
    """
    repository = ComplianceCheckRepository(session)
    publisher = _get_publisher()
    service = ComplianceCheckService(repository=repository, publisher=publisher)

    check = await service.get_compliance_status(tenant=tenant)
    if check is None:
        return None
    return ComplianceCheckResponse.model_validate(check)


@router.post("/quantum/compliance/check", response_model=ComplianceCheckResponse, status_code=201)
async def run_compliance_check(
    request: ComplianceCheckRequest,
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ComplianceCheckResponse:
    """Run a NIST PQC compliance check against the current cryptographic posture.

    Args:
        request: Compliance check parameters.
        tenant: Authenticated tenant context.
        session: Database session.

    Returns:
        The newly created compliance check with findings and remediation plan.
    """
    repository = ComplianceCheckRepository(session)
    publisher = _get_publisher()
    service = ComplianceCheckService(repository=repository, publisher=publisher)

    inventory_dicts = [asset.model_dump() for asset in request.algorithm_inventory]

    check = await service.run_compliance_check(
        standard=request.standard,
        standard_version=request.standard_version,
        algorithm_inventory=inventory_dicts,
        checked_by=tenant.user_id,
        tenant=tenant,
    )

    return ComplianceCheckResponse.model_validate(check)
