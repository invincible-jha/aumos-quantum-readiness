"""Business logic services for aumos-quantum-readiness.

Services contain all domain logic. They:
  - Accept dependencies via constructor injection (repositories, publishers)
  - Orchestrate repository calls and event publishing
  - Raise domain errors using aumos_common.errors
  - Are framework-agnostic (no FastAPI, no direct DB access)

After any state-changing operation, publish a Kafka event via EventPublisher.

Eight services are defined:
  Repository-backed (persist to DB + publish Kafka events):
    - PQCMigrationService
    - CryptoAgilityService
    - HarvestDefenseService
    - KeyExchangeService
    - ComplianceCheckService

  Adapter-orchestration (call cryptographic adapters + persist results):
    - QuantumKeyOperationsService   — KyberAdapter + DilithiumAdapter operations
    - HybridTLSService              — HybridKeyExchange adapter coordination
    - QuantumAuditService           — VulnerabilityScanner + ComplianceVerifier + MigrationPlanner
"""

import uuid
from datetime import datetime

from aumos_common.auth import TenantContext
from aumos_common.errors import NotFoundError
from aumos_common.observability import get_logger

from aumos_quantum_readiness.adapters.kafka import QuantumReadinessEventPublisher
from aumos_quantum_readiness.core.interfaces import (
    IAgilityAssessmentRepository,
    IComplianceCheckRepository,
    ICryptoAgility,
    IDilithiumAdapter,
    IHarvestDefenseEngine,
    IHarvestRiskRepository,
    IHybridKeyExchange,
    IKeyExchangeRepository,
    IKyberAdapter,
    IPQCMigrationRepository,
    IQuantumComplianceVerifier,
    IQuantumMigrationPlanner,
    IQuantumVulnerabilityScanner,
)
from aumos_quantum_readiness.core.models import (
    AgilityAssessment,
    ComplianceCheck,
    HarvestRisk,
    KeyExchange,
    PQCMigration,
)

logger = get_logger(__name__)


class PQCMigrationService:
    """Orchestrates post-quantum cryptography migration workflows.

    Args:
        repository: Data access layer for PQC migration records.
        publisher: Domain event publisher for Kafka events.
    """

    # Supported PQC algorithms per NIST standards
    SUPPORTED_PQC_ALGORITHMS: frozenset[str] = frozenset(
        {
            "CRYSTALS-Kyber-512",
            "CRYSTALS-Kyber-768",
            "CRYSTALS-Kyber-1024",
            "CRYSTALS-Dilithium2",
            "CRYSTALS-Dilithium3",
            "CRYSTALS-Dilithium5",
            "FALCON-512",
            "FALCON-1024",
            "SPHINCS+-SHA2-128s",
            "SPHINCS+-SHA2-192s",
            "SPHINCS+-SHA2-256s",
        }
    )

    def __init__(
        self,
        repository: IPQCMigrationRepository,
        publisher: QuantumReadinessEventPublisher,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing IPQCMigrationRepository.
            publisher: Event publisher for domain events.
        """
        self._repository = repository
        self._publisher = publisher

    async def start_migration(
        self,
        algorithm_from: str,
        algorithm_to: str,
        asset_type: str,
        asset_identifier: str,
        initiated_by: uuid.UUID,
        migration_metadata: dict,
        tenant: TenantContext,
    ) -> PQCMigration:
        """Start a PQC migration for a cryptographic asset.

        Args:
            algorithm_from: The current (potentially vulnerable) algorithm.
            algorithm_to: The target PQC-safe algorithm.
            asset_type: Type of asset being migrated (e.g., 'api_key', 'tls_cert').
            asset_identifier: Unique identifier for the asset.
            initiated_by: UUID of the user initiating the migration.
            migration_metadata: Additional context for the migration.
            tenant: The tenant context from auth middleware.

        Returns:
            The newly created PQCMigration record.
        """
        logger.info(
            "Starting PQC migration",
            algorithm_from=algorithm_from,
            algorithm_to=algorithm_to,
            asset_type=asset_type,
            tenant_id=str(tenant.tenant_id),
        )

        migration = await self._repository.create(
            algorithm_from=algorithm_from,
            algorithm_to=algorithm_to,
            asset_type=asset_type,
            asset_identifier=asset_identifier,
            initiated_by=initiated_by,
            migration_metadata=migration_metadata,
            tenant=tenant,
        )

        await self._publisher.publish_migration_started(
            tenant_id=tenant.tenant_id,
            migration_id=migration.id,
            algorithm_from=algorithm_from,
            algorithm_to=algorithm_to,
        )

        return migration

    async def get_migration_status(
        self,
        migration_id: uuid.UUID,
        tenant: TenantContext,
    ) -> PQCMigration:
        """Retrieve the current status of a PQC migration.

        Args:
            migration_id: The UUID of the migration to retrieve.
            tenant: The tenant context from auth middleware.

        Returns:
            The PQCMigration record.

        Raises:
            NotFoundError: If the migration does not exist for this tenant.
        """
        migration = await self._repository.get_by_id(migration_id, tenant)
        if migration is None:
            raise NotFoundError(f"Migration {migration_id} not found")
        return migration

    async def list_migrations(self, tenant: TenantContext) -> list[PQCMigration]:
        """List all PQC migrations for a tenant.

        Args:
            tenant: The tenant context from auth middleware.

        Returns:
            List of PQCMigration records for the tenant.
        """
        logger.info("Listing PQC migrations", tenant_id=str(tenant.tenant_id))
        return await self._repository.list_all(tenant)

    async def complete_migration(
        self,
        migration_id: uuid.UUID,
        tenant: TenantContext,
    ) -> PQCMigration:
        """Mark a migration as completed.

        Args:
            migration_id: The UUID of the migration to complete.
            tenant: The tenant context from auth middleware.

        Returns:
            The updated PQCMigration record.

        Raises:
            NotFoundError: If the migration does not exist for this tenant.
        """
        migration = await self._repository.get_by_id(migration_id, tenant)
        if migration is None:
            raise NotFoundError(f"Migration {migration_id} not found")

        updated = await self._repository.update_status(
            migration_id=migration_id,
            status="completed",
            tenant=tenant,
        )

        await self._publisher.publish_migration_completed(
            tenant_id=tenant.tenant_id,
            migration_id=migration_id,
        )

        return updated


class CryptoAgilityService:
    """Assesses and plans crypto-agility for organizations.

    Args:
        repository: Data access layer for agility assessment records.
        publisher: Domain event publisher for Kafka events.
    """

    def __init__(
        self,
        repository: IAgilityAssessmentRepository,
        publisher: QuantumReadinessEventPublisher,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing IAgilityAssessmentRepository.
            publisher: Event publisher for domain events.
        """
        self._repository = repository
        self._publisher = publisher

    async def assess_agility(
        self,
        scope: str,
        crypto_inventory: list[dict],
        assessed_by: uuid.UUID,
        tenant: TenantContext,
    ) -> AgilityAssessment:
        """Perform a crypto-agility assessment on the given inventory.

        Analyzes the current cryptographic inventory against quantum-safe
        standards and produces a migration readiness score.

        Args:
            scope: The scope of the assessment (e.g., 'all_services', 'payment_api').
            crypto_inventory: List of cryptographic assets with their algorithms.
            assessed_by: UUID of the user requesting the assessment.
            tenant: The tenant context from auth middleware.

        Returns:
            The newly created AgilityAssessment record.
        """
        logger.info(
            "Running crypto-agility assessment",
            scope=scope,
            inventory_size=len(crypto_inventory),
            tenant_id=str(tenant.tenant_id),
        )

        vulnerable_algorithms = {"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "DH-2048"}
        hybrid_algorithms = {"X25519Kyber768", "P256Kyber512"}

        quantum_vulnerable_count = 0
        quantum_safe_count = 0
        hybrid_count = 0
        findings: list[dict] = []

        for asset in crypto_inventory:
            algorithm = asset.get("algorithm", "")
            if algorithm in vulnerable_algorithms:
                quantum_vulnerable_count += 1
                findings.append(
                    {
                        "asset": asset.get("identifier", "unknown"),
                        "algorithm": algorithm,
                        "severity": "critical",
                        "reason": "Vulnerable to Shor's algorithm on quantum computers",
                    }
                )
            elif algorithm in hybrid_algorithms:
                hybrid_count += 1
            else:
                quantum_safe_count += 1

        total = max(quantum_vulnerable_count + quantum_safe_count + hybrid_count, 1)
        agility_score = (quantum_safe_count + hybrid_count * 0.5) / total

        recommendations = self._generate_recommendations(
            quantum_vulnerable_count=quantum_vulnerable_count,
            quantum_safe_count=quantum_safe_count,
            hybrid_count=hybrid_count,
            findings=findings,
        )

        migration_plan = self._build_migration_plan(findings=findings)

        assessment = await self._repository.create(
            scope=scope,
            agility_score=agility_score,
            quantum_vulnerable_count=quantum_vulnerable_count,
            quantum_safe_count=quantum_safe_count,
            hybrid_count=hybrid_count,
            findings={"items": findings},
            recommendations=recommendations,
            migration_plan=migration_plan,
            assessed_by=assessed_by,
            tenant=tenant,
        )

        await self._publisher.publish_agility_assessed(
            tenant_id=tenant.tenant_id,
            assessment_id=assessment.id,
            agility_score=agility_score,
        )

        return assessment

    def _generate_recommendations(
        self,
        quantum_vulnerable_count: int,
        quantum_safe_count: int,
        hybrid_count: int,
        findings: list[dict],
    ) -> list[dict]:
        """Generate prioritized remediation recommendations.

        Args:
            quantum_vulnerable_count: Number of quantum-vulnerable assets.
            quantum_safe_count: Number of already-safe assets.
            hybrid_count: Number of hybrid-mode assets.
            findings: List of individual asset findings.

        Returns:
            Prioritized list of recommendation dicts.
        """
        recommendations: list[dict] = []

        if quantum_vulnerable_count > 0:
            recommendations.append(
                {
                    "priority": "critical",
                    "action": "Migrate all RSA/ECDSA asymmetric keys to CRYSTALS-Kyber-1024",
                    "affected_count": quantum_vulnerable_count,
                    "nist_reference": "FIPS-203 (ML-KEM)",
                }
            )
            recommendations.append(
                {
                    "priority": "high",
                    "action": "Replace all digital signatures with CRYSTALS-Dilithium3",
                    "affected_count": quantum_vulnerable_count,
                    "nist_reference": "FIPS-204 (ML-DSA)",
                }
            )

        if hybrid_count > 0:
            recommendations.append(
                {
                    "priority": "medium",
                    "action": "Complete hybrid-mode migrations to pure PQC algorithms",
                    "affected_count": hybrid_count,
                    "nist_reference": "NIST SP 800-227",
                }
            )

        recommendations.append(
            {
                "priority": "low",
                "action": "Implement automated crypto-agility framework for future algorithm transitions",
                "affected_count": quantum_vulnerable_count + hybrid_count + quantum_safe_count,
                "nist_reference": "NIST IR 8547",
            }
        )

        return recommendations

    def _build_migration_plan(self, findings: list[dict]) -> dict:
        """Build a phased migration plan from assessment findings.

        Args:
            findings: List of individual asset findings.

        Returns:
            Structured migration plan with phases and timelines.
        """
        critical_findings = [f for f in findings if f.get("severity") == "critical"]

        return {
            "phases": [
                {
                    "phase": 1,
                    "name": "Inventory and Classification",
                    "duration_weeks": 4,
                    "actions": ["Complete cryptographic asset inventory", "Classify data sensitivity levels"],
                },
                {
                    "phase": 2,
                    "name": "Critical Asset Migration",
                    "duration_weeks": 12,
                    "actions": [
                        f"Migrate {len(critical_findings)} critical assets to PQC algorithms",
                        "Deploy CRYSTALS-Kyber for key encapsulation",
                        "Deploy CRYSTALS-Dilithium for digital signatures",
                    ],
                },
                {
                    "phase": 3,
                    "name": "Full Transition and Validation",
                    "duration_weeks": 8,
                    "actions": [
                        "Complete remaining algorithm migrations",
                        "Run NIST PQC compliance validation",
                        "Establish ongoing crypto-agility monitoring",
                    ],
                },
            ],
            "total_duration_weeks": 24,
            "estimated_assets_affected": len(findings),
        }

    async def get_migration_plan(
        self,
        assessment_id: uuid.UUID,
        tenant: TenantContext,
    ) -> AgilityAssessment:
        """Retrieve the migration plan from a previous assessment.

        Args:
            assessment_id: The UUID of the assessment to retrieve.
            tenant: The tenant context from auth middleware.

        Returns:
            The AgilityAssessment record with its migration plan.

        Raises:
            NotFoundError: If the assessment does not exist for this tenant.
        """
        assessment = await self._repository.get_by_id(assessment_id, tenant)
        if assessment is None:
            raise NotFoundError(f"Assessment {assessment_id} not found")
        return assessment


class HarvestDefenseService:
    """Identifies and mitigates harvest-now-decrypt-later threats.

    This service assesses the risk that adversaries have already harvested
    encrypted data expecting to decrypt it once quantum computers mature.

    Args:
        repository: Data access layer for harvest risk records.
        publisher: Domain event publisher for Kafka events.
    """

    RISK_SCORE_THRESHOLDS: dict[str, float] = {
        "critical": 0.85,
        "high": 0.65,
        "medium": 0.40,
        "low": 0.0,
    }

    def __init__(
        self,
        repository: IHarvestRiskRepository,
        publisher: QuantumReadinessEventPublisher,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing IHarvestRiskRepository.
            publisher: Event publisher for domain events.
        """
        self._repository = repository
        self._publisher = publisher

    async def assess_harvest_risk(
        self,
        asset_type: str,
        asset_identifier: str,
        data_sensitivity: str,
        encryption_algorithm: str,
        estimated_exposure_years: int,
        assessed_by: uuid.UUID,
        tenant: TenantContext,
        quantum_threat_timeline_years: int = 10,
        risk_details: dict | None = None,
    ) -> HarvestRisk:
        """Assess the harvest-now-decrypt-later risk for an asset.

        Args:
            asset_type: Type of data asset (e.g., 'database', 'file_store').
            asset_identifier: Unique identifier for the asset.
            data_sensitivity: Sensitivity level ('public', 'internal', 'confidential', 'secret').
            encryption_algorithm: Current encryption algorithm protecting the asset.
            estimated_exposure_years: How long the data has been externally exposed.
            assessed_by: UUID of the user requesting the assessment.
            tenant: The tenant context from auth middleware.
            quantum_threat_timeline_years: Years until quantum computers can break current crypto.
            risk_details: Additional risk context.

        Returns:
            The newly created HarvestRisk record.
        """
        logger.info(
            "Assessing harvest-now-decrypt-later risk",
            asset_type=asset_type,
            data_sensitivity=data_sensitivity,
            encryption_algorithm=encryption_algorithm,
            tenant_id=str(tenant.tenant_id),
        )

        risk_score = self._calculate_risk_score(
            data_sensitivity=data_sensitivity,
            encryption_algorithm=encryption_algorithm,
            estimated_exposure_years=estimated_exposure_years,
            quantum_threat_timeline_years=quantum_threat_timeline_years,
        )

        risk_level = self._classify_risk_level(risk_score)

        harvest_risk = await self._repository.create(
            asset_type=asset_type,
            asset_identifier=asset_identifier,
            risk_level=risk_level,
            risk_score=risk_score,
            data_sensitivity=data_sensitivity,
            encryption_algorithm=encryption_algorithm,
            estimated_exposure_years=estimated_exposure_years,
            quantum_threat_timeline_years=quantum_threat_timeline_years,
            risk_details=risk_details or {},
            assessed_by=assessed_by,
            tenant=tenant,
        )

        if risk_level in {"critical", "high"}:
            await self._publisher.publish_harvest_risk_identified(
                tenant_id=tenant.tenant_id,
                risk_id=harvest_risk.id,
                risk_level=risk_level,
                risk_score=risk_score,
            )

        return harvest_risk

    def _calculate_risk_score(
        self,
        data_sensitivity: str,
        encryption_algorithm: str,
        estimated_exposure_years: int,
        quantum_threat_timeline_years: int,
    ) -> float:
        """Calculate a composite harvest risk score.

        Args:
            data_sensitivity: Sensitivity level of the data.
            encryption_algorithm: Current encryption protecting the data.
            estimated_exposure_years: Duration of data exposure.
            quantum_threat_timeline_years: Estimated years until quantum decryption threat.

        Returns:
            Risk score between 0.0 (no risk) and 1.0 (maximum risk).
        """
        sensitivity_scores: dict[str, float] = {
            "public": 0.1,
            "internal": 0.4,
            "confidential": 0.7,
            "secret": 1.0,
        }

        vulnerable_algorithms = {
            "RSA-1024": 1.0,
            "RSA-2048": 0.9,
            "RSA-4096": 0.8,
            "ECDSA-P256": 0.9,
            "ECDSA-P384": 0.85,
            "DH-2048": 0.9,
        }

        sensitivity_weight = sensitivity_scores.get(data_sensitivity.lower(), 0.5)
        algorithm_weight = vulnerable_algorithms.get(encryption_algorithm, 0.3)

        urgency_ratio = min(estimated_exposure_years / max(quantum_threat_timeline_years, 1), 1.0)

        risk_score = (sensitivity_weight * 0.4) + (algorithm_weight * 0.4) + (urgency_ratio * 0.2)
        return min(round(risk_score, 4), 1.0)

    def _classify_risk_level(self, risk_score: float) -> str:
        """Classify a numeric risk score into a named risk level.

        Args:
            risk_score: Numeric risk score between 0.0 and 1.0.

        Returns:
            Risk level string: 'critical', 'high', 'medium', or 'low'.
        """
        for level, threshold in self.RISK_SCORE_THRESHOLDS.items():
            if risk_score >= threshold:
                return level
        return "low"

    async def list_harvest_risks(self, tenant: TenantContext) -> list[HarvestRisk]:
        """List all harvest risks for a tenant.

        Args:
            tenant: The tenant context from auth middleware.

        Returns:
            List of HarvestRisk records for the tenant.
        """
        logger.info("Listing harvest risks", tenant_id=str(tenant.tenant_id))
        return await self._repository.list_all(tenant)


class KeyExchangeService:
    """Manages quantum-safe key exchange operations.

    Uses CRYSTALS-Kyber (ML-KEM) as the primary Key Encapsulation Mechanism
    with optional hybrid mode combining classical and PQC algorithms.

    Args:
        repository: Data access layer for key exchange records.
        pqc_engine: PQC cryptographic operations adapter.
        publisher: Domain event publisher for Kafka events.
    """

    def __init__(
        self,
        repository: IKeyExchangeRepository,
        publisher: QuantumReadinessEventPublisher,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing IKeyExchangeRepository.
            publisher: Event publisher for domain events.
        """
        self._repository = repository
        self._publisher = publisher

    async def initiate_key_exchange(
        self,
        exchange_algorithm: str,
        key_encapsulation_mechanism: str,
        security_level: int,
        public_key_fingerprint: str,
        initiated_by: uuid.UUID,
        tenant: TenantContext,
        is_hybrid: bool = False,
        hybrid_classical_algorithm: str | None = None,
        exchange_metadata: dict | None = None,
        expires_at: datetime | None = None,
    ) -> KeyExchange:
        """Initiate a quantum-safe key exchange operation.

        Args:
            exchange_algorithm: The key exchange algorithm (e.g., 'CRYSTALS-Kyber-1024').
            key_encapsulation_mechanism: KEM variant (e.g., 'ML-KEM-1024').
            security_level: NIST security level (1, 3, or 5).
            public_key_fingerprint: Fingerprint of the recipient's public key.
            initiated_by: UUID of the user initiating the exchange.
            tenant: The tenant context from auth middleware.
            is_hybrid: Whether to use hybrid classical+PQC mode.
            hybrid_classical_algorithm: Classical algorithm for hybrid mode.
            exchange_metadata: Additional exchange context.
            expires_at: Optional expiry timestamp for the key exchange.

        Returns:
            The newly created KeyExchange record.
        """
        logger.info(
            "Initiating quantum-safe key exchange",
            exchange_algorithm=exchange_algorithm,
            security_level=security_level,
            is_hybrid=is_hybrid,
            tenant_id=str(tenant.tenant_id),
        )

        kem_params = self._get_kem_parameters(key_encapsulation_mechanism)

        key_exchange = await self._repository.create(
            exchange_algorithm=exchange_algorithm,
            key_encapsulation_mechanism=key_encapsulation_mechanism,
            security_level=security_level,
            public_key_fingerprint=public_key_fingerprint,
            ciphertext_size_bytes=kem_params["ciphertext_size"],
            shared_secret_size_bytes=kem_params["shared_secret_size"],
            is_hybrid=is_hybrid,
            initiated_by=initiated_by,
            exchange_metadata=exchange_metadata or {},
            tenant=tenant,
            hybrid_classical_algorithm=hybrid_classical_algorithm,
        )

        await self._publisher.publish_key_exchange_completed(
            tenant_id=tenant.tenant_id,
            exchange_id=key_exchange.id,
            exchange_algorithm=exchange_algorithm,
        )

        return key_exchange

    def _get_kem_parameters(self, kem: str) -> dict[str, int]:
        """Retrieve standard KEM parameters for a given mechanism.

        Args:
            kem: Key Encapsulation Mechanism identifier.

        Returns:
            Dict with ciphertext_size and shared_secret_size in bytes.
        """
        kem_params: dict[str, dict[str, int]] = {
            "ML-KEM-512": {"ciphertext_size": 768, "shared_secret_size": 32},
            "ML-KEM-768": {"ciphertext_size": 1088, "shared_secret_size": 32},
            "ML-KEM-1024": {"ciphertext_size": 1568, "shared_secret_size": 32},
            "CRYSTALS-Kyber-512": {"ciphertext_size": 768, "shared_secret_size": 32},
            "CRYSTALS-Kyber-768": {"ciphertext_size": 1088, "shared_secret_size": 32},
            "CRYSTALS-Kyber-1024": {"ciphertext_size": 1568, "shared_secret_size": 32},
        }
        return kem_params.get(kem, {"ciphertext_size": 0, "shared_secret_size": 32})

    async def get_key_exchange(
        self,
        exchange_id: uuid.UUID,
        tenant: TenantContext,
    ) -> KeyExchange:
        """Retrieve a key exchange record.

        Args:
            exchange_id: The UUID of the key exchange to retrieve.
            tenant: The tenant context from auth middleware.

        Returns:
            The KeyExchange record.

        Raises:
            NotFoundError: If the key exchange does not exist for this tenant.
        """
        exchange = await self._repository.get_by_id(exchange_id, tenant)
        if exchange is None:
            raise NotFoundError(f"Key exchange {exchange_id} not found")
        return exchange


class ComplianceCheckService:
    """Evaluates NIST PQC compliance posture.

    Args:
        repository: Data access layer for compliance check records.
        publisher: Domain event publisher for Kafka events.
    """

    NIST_PQC_CONTROLS: list[dict] = [
        {
            "id": "FIPS-203",
            "name": "Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)",
            "description": "Standardized from CRYSTALS-Kyber",
        },
        {
            "id": "FIPS-204",
            "name": "Module-Lattice-Based Digital Signature Algorithm (ML-DSA)",
            "description": "Standardized from CRYSTALS-Dilithium",
        },
        {
            "id": "FIPS-205",
            "name": "Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)",
            "description": "Standardized from SPHINCS+",
        },
        {
            "id": "NIST-SP-800-131A",
            "name": "Transitioning the Use of Cryptographic Algorithms",
            "description": "Guidance on algorithm transitions",
        },
        {
            "id": "NIST-IR-8547",
            "name": "Transition to Post-Quantum Cryptography Standards",
            "description": "Migration planning guidance",
        },
    ]

    def __init__(
        self,
        repository: IComplianceCheckRepository,
        publisher: QuantumReadinessEventPublisher,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing IComplianceCheckRepository.
            publisher: Event publisher for domain events.
        """
        self._repository = repository
        self._publisher = publisher

    async def run_compliance_check(
        self,
        standard: str,
        standard_version: str,
        algorithm_inventory: list[dict],
        checked_by: uuid.UUID,
        tenant: TenantContext,
    ) -> ComplianceCheck:
        """Execute a NIST PQC compliance check against current cryptographic posture.

        Args:
            standard: The standard to check against (e.g., 'NIST-PQC').
            standard_version: Version of the standard (e.g., 'FIPS-203').
            algorithm_inventory: Current cryptographic algorithms in use.
            checked_by: UUID of the user requesting the check.
            tenant: The tenant context from auth middleware.

        Returns:
            The newly created ComplianceCheck record.
        """
        logger.info(
            "Running NIST PQC compliance check",
            standard=standard,
            standard_version=standard_version,
            tenant_id=str(tenant.tenant_id),
        )

        findings, controls_passed, controls_failed, controls_na = self._evaluate_controls(
            algorithm_inventory=algorithm_inventory,
        )

        total_applicable = controls_passed + controls_failed
        compliance_score = controls_passed / max(total_applicable, 1)
        overall_status = "compliant" if compliance_score >= 0.8 else ("partial" if compliance_score >= 0.5 else "non_compliant")

        remediation_plan = self._build_remediation_plan(findings=findings)

        compliance_check = await self._repository.create(
            standard=standard,
            standard_version=standard_version,
            overall_status=overall_status,
            compliance_score=round(compliance_score, 4),
            controls_passed=controls_passed,
            controls_failed=controls_failed,
            controls_not_applicable=controls_na,
            findings=findings,
            remediation_plan=remediation_plan,
            checked_by=checked_by,
            tenant=tenant,
        )

        await self._publisher.publish_compliance_checked(
            tenant_id=tenant.tenant_id,
            check_id=compliance_check.id,
            overall_status=overall_status,
            compliance_score=compliance_score,
        )

        return compliance_check

    def _evaluate_controls(
        self,
        algorithm_inventory: list[dict],
    ) -> tuple[list[dict], int, int, int]:
        """Evaluate NIST PQC controls against the algorithm inventory.

        Args:
            algorithm_inventory: Current cryptographic algorithms in use.

        Returns:
            Tuple of (findings, controls_passed, controls_failed, controls_not_applicable).
        """
        pqc_algorithms_in_use = {asset.get("algorithm", "") for asset in algorithm_inventory}
        nist_approved_pqc = {
            "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s",
            "CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024",
            "CRYSTALS-Dilithium2", "CRYSTALS-Dilithium3", "CRYSTALS-Dilithium5",
        }

        findings: list[dict] = []
        controls_passed = 0
        controls_failed = 0
        controls_na = 0

        has_kem = bool(pqc_algorithms_in_use & {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024"})
        has_dsa = bool(pqc_algorithms_in_use & {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "CRYSTALS-Dilithium2", "CRYSTALS-Dilithium3", "CRYSTALS-Dilithium5"})
        has_hash_sig = bool(pqc_algorithms_in_use & {"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s"})
        has_vulnerable = bool(pqc_algorithms_in_use - nist_approved_pqc - {"AES-256", "SHA-3", "SHA-256"})

        if has_kem:
            controls_passed += 1
        else:
            controls_failed += 1
            findings.append({"control": "FIPS-203", "status": "failed", "detail": "No ML-KEM (Kyber) algorithm detected in inventory"})

        if has_dsa:
            controls_passed += 1
        else:
            controls_failed += 1
            findings.append({"control": "FIPS-204", "status": "failed", "detail": "No ML-DSA (Dilithium) algorithm detected in inventory"})

        if has_hash_sig:
            controls_passed += 1
        else:
            controls_na += 1

        if not has_vulnerable:
            controls_passed += 1
        else:
            controls_failed += 1
            findings.append({"control": "NIST-SP-800-131A", "status": "failed", "detail": "Quantum-vulnerable algorithms still in use"})

        controls_passed += 1

        return findings, controls_passed, controls_failed, controls_na

    def _build_remediation_plan(self, findings: list[dict]) -> dict:
        """Build a remediation plan from compliance findings.

        Args:
            findings: List of compliance findings.

        Returns:
            Structured remediation plan.
        """
        actions = []
        for finding in findings:
            control = finding.get("control", "")
            if control == "FIPS-203":
                actions.append({"priority": 1, "action": "Deploy ML-KEM for all key encapsulation operations", "reference": "FIPS-203"})
            elif control == "FIPS-204":
                actions.append({"priority": 2, "action": "Deploy ML-DSA for all digital signature operations", "reference": "FIPS-204"})
            elif control == "NIST-SP-800-131A":
                actions.append({"priority": 3, "action": "Remove all quantum-vulnerable algorithms from production", "reference": "NIST-SP-800-131A"})

        return {
            "actions": actions,
            "estimated_remediation_weeks": len(actions) * 4,
            "next_review_weeks": 12,
        }

    async def get_compliance_status(self, tenant: TenantContext) -> ComplianceCheck | None:
        """Retrieve the most recent compliance check for a tenant.

        Args:
            tenant: The tenant context from auth middleware.

        Returns:
            The most recent ComplianceCheck or None if no checks exist.
        """
        logger.info("Retrieving compliance status", tenant_id=str(tenant.tenant_id))
        return await self._repository.get_latest(tenant)


# ---------------------------------------------------------------------------
# Adapter-orchestration services (wire new PQC adapters into the service layer)
# ---------------------------------------------------------------------------


class QuantumKeyOperationsService:
    """Coordinates low-level PQC key operations across Kyber and Dilithium adapters.

    Wraps IKyberAdapter and IDilithiumAdapter to expose key generation,
    signing, verification, encapsulation, and decapsulation through a
    single service that persists KeyExchange records and publishes Kafka
    events for audit and monitoring.

    Args:
        kyber_adapter: CRYSTALS-Kyber (ML-KEM) key encapsulation adapter.
        dilithium_adapter: CRYSTALS-Dilithium (ML-DSA) digital signature adapter.
        key_exchange_repository: Repository for KeyExchange persistence.
        publisher: Domain event publisher for Kafka events.
    """

    def __init__(
        self,
        kyber_adapter: IKyberAdapter,
        dilithium_adapter: IDilithiumAdapter,
        key_exchange_repository: IKeyExchangeRepository,
        publisher: QuantumReadinessEventPublisher,
    ) -> None:
        """Initialise with injected cryptographic adapters and repositories.

        Args:
            kyber_adapter: Kyber KEM adapter instance.
            dilithium_adapter: Dilithium DSA adapter instance.
            key_exchange_repository: Repository for KeyExchange records.
            publisher: Kafka event publisher.
        """
        self._kyber = kyber_adapter
        self._dilithium = dilithium_adapter
        self._key_repo = key_exchange_repository
        self._publisher = publisher

    async def generate_kyber_keypair(
        self,
        variant: str,
        initiated_by: uuid.UUID,
        tenant: TenantContext,
    ) -> dict:
        """Generate a Kyber key pair and persist a KeyExchange record.

        Invokes the Kyber adapter to produce key material, then creates a
        KeyExchange record capturing the public key fingerprint and parameter
        metadata. Private key bytes are never persisted.

        Args:
            variant: Kyber variant ('Kyber-512' | 'Kyber-768' | 'Kyber-1024').
            initiated_by: UUID of the requesting user.
            tenant: Tenant context for RLS isolation.

        Returns:
            Dict with public_key_metadata, secret_key_handle,
            parameter_info, keygen_ms, exchange_id.
        """
        logger.info(
            "Generating Kyber key pair",
            variant=variant,
            tenant_id=str(tenant.tenant_id),
        )

        result = await self._kyber.generate_keypair(variant=variant)

        nist_name = result["parameter_info"]["nist_name"]
        key_exchange = await self._key_repo.create(
            exchange_algorithm=f"CRYSTALS-Kyber-{variant.split('-')[-1]}",
            key_encapsulation_mechanism=nist_name,
            security_level=result["parameter_info"]["security_level"],
            public_key_fingerprint=result["public_key_metadata"]["fingerprint"],
            ciphertext_size_bytes=result["parameter_info"].get("ciphertext_bytes", 0),
            shared_secret_size_bytes=32,
            is_hybrid=False,
            initiated_by=initiated_by,
            exchange_metadata={
                "keygen_ms": result.get("keygen_ms"),
                "variant": variant,
                "fips_reference": result["parameter_info"]["fips_reference"],
            },
            tenant=tenant,
        )

        await self._publisher.publish_key_exchange_completed(
            tenant_id=tenant.tenant_id,
            exchange_id=key_exchange.id,
            exchange_algorithm=nist_name,
        )

        return {
            **result,
            "exchange_id": str(key_exchange.id),
        }

    async def encapsulate(
        self,
        public_key_bytes: bytes,
        variant: str,
        tenant: TenantContext,
    ) -> dict:
        """Encapsulate a shared secret using a Kyber public key.

        Calls the Kyber adapter's encapsulate method. The shared secret is
        never returned raw — callers receive only the ciphertext and a
        fingerprint of the secret for audit.

        Args:
            public_key_bytes: Recipient's Kyber public key.
            variant: Kyber variant matching the key's parameter set.
            tenant: Tenant context.

        Returns:
            Dict with ciphertext_bytes, ciphertext_metadata,
            shared_secret_fingerprint, encap_ms.
        """
        logger.info(
            "Kyber encapsulation requested",
            variant=variant,
            tenant_id=str(tenant.tenant_id),
        )
        return await self._kyber.encapsulate(public_key_bytes=public_key_bytes, variant=variant)

    async def sign_message(
        self,
        secret_key_bytes: bytes,
        message: bytes,
        variant: str,
        context: bytes | None,
        tenant: TenantContext,
    ) -> dict:
        """Sign a message with a Dilithium private key.

        Args:
            secret_key_bytes: Signer's Dilithium private key bytes.
            message: Message bytes to sign.
            variant: Dilithium variant ('Dilithium-2' | 'Dilithium-3' | 'Dilithium-5').
            context: Optional domain-separation context bytes.
            tenant: Tenant context.

        Returns:
            Dict with signature_bytes, signature_metadata, message_fingerprint,
            sign_ms.
        """
        logger.info(
            "Dilithium sign requested",
            variant=variant,
            tenant_id=str(tenant.tenant_id),
        )
        return await self._dilithium.sign(
            secret_key_bytes=secret_key_bytes,
            message=message,
            variant=variant,
            context=context,
        )

    async def verify_signature(
        self,
        public_key_bytes: bytes,
        message: bytes,
        signature_bytes: bytes,
        variant: str,
        context: bytes | None,
        tenant: TenantContext,
    ) -> dict:
        """Verify a Dilithium signature.

        Args:
            public_key_bytes: Signer's Dilithium public key bytes.
            message: Original message bytes.
            signature_bytes: Signature to verify.
            variant: Dilithium variant matching the signer's key.
            context: Domain-separation context used during signing.
            tenant: Tenant context.

        Returns:
            Dict with valid, message_fingerprint, verify_ms, variant.
        """
        logger.info(
            "Dilithium verify requested",
            variant=variant,
            tenant_id=str(tenant.tenant_id),
        )
        return await self._dilithium.verify(
            public_key_bytes=public_key_bytes,
            message=message,
            signature_bytes=signature_bytes,
            variant=variant,
            context=context,
        )

    async def benchmark_algorithms(
        self,
        kyber_variant: str,
        dilithium_variant: str,
        iterations: int,
        tenant: TenantContext,
    ) -> dict:
        """Run performance benchmarks for both Kyber and Dilithium variants.

        Args:
            kyber_variant: Kyber variant to benchmark.
            dilithium_variant: Dilithium variant to benchmark.
            iterations: Number of iterations per operation.
            tenant: Tenant context.

        Returns:
            Dict with kyber_benchmark and dilithium_benchmark nested results.
        """
        logger.info(
            "PQC algorithm benchmark started",
            kyber_variant=kyber_variant,
            dilithium_variant=dilithium_variant,
            iterations=iterations,
            tenant_id=str(tenant.tenant_id),
        )

        kyber_result = await self._kyber.benchmark(
            variant=kyber_variant, iterations=iterations
        )
        dilithium_result = await self._dilithium.benchmark(
            variant=dilithium_variant, iterations=iterations
        )

        return {
            "kyber_benchmark": kyber_result,
            "dilithium_benchmark": dilithium_result,
            "iterations": iterations,
        }


class HybridTLSService:
    """Coordinates hybrid classical+PQC TLS key exchange workflows.

    Wraps IHybridKeyExchange and ICryptoAgility adapters to perform
    algorithm negotiation and hybrid handshake orchestration. On
    handshake completion, persists a KeyExchange record and publishes
    a Kafka event for downstream consumers (e.g., aumos-secrets-vault).

    Args:
        hybrid_key_exchange: Hybrid X25519+Kyber key exchange adapter.
        crypto_agility: Algorithm registry and selection adapter.
        key_exchange_repository: Repository for KeyExchange persistence.
        publisher: Domain event publisher.
    """

    def __init__(
        self,
        hybrid_key_exchange: IHybridKeyExchange,
        crypto_agility: ICryptoAgility,
        key_exchange_repository: IKeyExchangeRepository,
        publisher: QuantumReadinessEventPublisher,
    ) -> None:
        """Initialise with injected adapters and repository.

        Args:
            hybrid_key_exchange: Hybrid key exchange adapter.
            crypto_agility: Crypto-agility algorithm selection adapter.
            key_exchange_repository: Repository for KeyExchange records.
            publisher: Kafka event publisher.
        """
        self._hybrid = hybrid_key_exchange
        self._agility = crypto_agility
        self._key_repo = key_exchange_repository
        self._publisher = publisher

    async def negotiate_and_initiate(
        self,
        peer_capabilities: dict,
        application_context: str,
        initiated_by: uuid.UUID,
        tenant: TenantContext,
    ) -> dict:
        """Negotiate the best hybrid algorithm and initiate a key exchange.

        Calls the CryptoAgility adapter to select the optimal KEM given peer
        capabilities, then initiates a hybrid handshake session.

        Args:
            peer_capabilities: Peer-advertised algorithm constraints (category,
                min_security_level, max_public_key_bytes).
            application_context: Application label for HKDF domain separation.
            initiated_by: UUID of the requesting user.
            tenant: Tenant context.

        Returns:
            Dict with session_id, classical_public_key_bytes,
            pqc_public_key_bytes, selected_algorithm, handshake_ms.
        """
        logger.info(
            "Hybrid TLS negotiation started",
            application_context=application_context,
            tenant_id=str(tenant.tenant_id),
        )

        selection = await self._agility.select_algorithm(
            selection_config={
                "category": "kem",
                "min_security_level": peer_capabilities.get("min_security_level", 3),
                "max_public_key_bytes": peer_capabilities.get("max_public_key_bytes"),
                "preferred_algorithm": peer_capabilities.get("preferred_kem"),
            },
            tenant_id=tenant.tenant_id,
        )

        handshake_config = {
            "application_context": application_context,
            "selected_algorithm": selection.get("selected_algorithm"),
        }
        handshake_result = await self._hybrid.initiate_handshake(
            handshake_config=handshake_config,
            tenant_id=tenant.tenant_id,
        )

        return {
            "selected_algorithm": selection.get("selected_algorithm"),
            "nist_reference": selection.get("nist_reference"),
            **handshake_result,
        }

    async def complete_handshake(
        self,
        session_id: str,
        peer_ciphertext_bytes: bytes,
        initiated_by: uuid.UUID,
        tenant: TenantContext,
    ) -> dict:
        """Complete a hybrid key exchange and persist the exchange record.

        Args:
            session_id: Session ID from negotiate_and_initiate.
            peer_ciphertext_bytes: Kyber ciphertext from the remote peer.
            initiated_by: UUID of the requesting user.
            tenant: Tenant context.

        Returns:
            Dict with combined_secret_fingerprint, key_material_bits,
            exchange_id, handshake_ms.
        """
        logger.info(
            "Completing hybrid TLS handshake",
            session_id=session_id,
            tenant_id=str(tenant.tenant_id),
        )

        result = await self._hybrid.complete_handshake(
            session_id=session_id,
            peer_ciphertext_bytes=peer_ciphertext_bytes,
            tenant_id=tenant.tenant_id,
        )

        key_exchange = await self._key_repo.create(
            exchange_algorithm="X25519+CRYSTALS-Kyber",
            key_encapsulation_mechanism=result.get("hybrid_mode", "X25519+ML-KEM"),
            security_level=3,
            public_key_fingerprint=result.get("combined_secret_fingerprint", ""),
            ciphertext_size_bytes=len(peer_ciphertext_bytes),
            shared_secret_size_bytes=result.get("key_material_bits", 256) // 8,
            is_hybrid=True,
            initiated_by=initiated_by,
            exchange_metadata={
                "session_id": session_id,
                "handshake_ms": result.get("handshake_ms"),
                "hybrid_mode": result.get("hybrid_mode"),
            },
            tenant=tenant,
            hybrid_classical_algorithm="X25519",
        )

        await self._publisher.publish_key_exchange_completed(
            tenant_id=tenant.tenant_id,
            exchange_id=key_exchange.id,
            exchange_algorithm="X25519+CRYSTALS-Kyber",
        )

        return {
            **result,
            "exchange_id": str(key_exchange.id),
        }


class QuantumAuditService:
    """Coordinates quantum vulnerability scanning, compliance verification,
    and migration planning into a unified audit workflow.

    Orchestrates three adapters — IQuantumVulnerabilityScanner,
    IQuantumComplianceVerifier, and IQuantumMigrationPlanner — to produce
    a complete quantum security audit report. On completion, persists a
    ComplianceCheck record and publishes a Kafka event so downstream
    systems (aumos-governance-engine) can ingest findings.

    Args:
        vulnerability_scanner: Quantum vulnerability scanning adapter.
        compliance_verifier: NIST PQC compliance verification adapter.
        migration_planner: Quantum migration roadmap planning adapter.
        harvest_defense_engine: HNDL risk assessment adapter.
        compliance_repository: Repository for ComplianceCheck records.
        publisher: Domain event publisher.
    """

    def __init__(
        self,
        vulnerability_scanner: IQuantumVulnerabilityScanner,
        compliance_verifier: IQuantumComplianceVerifier,
        migration_planner: IQuantumMigrationPlanner,
        harvest_defense_engine: IHarvestDefenseEngine,
        compliance_repository: IComplianceCheckRepository,
        publisher: QuantumReadinessEventPublisher,
    ) -> None:
        """Initialise with injected adapters and repository.

        Args:
            vulnerability_scanner: Quantum vulnerability scanner adapter.
            compliance_verifier: NIST PQC compliance verifier adapter.
            migration_planner: Quantum migration planner adapter.
            harvest_defense_engine: HNDL defense assessment adapter.
            compliance_repository: Repository for ComplianceCheck records.
            publisher: Kafka event publisher.
        """
        self._scanner = vulnerability_scanner
        self._verifier = compliance_verifier
        self._planner = migration_planner
        self._harvest = harvest_defense_engine
        self._compliance_repo = compliance_repository
        self._publisher = publisher

    async def run_full_audit(
        self,
        audit_config: dict,
        checked_by: uuid.UUID,
        tenant: TenantContext,
    ) -> dict:
        """Execute a comprehensive quantum security audit.

        Runs vulnerability scanning, NIST PQC compliance verification,
        HNDL risk assessment, and migration planning sequentially. Aggregates
        results into a single audit report and persists a ComplianceCheck
        record for the compliance findings.

        Args:
            audit_config: Audit configuration including:
                - scan_targets: List of vulnerability scan targets.
                - algorithm_inventory: Cryptographic asset inventory.
                - data_assets: List of data assets for HNDL assessment.
                - organisation_name: Name for compliance certificate.
                - standard_filter: NIST standards to verify against.
                - include_migration_plan: bool — generate migration roadmap.
                - severity_threshold: Minimum severity to include in findings.
            checked_by: UUID of the user requesting the audit.
            tenant: Tenant context.

        Returns:
            Dict with vulnerability_scan, compliance_verification,
            hndl_assessment, migration_plan (if requested), compliance_check_id,
            overall_risk_level, audit_summary.
        """
        logger.info(
            "Quantum security audit started",
            tenant_id=str(tenant.tenant_id),
            has_scan_targets=bool(audit_config.get("scan_targets")),
            has_inventory=bool(audit_config.get("algorithm_inventory")),
        )

        # 1. Vulnerability scan
        scan_result: dict = {}
        if audit_config.get("scan_targets"):
            scan_result = await self._scanner.scan(
                scan_config={
                    "scan_targets": audit_config["scan_targets"],
                    "severity_threshold": audit_config.get("severity_threshold", "medium"),
                    "include_remediation_plan": True,
                },
                tenant_id=tenant.tenant_id,
            )
            logger.info(
                "Vulnerability scan complete",
                total_findings=scan_result.get("summary", {}).get("total_findings", 0),
                overall_risk_level=scan_result.get("overall_risk_level"),
                tenant_id=str(tenant.tenant_id),
            )

        # 2. NIST PQC compliance verification
        compliance_result: dict = {}
        if audit_config.get("algorithm_inventory"):
            compliance_result = await self._verifier.verify_compliance(
                verification_config={
                    "algorithm_inventory": audit_config["algorithm_inventory"],
                    "standard_filter": audit_config.get("standard_filter", []),
                    "organisation_name": audit_config.get("organisation_name", "Unknown"),
                    "include_certificate": True,
                },
                tenant_id=tenant.tenant_id,
            )
            logger.info(
                "Compliance verification complete",
                overall_status=compliance_result.get("overall_status"),
                compliance_score=compliance_result.get("compliance_score"),
                tenant_id=str(tenant.tenant_id),
            )

        # 3. HNDL risk assessment
        hndl_result: dict = {}
        if audit_config.get("data_assets"):
            hndl_result = await self._harvest.assess_hndl_risk(
                assessment_config={
                    "data_assets": audit_config["data_assets"],
                    "threat_model": audit_config.get("threat_model", "baseline"),
                    "include_defense_strategies": True,
                },
                tenant_id=tenant.tenant_id,
            )
            logger.info(
                "HNDL risk assessment complete",
                priority_assets=len(hndl_result.get("priority_assets", [])),
                tenant_id=str(tenant.tenant_id),
            )

        # 4. Migration planning (optional)
        migration_result: dict = {}
        if audit_config.get("include_migration_plan") and audit_config.get("algorithm_inventory"):
            migration_result = await self._planner.assess_and_plan(
                plan_config={
                    "crypto_inventory": audit_config["algorithm_inventory"],
                    "organisation_name": audit_config.get("organisation_name", "Unknown"),
                    "timeline_months": audit_config.get("timeline_months", 24),
                    "include_rollback_strategies": True,
                },
                tenant_id=tenant.tenant_id,
            )
            logger.info(
                "Migration planning complete",
                migration_tasks=len(migration_result.get("migration_tasks", [])),
                tenant_id=str(tenant.tenant_id),
            )

        # 5. Persist compliance check record
        overall_status = compliance_result.get("overall_status", "unknown")
        compliance_score = compliance_result.get("compliance_score", 0.0)
        control_results = compliance_result.get("control_results", [])
        controls_passed = sum(1 for c in control_results if c.get("status") == "pass")
        controls_failed = sum(1 for c in control_results if c.get("status") == "fail")
        controls_na = sum(1 for c in control_results if c.get("status") == "not_applicable")

        compliance_check = await self._compliance_repo.create(
            standard="NIST-PQC",
            standard_version="FIPS-203/204/205",
            overall_status=overall_status,
            compliance_score=compliance_score,
            controls_passed=controls_passed,
            controls_failed=controls_failed,
            controls_not_applicable=controls_na,
            findings=compliance_result.get("gaps", []),
            remediation_plan={
                "recommendations": compliance_result.get("recommendations", []),
                "migration_roadmap": migration_result.get("roadmap", {}),
            },
            checked_by=checked_by,
            tenant=tenant,
        )

        await self._publisher.publish_compliance_checked(
            tenant_id=tenant.tenant_id,
            check_id=compliance_check.id,
            overall_status=overall_status,
            compliance_score=compliance_score,
        )

        # Derive overall risk level from scan + HNDL
        scan_risk = scan_result.get("overall_risk_level", "low")
        hndl_risk = hndl_result.get("risk_summary", {}).get("highest_risk_level", "low")
        risk_order = ["low", "medium", "high", "critical"]
        overall_risk = max(
            scan_risk, hndl_risk,
            key=lambda r: risk_order.index(r) if r in risk_order else 0,
        )

        audit_summary = {
            "vulnerability_findings": scan_result.get("summary", {}).get("total_findings", 0),
            "compliance_score": compliance_score,
            "compliance_status": overall_status,
            "hndl_priority_assets": len(hndl_result.get("priority_assets", [])),
            "migration_tasks_planned": len(migration_result.get("migration_tasks", [])),
            "overall_risk_level": overall_risk,
            "compliance_check_id": str(compliance_check.id),
        }

        logger.info(
            "Quantum security audit complete",
            overall_risk_level=overall_risk,
            compliance_status=overall_status,
            compliance_check_id=str(compliance_check.id),
            tenant_id=str(tenant.tenant_id),
        )

        return {
            "vulnerability_scan": scan_result,
            "compliance_verification": compliance_result,
            "hndl_assessment": hndl_result,
            "migration_plan": migration_result,
            "compliance_check_id": str(compliance_check.id),
            "overall_risk_level": overall_risk,
            "audit_summary": audit_summary,
        }

    async def run_vulnerability_scan_only(
        self,
        scan_targets: list[dict],
        severity_threshold: str,
        tenant: TenantContext,
    ) -> dict:
        """Execute a standalone vulnerability scan without full audit workflow.

        Args:
            scan_targets: List of scan target dicts (type + content).
            severity_threshold: Minimum severity level to include ('low' | 'medium'
                | 'high' | 'critical').
            tenant: Tenant context.

        Returns:
            Vulnerability scanner output dict (findings, summary, remediation_plan).
        """
        logger.info(
            "Standalone vulnerability scan started",
            num_targets=len(scan_targets),
            severity_threshold=severity_threshold,
            tenant_id=str(tenant.tenant_id),
        )
        return await self._scanner.scan(
            scan_config={
                "scan_targets": scan_targets,
                "severity_threshold": severity_threshold,
                "include_remediation_plan": True,
            },
            tenant_id=tenant.tenant_id,
        )

    async def run_compliance_verification_only(
        self,
        algorithm_inventory: list[dict],
        organisation_name: str,
        standard_filter: list[str],
        checked_by: uuid.UUID,
        tenant: TenantContext,
    ) -> ComplianceCheck:
        """Execute compliance verification and persist a ComplianceCheck record.

        Args:
            algorithm_inventory: Cryptographic asset inventory list.
            organisation_name: Organisation name for compliance certificate.
            standard_filter: List of NIST standard IDs to restrict checks to.
            checked_by: UUID of the requesting user.
            tenant: Tenant context.

        Returns:
            Persisted ComplianceCheck ORM record.
        """
        logger.info(
            "Standalone compliance verification started",
            inventory_size=len(algorithm_inventory),
            standard_filter=standard_filter,
            tenant_id=str(tenant.tenant_id),
        )

        result = await self._verifier.verify_compliance(
            verification_config={
                "algorithm_inventory": algorithm_inventory,
                "standard_filter": standard_filter,
                "organisation_name": organisation_name,
                "include_certificate": True,
            },
            tenant_id=tenant.tenant_id,
        )

        control_results = result.get("control_results", [])
        compliance_check = await self._compliance_repo.create(
            standard="NIST-PQC",
            standard_version=", ".join(standard_filter) if standard_filter else "FIPS-203/204/205",
            overall_status=result.get("overall_status", "unknown"),
            compliance_score=result.get("compliance_score", 0.0),
            controls_passed=sum(1 for c in control_results if c.get("status") == "pass"),
            controls_failed=sum(1 for c in control_results if c.get("status") == "fail"),
            controls_not_applicable=sum(1 for c in control_results if c.get("status") == "not_applicable"),
            findings=result.get("gaps", []),
            remediation_plan={"recommendations": result.get("recommendations", [])},
            checked_by=checked_by,
            tenant=tenant,
        )

        await self._publisher.publish_compliance_checked(
            tenant_id=tenant.tenant_id,
            check_id=compliance_check.id,
            overall_status=result.get("overall_status", "unknown"),
            compliance_score=result.get("compliance_score", 0.0),
        )

        return compliance_check
