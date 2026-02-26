"""Business logic services for aumos-quantum-readiness.

Services contain all domain logic. They:
  - Accept dependencies via constructor injection (repositories, publishers)
  - Orchestrate repository calls and event publishing
  - Raise domain errors using aumos_common.errors
  - Are framework-agnostic (no FastAPI, no direct DB access)

After any state-changing operation, publish a Kafka event via EventPublisher.
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
