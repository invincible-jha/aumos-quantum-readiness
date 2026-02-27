"""Abstract interfaces (Protocol classes) for aumos-quantum-readiness.

Defining interfaces as Protocol classes enables:
  - Dependency injection in services
  - Easy mocking in tests
  - Clear contracts between layers

Services depend on interfaces, not concrete implementations.

Two categories of interface are defined here:
  1. Repository interfaces (IPrefix) — data-access contracts backed by SQLAlchemy.
  2. Adapter interfaces (IPrefix) — cryptographic operation contracts backed by
     PQC algorithm implementations (liboqs-python in production).
"""

import uuid
from typing import Any, Protocol, runtime_checkable

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


# ---------------------------------------------------------------------------
# Adapter-level cryptographic operation interfaces
# ---------------------------------------------------------------------------


@runtime_checkable
class IKyberAdapter(Protocol):
    """Contract for CRYSTALS-Kyber (ML-KEM) key encapsulation adapters.

    Implementations wrap liboqs-python KEM operations for Kyber-512,
    Kyber-768, and Kyber-1024 parameter sets per FIPS-203.
    """

    async def generate_keypair(
        self,
        variant: str | None = None,
    ) -> dict[str, Any]:
        """Generate a Kyber key pair.

        Args:
            variant: 'Kyber-512' | 'Kyber-768' | 'Kyber-1024'.
                Defaults to adapter's default_variant.

        Returns:
            Dict with public_key_metadata, public_key_bytes,
            secret_key_handle, parameter_info, keygen_ms.
        """
        ...

    async def encapsulate(
        self,
        public_key_bytes: bytes,
        variant: str | None = None,
    ) -> dict[str, Any]:
        """Encapsulate a shared secret using a Kyber public key.

        Args:
            public_key_bytes: Recipient's Kyber public key bytes.
            variant: Kyber variant matching the key's parameter set.

        Returns:
            Dict with ciphertext_metadata, ciphertext_bytes,
            shared_secret_fingerprint, shared_secret_size_bytes, encap_ms.
        """
        ...

    async def decapsulate(
        self,
        secret_key_bytes: bytes,
        ciphertext_bytes: bytes,
        variant: str | None = None,
    ) -> dict[str, Any]:
        """Decapsulate a shared secret from a Kyber ciphertext.

        Args:
            secret_key_bytes: Recipient's Kyber private key bytes.
            ciphertext_bytes: Ciphertext received from the sender.
            variant: Kyber variant matching the key pair's parameter set.

        Returns:
            Dict with shared_secret_fingerprint, shared_secret_size_bytes,
            decap_ms, success.
        """
        ...

    async def benchmark(
        self,
        variant: str | None = None,
        iterations: int = 100,
    ) -> dict[str, Any]:
        """Benchmark key generation, encapsulation, and decapsulation.

        Args:
            variant: Kyber variant to benchmark.
            iterations: Number of iterations per operation.

        Returns:
            Dict with keygen_mean_ms, encap_mean_ms, decap_mean_ms, variant.
        """
        ...


@runtime_checkable
class IDilithiumAdapter(Protocol):
    """Contract for CRYSTALS-Dilithium (ML-DSA) digital signature adapters.

    Implementations wrap liboqs-python DSA operations for Dilithium-2,
    Dilithium-3, and Dilithium-5 parameter sets per FIPS-204.
    """

    async def generate_keypair(
        self,
        variant: str | None = None,
        deterministic_seed: bytes | None = None,
    ) -> dict[str, Any]:
        """Generate a Dilithium signing key pair.

        Args:
            variant: 'Dilithium-2' | 'Dilithium-3' | 'Dilithium-5'
                (or ML-DSA-44/65/87 aliases).
            deterministic_seed: Optional 32-byte seed for deterministic keygen.

        Returns:
            Dict with public_key_metadata, public_key_bytes,
            secret_key_handle, parameter_info, keygen_ms.
        """
        ...

    async def sign(
        self,
        secret_key_bytes: bytes,
        message: bytes,
        variant: str | None = None,
        context: bytes | None = None,
    ) -> dict[str, Any]:
        """Sign a message with a Dilithium private key.

        Args:
            secret_key_bytes: Signer's Dilithium private key bytes.
            message: Message bytes to sign.
            variant: Dilithium variant matching the key's parameter set.
            context: Optional domain-separation context bytes (FIPS-204 §5.2).

        Returns:
            Dict with signature_bytes, signature_metadata, message_fingerprint,
            sign_ms.
        """
        ...

    async def verify(
        self,
        public_key_bytes: bytes,
        message: bytes,
        signature_bytes: bytes,
        variant: str | None = None,
        context: bytes | None = None,
    ) -> dict[str, Any]:
        """Verify a Dilithium signature.

        Args:
            public_key_bytes: Signer's Dilithium public key bytes.
            message: Original message bytes.
            signature_bytes: Signature bytes to verify.
            variant: Dilithium variant matching the key's parameter set.
            context: Domain-separation context used during signing.

        Returns:
            Dict with valid, message_fingerprint, verify_ms, variant.
        """
        ...

    async def benchmark(
        self,
        variant: str | None = None,
        iterations: int = 100,
    ) -> dict[str, Any]:
        """Benchmark key generation, signing, and verification.

        Args:
            variant: Dilithium variant to benchmark.
            iterations: Number of iterations per operation.

        Returns:
            Dict with keygen_mean_ms, sign_mean_ms, verify_mean_ms, variant.
        """
        ...


@runtime_checkable
class IHybridKeyExchange(Protocol):
    """Contract for hybrid classical+PQC key exchange adapters.

    Implementations combine X25519 (classical) with CRYSTALS-Kyber (PQC)
    using HKDF to produce a combined shared secret per NIST SP 800-227.
    """

    async def initiate_handshake(
        self,
        handshake_config: dict[str, Any],
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Initiate a hybrid TLS-style handshake.

        Args:
            handshake_config: Handshake parameters including peer_public_key_x25519,
                peer_public_key_kyber, application_context.
            tenant_id: Tenant context.

        Returns:
            Dict with session_id, classical_public_key_bytes,
            pqc_public_key_bytes, combined_fingerprint, handshake_ms.
        """
        ...

    async def complete_handshake(
        self,
        session_id: str,
        peer_ciphertext_bytes: bytes,
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Complete a hybrid key exchange handshake.

        Args:
            session_id: Session identifier from initiate_handshake.
            peer_ciphertext_bytes: Kyber ciphertext from the remote peer.
            tenant_id: Tenant context.

        Returns:
            Dict with session_id, combined_secret_fingerprint,
            key_material_bits, handshake_ms, hybrid_mode.
        """
        ...

    async def export_key_material(
        self,
        session_id: str,
        label: str,
        context: bytes,
        length_bytes: int,
    ) -> dict[str, Any]:
        """Derive keying material from a completed handshake session.

        Args:
            session_id: Completed session identifier.
            label: HKDF label string for domain separation.
            context: Application context bytes.
            length_bytes: Number of output key bytes to derive.

        Returns:
            Dict with key_material_fingerprint, length_bytes, label,
            derivation_ms.
        """
        ...


@runtime_checkable
class ICryptoAgility(Protocol):
    """Contract for crypto-agility framework adapters.

    Implementations provide runtime algorithm selection, capability
    matrices, deprecation management, and migration-safe API negotiation
    across classical and post-quantum algorithm families.
    """

    async def select_algorithm(
        self,
        selection_config: dict[str, Any],
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Select the best available algorithm for a given use case.

        Args:
            selection_config: Selection constraints including category,
                min_security_level, max_signature_bytes, preferred_algorithm.
            tenant_id: Tenant context.

        Returns:
            Dict with selected_algorithm, nist_reference, quantum_status,
            lifecycle, security_level_bits.
        """
        ...

    async def validate_algorithm(
        self,
        algorithm_name: str,
        usage_context: str,
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Validate an algorithm for a given usage context.

        Args:
            algorithm_name: Algorithm name to validate.
            usage_context: Intended use context.
            tenant_id: Tenant context.

        Returns:
            Dict with valid, algorithm, lifecycle, quantum_status,
            warnings, nist_reference.
        """
        ...

    async def get_capability_matrix(
        self,
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Return the full algorithm capability matrix.

        Args:
            tenant_id: Tenant context.

        Returns:
            Dict with algorithms grouped by category, lifecycle, and
            quantum_status with security level metadata.
        """
        ...


@runtime_checkable
class IQuantumMigrationPlanner(Protocol):
    """Contract for quantum migration planning adapters.

    Implementations assess cryptographic inventories, prioritise assets
    by risk, generate phased migration roadmaps, and produce rollback
    strategies for each migration task.
    """

    async def assess_and_plan(
        self,
        plan_config: dict[str, Any],
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Assess a cryptographic inventory and produce a migration plan.

        Args:
            plan_config: Planning parameters including crypto_inventory
                (list of asset dicts), organisation_name, timeline_months,
                include_rollback_strategies.
            tenant_id: Tenant context.

        Returns:
            Dict with inventory_summary, migration_tasks, priority_order,
            dependency_graph, roadmap, testing_plan, rollback_strategies,
            estimated_total_weeks, output_uri.
        """
        ...


@runtime_checkable
class IQuantumVulnerabilityScanner(Protocol):
    """Contract for quantum vulnerability scanning adapters.

    Implementations scan code, TLS configurations, and X.509 certificates
    for quantum-vulnerable cryptographic primitives and score findings by
    severity.
    """

    async def scan(
        self,
        scan_config: dict[str, Any],
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Execute a quantum vulnerability scan.

        Args:
            scan_config: Scan parameters including scan_targets (list of
                target dicts with type and content), severity_threshold,
                include_remediation_plan.
            tenant_id: Tenant context.

        Returns:
            Dict with findings, summary, remediation_plan, overall_risk_level,
            output_uri.
        """
        ...


@runtime_checkable
class IQuantumComplianceVerifier(Protocol):
    """Contract for NIST PQC compliance verifier adapters.

    Implementations evaluate cryptographic inventories against FIPS-203,
    FIPS-204, FIPS-205, and NIST SP 800 controls, scoring each control
    and generating compliance certificates.
    """

    async def verify_compliance(
        self,
        verification_config: dict[str, Any],
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Verify NIST PQC compliance for a cryptographic inventory.

        Args:
            verification_config: Config including algorithm_inventory,
                standard_filter, organisation_name, include_certificate.
            tenant_id: Tenant context.

        Returns:
            Dict with control_results, overall_status, compliance_score,
            gaps, recommendations, compliance_certificate, output_uri.
        """
        ...


@runtime_checkable
class IHarvestDefenseEngine(Protocol):
    """Contract for harvest-now-decrypt-later defense adapters.

    Implementations model HNDL exposure windows, score asset risk,
    project quantum threat timelines, and generate prioritised defense
    strategies per asset.
    """

    async def assess_hndl_risk(
        self,
        assessment_config: dict[str, Any],
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Assess harvest-now-decrypt-later risk for a set of assets.

        Args:
            assessment_config: Assessment parameters including data_assets
                (list of asset dicts), threat_model, include_defense_strategies.
            tenant_id: Tenant context.

        Returns:
            Dict with asset_risks, risk_summary, threat_timeline,
            defense_strategies, priority_assets, output_uri.
        """
        ...


__all__ = [
    # Repository interfaces
    "IPQCMigrationRepository",
    "IAgilityAssessmentRepository",
    "IHarvestRiskRepository",
    "IKeyExchangeRepository",
    "IComplianceCheckRepository",
    # Adapter-level cryptographic operation interfaces
    "IKyberAdapter",
    "IDilithiumAdapter",
    "IHybridKeyExchange",
    "ICryptoAgility",
    "IQuantumMigrationPlanner",
    "IQuantumVulnerabilityScanner",
    "IQuantumComplianceVerifier",
    "IHarvestDefenseEngine",
]
