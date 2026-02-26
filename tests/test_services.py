"""Unit tests for aumos-quantum-readiness services."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from aumos_quantum_readiness.adapters.kafka import QuantumReadinessEventPublisher
from aumos_quantum_readiness.core.models import (
    AgilityAssessment,
    ComplianceCheck,
    HarvestRisk,
    KeyExchange,
    PQCMigration,
)
from aumos_quantum_readiness.core.services import (
    ComplianceCheckService,
    CryptoAgilityService,
    HarvestDefenseService,
    KeyExchangeService,
    PQCMigrationService,
)


# ---------------------------------------------------------------------------
# PQCMigrationService tests
# ---------------------------------------------------------------------------


class TestPQCMigrationService:
    """Tests for PQCMigrationService."""

    @pytest.fixture
    def mock_migration(self, tenant_id: uuid.UUID, user_id: uuid.UUID) -> PQCMigration:
        """Return a stub PQCMigration."""
        migration = MagicMock(spec=PQCMigration)
        migration.id = uuid.uuid4()
        migration.tenant_id = tenant_id
        migration.algorithm_from = "RSA-2048"
        migration.algorithm_to = "CRYSTALS-Kyber-1024"
        migration.status = "pending"
        migration.asset_type = "api_key"
        migration.asset_identifier = "key-001"
        migration.initiated_by = user_id
        return migration

    @pytest.fixture
    def mock_repository(self, mock_migration: PQCMigration) -> MagicMock:
        """Return a mock PQC migration repository."""
        repo = MagicMock()
        repo.create = AsyncMock(return_value=mock_migration)
        repo.get_by_id = AsyncMock(return_value=mock_migration)
        repo.list_all = AsyncMock(return_value=[mock_migration])
        repo.update_status = AsyncMock(return_value=mock_migration)
        return repo

    async def test_start_migration_creates_record(
        self,
        mock_repository: MagicMock,
        mock_publisher: QuantumReadinessEventPublisher,
        tenant_context: MagicMock,
        user_id: uuid.UUID,
    ) -> None:
        """start_migration creates a migration record and publishes an event."""
        service = PQCMigrationService(repository=mock_repository, publisher=mock_publisher)

        result = await service.start_migration(
            algorithm_from="RSA-2048",
            algorithm_to="CRYSTALS-Kyber-1024",
            asset_type="api_key",
            asset_identifier="key-001",
            initiated_by=user_id,
            migration_metadata={},
            tenant=tenant_context,
        )

        mock_repository.create.assert_called_once()
        mock_publisher.publish_migration_started.assert_called_once()
        assert result is not None

    async def test_get_migration_status_returns_record(
        self,
        mock_repository: MagicMock,
        mock_publisher: QuantumReadinessEventPublisher,
        tenant_context: MagicMock,
        mock_migration: PQCMigration,
    ) -> None:
        """get_migration_status returns the migration record."""
        service = PQCMigrationService(repository=mock_repository, publisher=mock_publisher)

        result = await service.get_migration_status(
            migration_id=mock_migration.id,
            tenant=tenant_context,
        )

        assert result == mock_migration

    async def test_get_migration_status_raises_not_found(
        self,
        mock_publisher: QuantumReadinessEventPublisher,
        tenant_context: MagicMock,
    ) -> None:
        """get_migration_status raises NotFoundError when record does not exist."""
        from aumos_common.errors import NotFoundError

        repo = MagicMock()
        repo.get_by_id = AsyncMock(return_value=None)
        service = PQCMigrationService(repository=repo, publisher=mock_publisher)

        with pytest.raises(NotFoundError):
            await service.get_migration_status(
                migration_id=uuid.uuid4(),
                tenant=tenant_context,
            )

    async def test_list_migrations_returns_all(
        self,
        mock_repository: MagicMock,
        mock_publisher: QuantumReadinessEventPublisher,
        tenant_context: MagicMock,
        mock_migration: PQCMigration,
    ) -> None:
        """list_migrations returns all records for the tenant."""
        service = PQCMigrationService(repository=mock_repository, publisher=mock_publisher)

        results = await service.list_migrations(tenant=tenant_context)

        assert len(results) == 1
        assert results[0] == mock_migration


# ---------------------------------------------------------------------------
# CryptoAgilityService tests
# ---------------------------------------------------------------------------


class TestCryptoAgilityService:
    """Tests for CryptoAgilityService."""

    @pytest.fixture
    def mock_repository(self) -> MagicMock:
        """Return a mock agility assessment repository."""
        repo = MagicMock()
        repo.create = AsyncMock(return_value=MagicMock(spec=AgilityAssessment, id=uuid.uuid4()))
        repo.get_by_id = AsyncMock(return_value=MagicMock(spec=AgilityAssessment))
        repo.list_all = AsyncMock(return_value=[])
        return repo

    async def test_assess_agility_with_vulnerable_inventory(
        self,
        mock_repository: MagicMock,
        mock_publisher: QuantumReadinessEventPublisher,
        tenant_context: MagicMock,
        user_id: uuid.UUID,
    ) -> None:
        """assess_agility identifies quantum-vulnerable algorithms and scores accordingly."""
        service = CryptoAgilityService(repository=mock_repository, publisher=mock_publisher)

        await service.assess_agility(
            scope="payment_api",
            crypto_inventory=[
                {"identifier": "key-001", "algorithm": "RSA-2048", "asset_type": "api_key"},
                {"identifier": "key-002", "algorithm": "ECDSA-P256", "asset_type": "cert"},
            ],
            assessed_by=user_id,
            tenant=tenant_context,
        )

        mock_repository.create.assert_called_once()
        call_kwargs = mock_repository.create.call_args.kwargs
        assert call_kwargs["quantum_vulnerable_count"] == 2
        assert call_kwargs["quantum_safe_count"] == 0
        assert call_kwargs["agility_score"] == 0.0

    async def test_assess_agility_with_safe_inventory(
        self,
        mock_repository: MagicMock,
        mock_publisher: QuantumReadinessEventPublisher,
        tenant_context: MagicMock,
        user_id: uuid.UUID,
    ) -> None:
        """assess_agility scores 1.0 for a fully quantum-safe inventory."""
        service = CryptoAgilityService(repository=mock_repository, publisher=mock_publisher)

        await service.assess_agility(
            scope="all_services",
            crypto_inventory=[
                {"identifier": "key-001", "algorithm": "ML-KEM-1024", "asset_type": "kem"},
                {"identifier": "key-002", "algorithm": "ML-DSA-65", "asset_type": "signature"},
            ],
            assessed_by=user_id,
            tenant=tenant_context,
        )

        call_kwargs = mock_repository.create.call_args.kwargs
        assert call_kwargs["quantum_safe_count"] == 2
        assert call_kwargs["quantum_vulnerable_count"] == 0
        assert call_kwargs["agility_score"] == 1.0

    def test_generate_recommendations_for_vulnerable_assets(self) -> None:
        """_generate_recommendations includes critical action for vulnerable assets."""
        service = CryptoAgilityService(
            repository=MagicMock(),
            publisher=MagicMock(),
        )

        recommendations = service._generate_recommendations(
            quantum_vulnerable_count=5,
            quantum_safe_count=0,
            hybrid_count=0,
            findings=[],
        )

        assert len(recommendations) >= 2
        priorities = [r["priority"] for r in recommendations]
        assert "critical" in priorities


# ---------------------------------------------------------------------------
# HarvestDefenseService tests
# ---------------------------------------------------------------------------


class TestHarvestDefenseService:
    """Tests for HarvestDefenseService."""

    @pytest.fixture
    def mock_repository(self) -> MagicMock:
        """Return a mock harvest risk repository."""
        repo = MagicMock()
        repo.create = AsyncMock(return_value=MagicMock(spec=HarvestRisk, id=uuid.uuid4()))
        repo.list_all = AsyncMock(return_value=[])
        return repo

    def test_risk_score_calculation_high_sensitivity_vulnerable_algorithm(self) -> None:
        """_calculate_risk_score returns high score for secret data with RSA-2048."""
        service = HarvestDefenseService(repository=MagicMock(), publisher=MagicMock())

        score = service._calculate_risk_score(
            data_sensitivity="secret",
            encryption_algorithm="RSA-2048",
            estimated_exposure_years=5,
            quantum_threat_timeline_years=10,
        )

        assert score >= 0.7

    def test_risk_score_calculation_low_sensitivity_safe_algorithm(self) -> None:
        """_calculate_risk_score returns low score for public data with safe algorithm."""
        service = HarvestDefenseService(repository=MagicMock(), publisher=MagicMock())

        score = service._calculate_risk_score(
            data_sensitivity="public",
            encryption_algorithm="AES-256",
            estimated_exposure_years=1,
            quantum_threat_timeline_years=10,
        )

        assert score < 0.4

    def test_classify_risk_level_critical(self) -> None:
        """_classify_risk_level returns 'critical' for scores above threshold."""
        service = HarvestDefenseService(repository=MagicMock(), publisher=MagicMock())
        assert service._classify_risk_level(0.90) == "critical"

    def test_classify_risk_level_low(self) -> None:
        """_classify_risk_level returns 'low' for very low scores."""
        service = HarvestDefenseService(repository=MagicMock(), publisher=MagicMock())
        assert service._classify_risk_level(0.10) == "low"

    async def test_assess_harvest_risk_publishes_event_for_high_risk(
        self,
        mock_repository: MagicMock,
        mock_publisher: QuantumReadinessEventPublisher,
        tenant_context: MagicMock,
        user_id: uuid.UUID,
    ) -> None:
        """assess_harvest_risk publishes an event when risk is critical or high."""
        service = HarvestDefenseService(repository=mock_repository, publisher=mock_publisher)

        await service.assess_harvest_risk(
            asset_type="database",
            asset_identifier="prod-db-001",
            data_sensitivity="secret",
            encryption_algorithm="RSA-2048",
            estimated_exposure_years=5,
            assessed_by=user_id,
            tenant=tenant_context,
        )

        mock_publisher.publish_harvest_risk_identified.assert_called_once()

    async def test_assess_harvest_risk_no_event_for_low_risk(
        self,
        mock_repository: MagicMock,
        mock_publisher: QuantumReadinessEventPublisher,
        tenant_context: MagicMock,
        user_id: uuid.UUID,
    ) -> None:
        """assess_harvest_risk does not publish an event for low-risk assessments."""
        service = HarvestDefenseService(repository=mock_repository, publisher=mock_publisher)

        await service.assess_harvest_risk(
            asset_type="file_store",
            asset_identifier="public-assets",
            data_sensitivity="public",
            encryption_algorithm="AES-256",
            estimated_exposure_years=1,
            assessed_by=user_id,
            tenant=tenant_context,
        )

        mock_publisher.publish_harvest_risk_identified.assert_not_called()


# ---------------------------------------------------------------------------
# KeyExchangeService tests
# ---------------------------------------------------------------------------


class TestKeyExchangeService:
    """Tests for KeyExchangeService."""

    @pytest.fixture
    def mock_repository(self) -> MagicMock:
        """Return a mock key exchange repository."""
        repo = MagicMock()
        exchange = MagicMock(spec=KeyExchange)
        exchange.id = uuid.uuid4()
        repo.create = AsyncMock(return_value=exchange)
        repo.get_by_id = AsyncMock(return_value=exchange)
        return repo

    async def test_initiate_key_exchange_creates_record(
        self,
        mock_repository: MagicMock,
        mock_publisher: QuantumReadinessEventPublisher,
        tenant_context: MagicMock,
        user_id: uuid.UUID,
    ) -> None:
        """initiate_key_exchange creates a record and publishes an event."""
        service = KeyExchangeService(repository=mock_repository, publisher=mock_publisher)

        result = await service.initiate_key_exchange(
            exchange_algorithm="CRYSTALS-Kyber-1024",
            key_encapsulation_mechanism="ML-KEM-1024",
            security_level=5,
            public_key_fingerprint="sha256:abcdef1234567890",
            initiated_by=user_id,
            tenant=tenant_context,
        )

        mock_repository.create.assert_called_once()
        mock_publisher.publish_key_exchange_completed.assert_called_once()
        assert result is not None

    def test_get_kem_parameters_returns_correct_sizes_for_ml_kem_1024(self) -> None:
        """_get_kem_parameters returns correct ciphertext size for ML-KEM-1024."""
        service = KeyExchangeService(repository=MagicMock(), publisher=MagicMock())
        params = service._get_kem_parameters("ML-KEM-1024")
        assert params["ciphertext_size"] == 1568
        assert params["shared_secret_size"] == 32

    def test_get_kem_parameters_returns_defaults_for_unknown(self) -> None:
        """_get_kem_parameters returns zero ciphertext size for unknown algorithms."""
        service = KeyExchangeService(repository=MagicMock(), publisher=MagicMock())
        params = service._get_kem_parameters("UNKNOWN-ALG")
        assert params["ciphertext_size"] == 0


# ---------------------------------------------------------------------------
# ComplianceCheckService tests
# ---------------------------------------------------------------------------


class TestComplianceCheckService:
    """Tests for ComplianceCheckService."""

    @pytest.fixture
    def mock_repository(self) -> MagicMock:
        """Return a mock compliance check repository."""
        repo = MagicMock()
        check = MagicMock(spec=ComplianceCheck)
        check.id = uuid.uuid4()
        repo.create = AsyncMock(return_value=check)
        repo.get_latest = AsyncMock(return_value=check)
        repo.list_all = AsyncMock(return_value=[check])
        return repo

    async def test_run_compliance_check_with_pqc_algorithms(
        self,
        mock_repository: MagicMock,
        mock_publisher: QuantumReadinessEventPublisher,
        tenant_context: MagicMock,
        user_id: uuid.UUID,
    ) -> None:
        """run_compliance_check passes controls for NIST-approved PQC algorithms."""
        service = ComplianceCheckService(repository=mock_repository, publisher=mock_publisher)

        await service.run_compliance_check(
            standard="NIST-PQC",
            standard_version="FIPS-203",
            algorithm_inventory=[
                {"identifier": "kem-001", "algorithm": "ML-KEM-1024"},
                {"identifier": "sig-001", "algorithm": "ML-DSA-65"},
            ],
            checked_by=user_id,
            tenant=tenant_context,
        )

        call_kwargs = mock_repository.create.call_args.kwargs
        assert call_kwargs["controls_passed"] > 0
        assert call_kwargs["overall_status"] in {"compliant", "partial", "non_compliant"}

    async def test_run_compliance_check_with_no_pqc_algorithms(
        self,
        mock_repository: MagicMock,
        mock_publisher: QuantumReadinessEventPublisher,
        tenant_context: MagicMock,
        user_id: uuid.UUID,
    ) -> None:
        """run_compliance_check fails KEM and DSA controls when no PQC algorithms present."""
        service = ComplianceCheckService(repository=mock_repository, publisher=mock_publisher)

        await service.run_compliance_check(
            standard="NIST-PQC",
            standard_version="FIPS-203",
            algorithm_inventory=[
                {"identifier": "key-001", "algorithm": "RSA-2048"},
            ],
            checked_by=user_id,
            tenant=tenant_context,
        )

        call_kwargs = mock_repository.create.call_args.kwargs
        assert call_kwargs["controls_failed"] >= 2
        assert call_kwargs["overall_status"] == "non_compliant"

    async def test_get_compliance_status_returns_latest(
        self,
        mock_repository: MagicMock,
        mock_publisher: QuantumReadinessEventPublisher,
        tenant_context: MagicMock,
    ) -> None:
        """get_compliance_status returns the most recent compliance check."""
        service = ComplianceCheckService(repository=mock_repository, publisher=mock_publisher)

        result = await service.get_compliance_status(tenant=tenant_context)

        mock_repository.get_latest.assert_called_once_with(tenant_context)
        assert result is not None
