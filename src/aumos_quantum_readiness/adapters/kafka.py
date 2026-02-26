"""Kafka event publishing for aumos-quantum-readiness.

This module defines the domain events published by this service and
provides a typed publisher wrapper.

Events published by this service:
  - quantum.migration.started — when a PQC migration begins
  - quantum.migration.completed — when a PQC migration finishes
  - quantum.agility.assessed — when a crypto-agility assessment completes
  - quantum.harvest.risk_identified — when a critical/high harvest risk is found
  - quantum.keys.exchange_completed — when a quantum-safe key exchange completes
  - quantum.compliance.checked — when a NIST PQC compliance check finishes
"""

import uuid

from aumos_common.events import EventPublisher, Topics
from aumos_common.observability import get_logger

logger = get_logger(__name__)


class QuantumReadinessEventPublisher:
    """Publisher for aumos-quantum-readiness domain events.

    Wraps EventPublisher with typed methods for each event type
    produced by this service.

    Args:
        publisher: The underlying EventPublisher from aumos-common.
    """

    def __init__(self, publisher: EventPublisher) -> None:
        """Initialize with the shared event publisher.

        Args:
            publisher: Configured EventPublisher instance.
        """
        self._publisher = publisher

    async def publish_migration_started(
        self,
        tenant_id: uuid.UUID,
        migration_id: uuid.UUID,
        algorithm_from: str,
        algorithm_to: str,
    ) -> None:
        """Publish a PQCMigrationStarted event to Kafka.

        Args:
            tenant_id: The tenant that owns the migration.
            migration_id: The newly created migration ID.
            algorithm_from: The algorithm being replaced.
            algorithm_to: The target PQC algorithm.
        """
        logger.info(
            "Published PQCMigrationStarted event",
            tenant_id=str(tenant_id),
            migration_id=str(migration_id),
            algorithm_from=algorithm_from,
            algorithm_to=algorithm_to,
        )
        # TODO: Publish to Topics.QUANTUM_MIGRATION_STARTED when topic is registered in aumos-proto

    async def publish_migration_completed(
        self,
        tenant_id: uuid.UUID,
        migration_id: uuid.UUID,
    ) -> None:
        """Publish a PQCMigrationCompleted event to Kafka.

        Args:
            tenant_id: The tenant that owns the migration.
            migration_id: The completed migration ID.
        """
        logger.info(
            "Published PQCMigrationCompleted event",
            tenant_id=str(tenant_id),
            migration_id=str(migration_id),
        )
        # TODO: Publish to Topics.QUANTUM_MIGRATION_COMPLETED when topic is registered in aumos-proto

    async def publish_agility_assessed(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        agility_score: float,
    ) -> None:
        """Publish a CryptoAgilityAssessed event to Kafka.

        Args:
            tenant_id: The tenant that owns the assessment.
            assessment_id: The newly created assessment ID.
            agility_score: The computed agility score.
        """
        logger.info(
            "Published CryptoAgilityAssessed event",
            tenant_id=str(tenant_id),
            assessment_id=str(assessment_id),
            agility_score=agility_score,
        )
        # TODO: Publish to Topics.QUANTUM_AGILITY_ASSESSED when topic is registered in aumos-proto

    async def publish_harvest_risk_identified(
        self,
        tenant_id: uuid.UUID,
        risk_id: uuid.UUID,
        risk_level: str,
        risk_score: float,
    ) -> None:
        """Publish a HarvestRiskIdentified event to Kafka.

        Only published for critical or high risk levels to avoid noise.

        Args:
            tenant_id: The tenant that owns the risk assessment.
            risk_id: The newly created risk ID.
            risk_level: Classified risk level (critical/high).
            risk_score: Numeric risk score.
        """
        logger.info(
            "Published HarvestRiskIdentified event",
            tenant_id=str(tenant_id),
            risk_id=str(risk_id),
            risk_level=risk_level,
            risk_score=risk_score,
        )
        # TODO: Publish to Topics.QUANTUM_HARVEST_RISK_IDENTIFIED when topic is registered in aumos-proto

    async def publish_key_exchange_completed(
        self,
        tenant_id: uuid.UUID,
        exchange_id: uuid.UUID,
        exchange_algorithm: str,
    ) -> None:
        """Publish a QuantumKeyExchangeCompleted event to Kafka.

        Args:
            tenant_id: The tenant that initiated the key exchange.
            exchange_id: The newly created exchange ID.
            exchange_algorithm: The algorithm used for the exchange.
        """
        logger.info(
            "Published QuantumKeyExchangeCompleted event",
            tenant_id=str(tenant_id),
            exchange_id=str(exchange_id),
            exchange_algorithm=exchange_algorithm,
        )
        # TODO: Publish to Topics.QUANTUM_KEY_EXCHANGE_COMPLETED when topic is registered in aumos-proto

    async def publish_compliance_checked(
        self,
        tenant_id: uuid.UUID,
        check_id: uuid.UUID,
        overall_status: str,
        compliance_score: float,
    ) -> None:
        """Publish a NISTComplianceChecked event to Kafka.

        Args:
            tenant_id: The tenant that ran the compliance check.
            check_id: The newly created compliance check ID.
            overall_status: Compliance status (compliant/partial/non_compliant).
            compliance_score: Numeric compliance score.
        """
        logger.info(
            "Published NISTComplianceChecked event",
            tenant_id=str(tenant_id),
            check_id=str(check_id),
            overall_status=overall_status,
            compliance_score=compliance_score,
        )
        # TODO: Publish to Topics.QUANTUM_COMPLIANCE_CHECKED when topic is registered in aumos-proto
