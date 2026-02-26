"""Test fixtures for aumos-quantum-readiness."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from aumos_quantum_readiness.adapters.kafka import QuantumReadinessEventPublisher


@pytest.fixture
def tenant_id() -> uuid.UUID:
    """Return a stable test tenant UUID."""
    return uuid.UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture
def user_id() -> uuid.UUID:
    """Return a stable test user UUID."""
    return uuid.UUID("00000000-0000-0000-0000-000000000002")


@pytest.fixture
def tenant_context(tenant_id: uuid.UUID, user_id: uuid.UUID) -> MagicMock:
    """Return a mock TenantContext."""
    context = MagicMock()
    context.tenant_id = tenant_id
    context.user_id = user_id
    return context


@pytest.fixture
def mock_publisher() -> QuantumReadinessEventPublisher:
    """Return a mock event publisher with all methods stubbed."""
    publisher = MagicMock(spec=QuantumReadinessEventPublisher)
    publisher.publish_migration_started = AsyncMock()
    publisher.publish_migration_completed = AsyncMock()
    publisher.publish_agility_assessed = AsyncMock()
    publisher.publish_harvest_risk_identified = AsyncMock()
    publisher.publish_key_exchange_completed = AsyncMock()
    publisher.publish_compliance_checked = AsyncMock()
    return publisher
