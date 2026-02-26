"""SQLAlchemy ORM models for aumos-quantum-readiness.

All tenant-scoped tables extend AumOSModel which provides:
  - id: UUID primary key
  - tenant_id: UUID (RLS-enforced)
  - created_at: datetime
  - updated_at: datetime

Table naming convention: qrd_{table_name}
"""

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aumos_common.database import AumOSModel


class PQCMigration(AumOSModel):
    """Tracks post-quantum cryptography migration records.

    Table: qrd_migrations
    """

    __tablename__ = "qrd_migrations"

    algorithm_from: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    algorithm_to: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending", index=True)
    asset_type: Mapped[str] = mapped_column(String(100), nullable=False)
    asset_identifier: Mapped[str] = mapped_column(String(500), nullable=False)
    migration_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    initiated_by: Mapped[uuid.UUID] = mapped_column(nullable=False)


class AgilityAssessment(AumOSModel):
    """Stores crypto-agility assessment results.

    Table: qrd_agility_assessments
    """

    __tablename__ = "qrd_agility_assessments"

    scope: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    agility_score: Mapped[float] = mapped_column(Float, nullable=False)
    quantum_vulnerable_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    quantum_safe_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hybrid_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    recommendations: Mapped[dict] = mapped_column(JSON, nullable=False, default=list)
    migration_plan: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    assessed_by: Mapped[uuid.UUID] = mapped_column(nullable=False)


class HarvestRisk(AumOSModel):
    """Records harvest-now-decrypt-later risk assessments.

    Table: qrd_harvest_risks
    """

    __tablename__ = "qrd_harvest_risks"

    asset_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    asset_identifier: Mapped[str] = mapped_column(String(500), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    data_sensitivity: Mapped[str] = mapped_column(String(50), nullable=False)
    encryption_algorithm: Mapped[str] = mapped_column(String(100), nullable=False)
    estimated_exposure_years: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    quantum_threat_timeline_years: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    mitigation_status: Mapped[str] = mapped_column(String(50), nullable=False, default="unmitigated")
    risk_details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    assessed_by: Mapped[uuid.UUID] = mapped_column(nullable=False)


class KeyExchange(AumOSModel):
    """Records quantum-safe key exchange operations.

    Table: qrd_key_exchanges
    """

    __tablename__ = "qrd_key_exchanges"

    exchange_algorithm: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    key_encapsulation_mechanism: Mapped[str] = mapped_column(String(100), nullable=False)
    security_level: Mapped[int] = mapped_column(Integer, nullable=False)
    public_key_fingerprint: Mapped[str] = mapped_column(String(512), nullable=False)
    ciphertext_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    shared_secret_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hybrid_classical_algorithm: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_hybrid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    exchange_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    expires_at: Mapped[datetime | None] = mapped_column(nullable=True)
    initiated_by: Mapped[uuid.UUID] = mapped_column(nullable=False)


class ComplianceCheck(AumOSModel):
    """Tracks NIST PQC compliance check results.

    Table: qrd_compliance_checks
    """

    __tablename__ = "qrd_compliance_checks"

    standard: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    standard_version: Mapped[str] = mapped_column(String(50), nullable=False)
    overall_status: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    compliance_score: Mapped[float] = mapped_column(Float, nullable=False)
    controls_passed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    controls_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    controls_not_applicable: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings: Mapped[dict] = mapped_column(JSON, nullable=False, default=list)
    remediation_plan: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    next_review_date: Mapped[datetime | None] = mapped_column(nullable=True)
    checked_by: Mapped[uuid.UUID] = mapped_column(nullable=False)


__all__ = [
    "PQCMigration",
    "AgilityAssessment",
    "HarvestRisk",
    "KeyExchange",
    "ComplianceCheck",
]
