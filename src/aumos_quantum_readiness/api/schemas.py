"""Pydantic request/response schemas for aumos-quantum-readiness.

All API inputs and outputs are validated through these models.
No raw dicts are returned from API endpoints.
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# PQC Migration schemas
# ---------------------------------------------------------------------------


class PQCMigrationRequest(BaseModel):
    """Request body for starting a PQC migration."""

    algorithm_from: str = Field(..., description="Current (potentially vulnerable) algorithm", min_length=1, max_length=100)
    algorithm_to: str = Field(..., description="Target PQC-safe algorithm", min_length=1, max_length=100)
    asset_type: str = Field(..., description="Type of cryptographic asset", min_length=1, max_length=100)
    asset_identifier: str = Field(..., description="Unique identifier for the asset", min_length=1, max_length=500)
    migration_metadata: dict[str, Any] = Field(default_factory=dict, description="Additional migration context")


class PQCMigrationResponse(BaseModel):
    """Response body for PQC migration operations."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    algorithm_from: str
    algorithm_to: str
    status: str
    asset_type: str
    asset_identifier: str
    migration_metadata: dict[str, Any]
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    initiated_by: uuid.UUID
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Crypto-agility schemas
# ---------------------------------------------------------------------------


class CryptoAsset(BaseModel):
    """Individual cryptographic asset for inventory assessment."""

    identifier: str = Field(..., description="Asset identifier", min_length=1)
    algorithm: str = Field(..., description="Current cryptographic algorithm in use", min_length=1)
    asset_type: str = Field(default="unknown", description="Type of asset")


class AgilityAssessmentRequest(BaseModel):
    """Request body for a crypto-agility assessment."""

    scope: str = Field(..., description="Assessment scope (e.g., 'all_services', 'payment_api')", min_length=1, max_length=255)
    crypto_inventory: list[CryptoAsset] = Field(..., description="List of cryptographic assets to assess", min_length=1)


class AgilityAssessmentResponse(BaseModel):
    """Response body for crypto-agility assessment."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    scope: str
    agility_score: float
    quantum_vulnerable_count: int
    quantum_safe_count: int
    hybrid_count: int
    findings: dict[str, Any]
    recommendations: dict[str, Any]
    migration_plan: dict[str, Any]
    assessed_by: uuid.UUID
    created_at: datetime
    updated_at: datetime


class MigrationPlanResponse(BaseModel):
    """Response body for the migration plan endpoint."""

    assessment_id: uuid.UUID
    scope: str
    agility_score: float
    migration_plan: dict[str, Any]
    recommendations: dict[str, Any]
    created_at: datetime


# ---------------------------------------------------------------------------
# Harvest defense schemas
# ---------------------------------------------------------------------------


class HarvestAssessmentRequest(BaseModel):
    """Request body for a harvest-now-decrypt-later risk assessment."""

    asset_type: str = Field(..., description="Type of data asset", min_length=1, max_length=100)
    asset_identifier: str = Field(..., description="Unique identifier for the asset", min_length=1, max_length=500)
    data_sensitivity: str = Field(..., description="Data sensitivity level", pattern="^(public|internal|confidential|secret)$")
    encryption_algorithm: str = Field(..., description="Current encryption algorithm", min_length=1, max_length=100)
    estimated_exposure_years: int = Field(..., description="Years the data has been externally exposed", ge=0, le=100)
    quantum_threat_timeline_years: int = Field(default=10, description="Estimated years until quantum decryption threat", ge=1, le=50)
    risk_details: dict[str, Any] = Field(default_factory=dict, description="Additional risk context")


class HarvestRiskResponse(BaseModel):
    """Response body for harvest risk records."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    asset_type: str
    asset_identifier: str
    risk_level: str
    risk_score: float
    data_sensitivity: str
    encryption_algorithm: str
    estimated_exposure_years: int
    quantum_threat_timeline_years: int
    mitigation_status: str
    risk_details: dict[str, Any]
    assessed_by: uuid.UUID
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Key exchange schemas
# ---------------------------------------------------------------------------


class KeyExchangeRequest(BaseModel):
    """Request body for initiating a quantum-safe key exchange."""

    exchange_algorithm: str = Field(..., description="Key exchange algorithm", min_length=1, max_length=100)
    key_encapsulation_mechanism: str = Field(..., description="KEM variant (e.g., ML-KEM-1024)", min_length=1, max_length=100)
    security_level: int = Field(..., description="NIST security level (1, 3, or 5)", ge=1, le=5)
    public_key_fingerprint: str = Field(..., description="Fingerprint of recipient public key", min_length=1, max_length=512)
    is_hybrid: bool = Field(default=False, description="Use hybrid classical+PQC mode")
    hybrid_classical_algorithm: str | None = Field(default=None, description="Classical algorithm for hybrid mode", max_length=100)
    exchange_metadata: dict[str, Any] = Field(default_factory=dict, description="Additional exchange context")
    expires_at: datetime | None = Field(default=None, description="Optional key exchange expiry")


class KeyExchangeResponse(BaseModel):
    """Response body for key exchange operations."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    exchange_algorithm: str
    key_encapsulation_mechanism: str
    security_level: int
    public_key_fingerprint: str
    ciphertext_size_bytes: int
    shared_secret_size_bytes: int
    is_hybrid: bool
    hybrid_classical_algorithm: str | None
    exchange_metadata: dict[str, Any]
    expires_at: datetime | None
    initiated_by: uuid.UUID
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Compliance schemas
# ---------------------------------------------------------------------------


class ComplianceCheckRequest(BaseModel):
    """Request body for running a NIST PQC compliance check."""

    standard: str = Field(default="NIST-PQC", description="Compliance standard to check against", min_length=1, max_length=100)
    standard_version: str = Field(default="FIPS-203", description="Standard version", min_length=1, max_length=50)
    algorithm_inventory: list[CryptoAsset] = Field(..., description="Current cryptographic algorithms in use", min_length=1)


class ComplianceFinding(BaseModel):
    """Individual compliance finding."""

    control: str
    status: str
    detail: str


class ComplianceCheckResponse(BaseModel):
    """Response body for compliance check operations."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    standard: str
    standard_version: str
    overall_status: str
    compliance_score: float
    controls_passed: int
    controls_failed: int
    controls_not_applicable: int
    findings: list[dict[str, Any]]
    remediation_plan: dict[str, Any]
    next_review_date: datetime | None
    checked_by: uuid.UUID
    created_at: datetime
    updated_at: datetime
