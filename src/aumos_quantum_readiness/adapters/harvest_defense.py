"""Harvest-now-decrypt-later (HNDL) defense adapter.

Performs data sensitivity classification, exposure window estimation,
threat timeline modelling, priority data identification, defense strategy
recommendation, risk quantification, and HNDL assessment report generation.

The "harvest now, decrypt later" threat model assumes that adversaries are
already harvesting quantum-vulnerable encrypted data today, expecting to
decrypt it once fault-tolerant quantum computers become available.
"""

import math
import uuid
from dataclasses import dataclass, field
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Sensitivity and threat model constants
# ---------------------------------------------------------------------------


# Expected data shelf life in years — how long data must remain confidential
DATA_SHELF_LIFE_YEARS: dict[str, int] = {
    "public": 0,
    "internal": 2,
    "confidential": 10,
    "secret": 25,
    "top_secret": 50,
}

# Quantum threat maturity timeline models (years from now)
THREAT_TIMELINE_MODELS: dict[str, dict[str, Any]] = {
    "optimistic": {
        "cryptographically_relevant_qc_years": 15,
        "description": "Assumes current NISQ limitations persist; fault-tolerant QC delayed.",
        "confidence": 0.25,
    },
    "baseline": {
        "cryptographically_relevant_qc_years": 10,
        "description": "Mainstream expert consensus as of 2025.",
        "confidence": 0.50,
    },
    "pessimistic": {
        "cryptographically_relevant_qc_years": 5,
        "description": "Rapid progress scenario; well-funded state-actor timeline.",
        "confidence": 0.25,
    },
}

# Quantum-vulnerable algorithm exposure amplifier
ALGORITHM_VULNERABILITY_MULTIPLIER: dict[str, float] = {
    "RSA-1024": 1.0,
    "RSA-2048": 0.95,
    "RSA-3072": 0.85,
    "RSA-4096": 0.80,
    "ECDSA-P256": 0.95,
    "ECDSA-P384": 0.90,
    "ECDSA-P521": 0.85,
    "DH-1024": 1.0,
    "DH-2048": 0.95,
    "ECDH-P256": 0.95,
}

# Sensitivity scores for the composite risk formula
SENSITIVITY_RISK_SCORES: dict[str, float] = {
    "public": 0.0,
    "internal": 0.25,
    "confidential": 0.60,
    "secret": 0.85,
    "top_secret": 1.0,
}


# ---------------------------------------------------------------------------
# HNDL assessment types
# ---------------------------------------------------------------------------


@dataclass
class AssetRisk:
    """Risk assessment for a single data asset."""

    asset_id: str
    asset_type: str
    data_sensitivity: str
    encryption_algorithm: str
    exposure_years: float
    quantum_threat_years: float
    vulnerability_multiplier: float
    exposure_score: float  # [0.0, 1.0]
    sensitivity_score: float  # [0.0, 1.0]
    urgency_score: float  # [0.0, 1.0] — how soon action is needed
    composite_risk_score: float  # [0.0, 1.0]
    risk_level: str  # 'critical' | 'high' | 'medium' | 'low'
    is_already_harvested_likely: bool  # True if exposure > threat timeline
    defense_strategies: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HarvestDefense adapter
# ---------------------------------------------------------------------------


class HarvestDefense:
    """Harvest-now-decrypt-later threat assessment and defense adapter.

    Assesses each cryptographic asset's exposure to the HNDL threat by
    combining data sensitivity, algorithm vulnerability, exposure window,
    and quantum threat timeline. Produces prioritised defense strategies
    and a quantified risk assessment.
    """

    # Risk level thresholds (composite_risk_score)
    RISK_THRESHOLDS: dict[str, float] = {
        "critical": 0.75,
        "high": 0.50,
        "medium": 0.25,
        "low": 0.0,
    }

    async def assess_hndl_risk(
        self,
        assessment_config: dict[str, Any],
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Perform a full HNDL threat assessment for a set of data assets.

        Args:
            assessment_config: Assessment configuration dict. Supported keys:
                - assets: List of asset dicts:
                    {asset_id, asset_type, data_sensitivity, encryption_algorithm,
                     exposure_years, is_internet_facing?, data_volume_gb?}
                - threat_model: 'optimistic' | 'baseline' | 'pessimistic' (default 'baseline')
                - organisation_name: Name for the assessment report
                - include_defense_strategies: bool (default True)
            tenant_id: Tenant context.

        Returns:
            Dict with asset_risks, priority_assets, defense_strategies,
            threat_timeline, risk_summary, assessment_report, output_uri.
        """
        raw_assets: list[dict[str, Any]] = assessment_config.get("assets", [])
        threat_model_key: str = assessment_config.get("threat_model", "baseline")
        org_name: str = assessment_config.get("organisation_name", "Organisation")
        include_defense: bool = bool(assessment_config.get("include_defense_strategies", True))

        threat_model = THREAT_TIMELINE_MODELS.get(
            threat_model_key, THREAT_TIMELINE_MODELS["baseline"]
        )
        quantum_threat_years = float(threat_model["cryptographically_relevant_qc_years"])

        logger.info(
            "Starting HNDL risk assessment",
            num_assets=len(raw_assets),
            threat_model=threat_model_key,
            quantum_threat_years=quantum_threat_years,
            tenant_id=str(tenant_id),
        )

        asset_risks: list[AssetRisk] = []
        for asset_dict in raw_assets:
            risk = self._assess_asset(asset_dict, quantum_threat_years, include_defense)
            asset_risks.append(risk)

        priority_assets = self._identify_priority_assets(asset_risks)
        aggregate_defense = self._aggregate_defense_strategies(asset_risks) if include_defense else []
        threat_timeline = self._model_threat_timeline(threat_model)
        risk_summary = self._build_risk_summary(asset_risks, threat_timeline)
        assessment_report = self._build_assessment_report(
            org_name=org_name,
            tenant_id=tenant_id,
            asset_risks=asset_risks,
            risk_summary=risk_summary,
            threat_model=threat_model,
        )

        logger.info(
            "HNDL assessment complete",
            total_assets=len(asset_risks),
            critical_count=sum(1 for r in asset_risks if r.risk_level == "critical"),
            high_count=sum(1 for r in asset_risks if r.risk_level == "high"),
            tenant_id=str(tenant_id),
        )

        return {
            "asset_risks": [self._risk_to_dict(r) for r in asset_risks],
            "priority_assets": [self._risk_to_dict(r) for r in priority_assets],
            "defense_strategies": aggregate_defense,
            "threat_timeline": threat_timeline,
            "risk_summary": risk_summary,
            "assessment_report": assessment_report,
            "output_uri": (
                f"s3://aumos-quantum/{tenant_id}/harvest-defense/{uuid.uuid4()}.json"
            ),
        }

    def _assess_asset(
        self,
        asset_dict: dict[str, Any],
        quantum_threat_years: float,
        include_defense: bool,
    ) -> AssetRisk:
        """Compute a comprehensive HNDL risk score for a single asset.

        Args:
            asset_dict: Raw asset configuration dict.
            quantum_threat_years: Years until quantum decryption threat.
            include_defense: Whether to populate defense strategies.

        Returns:
            AssetRisk dataclass.
        """
        asset_id = asset_dict.get("asset_id", str(uuid.uuid4()))
        asset_type = asset_dict.get("asset_type", "unknown")
        data_sensitivity = asset_dict.get("data_sensitivity", "internal").lower()
        algorithm = asset_dict.get("encryption_algorithm", "RSA-2048")
        exposure_years = float(asset_dict.get("exposure_years", 1.0))
        is_internet_facing = bool(asset_dict.get("is_internet_facing", False))

        # Score components
        sensitivity_score = SENSITIVITY_RISK_SCORES.get(data_sensitivity, 0.5)
        vuln_multiplier = ALGORITHM_VULNERABILITY_MULTIPLIER.get(algorithm, 0.5)
        shelf_life_years = DATA_SHELF_LIFE_YEARS.get(data_sensitivity, 5)

        # Exposure score: fraction of shelf life already exposed
        exposure_score = min(exposure_years / max(shelf_life_years, 1), 1.0)

        # Urgency score: how close is the quantum threat relative to shelf life
        remaining_life = max(shelf_life_years - exposure_years, 0.0)
        if quantum_threat_years <= 0:
            urgency_score = 1.0
        else:
            urgency_score = min(1.0 - (remaining_life / quantum_threat_years), 1.0)
        urgency_score = max(0.0, urgency_score)

        # Internet-facing assets have elevated exposure
        internet_factor = 1.2 if is_internet_facing else 1.0

        # Composite risk: weighted combination
        composite = (
            sensitivity_score * 0.35
            + exposure_score * 0.25
            + urgency_score * 0.25
            + (vuln_multiplier - 0.5) * 0.15  # contribution from alg vulnerability
        ) * internet_factor
        composite_risk = round(min(max(composite, 0.0), 1.0), 4)

        risk_level = self._classify_risk(composite_risk)
        is_already_harvested_likely = exposure_years >= quantum_threat_years * 0.5

        defense_strategies: list[str] = []
        if include_defense:
            defense_strategies = self._build_defense_strategies(
                sensitivity=data_sensitivity,
                algorithm=algorithm,
                risk_level=risk_level,
                is_internet_facing=is_internet_facing,
            )

        return AssetRisk(
            asset_id=asset_id,
            asset_type=asset_type,
            data_sensitivity=data_sensitivity,
            encryption_algorithm=algorithm,
            exposure_years=exposure_years,
            quantum_threat_years=quantum_threat_years,
            vulnerability_multiplier=vuln_multiplier,
            exposure_score=round(exposure_score, 4),
            sensitivity_score=round(sensitivity_score, 4),
            urgency_score=round(urgency_score, 4),
            composite_risk_score=composite_risk,
            risk_level=risk_level,
            is_already_harvested_likely=is_already_harvested_likely,
            defense_strategies=defense_strategies,
        )

    def _classify_risk(self, composite_risk: float) -> str:
        """Classify a numeric risk score into a named risk level.

        Args:
            composite_risk: Composite risk score in [0.0, 1.0].

        Returns:
            Risk level string.
        """
        for level, threshold in self.RISK_THRESHOLDS.items():
            if composite_risk >= threshold:
                return level
        return "low"

    def _build_defense_strategies(
        self,
        sensitivity: str,
        algorithm: str,
        risk_level: str,
        is_internet_facing: bool,
    ) -> list[str]:
        """Generate asset-specific HNDL defense strategies.

        Args:
            sensitivity: Data sensitivity classification.
            algorithm: Current encryption algorithm.
            risk_level: Assessed risk level.
            is_internet_facing: Whether the asset is externally accessible.

        Returns:
            Ordered list of defense strategy strings.
        """
        strategies: list[str] = []

        if risk_level == "critical":
            strategies.append(
                f"IMMEDIATE: Re-encrypt all data protected by '{algorithm}' "
                "with AES-256-GCM. Initiate PQC migration within 30 days."
            )
            strategies.append(
                "Deploy ML-KEM-1024 (FIPS-203) for all key exchange operations "
                "to prevent further harvest exposure."
            )

        if sensitivity in ("confidential", "secret", "top_secret"):
            strategies.append(
                "Implement data minimisation: archive or delete data no longer "
                "required to reduce the harvest target surface."
            )
            strategies.append(
                "Enable perfect forward secrecy (PFS) with ephemeral PQC key exchange "
                "to limit decryption of past sessions."
            )

        if is_internet_facing:
            strategies.append(
                "Prioritise TLS stack upgrade to hybrid X25519+Kyber cipher suites "
                "to protect new key exchange sessions immediately."
            )

        strategies.append(
            "Enrol in continuous HNDL monitoring: track all encrypted data flows "
            "and flag high-sensitivity assets for priority migration."
        )

        return strategies

    def _identify_priority_assets(self, risks: list[AssetRisk]) -> list[AssetRisk]:
        """Return assets requiring immediate attention.

        Args:
            risks: Full list of assessed asset risks.

        Returns:
            Subset of assets classified as critical or high, sorted by risk score.
        """
        urgent = [r for r in risks if r.risk_level in ("critical", "high")]
        return sorted(urgent, key=lambda r: -r.composite_risk_score)

    def _aggregate_defense_strategies(self, risks: list[AssetRisk]) -> list[dict[str, Any]]:
        """Aggregate per-asset strategies into organisation-level recommendations.

        Args:
            risks: Full list of assessed asset risks.

        Returns:
            List of organisation-level defense strategy dicts.
        """
        critical_count = sum(1 for r in risks if r.risk_level == "critical")
        high_count = sum(1 for r in risks if r.risk_level == "high")

        strategies: list[dict[str, Any]] = [
            {
                "priority": 1,
                "category": "immediate_re_encryption",
                "action": (
                    f"Immediately re-encrypt {critical_count} critical-risk assets "
                    "with AES-256-GCM and initiate PQC key migration."
                ),
                "applies_to_count": critical_count,
                "estimated_effort_days": critical_count * 2,
                "nist_reference": "FIPS-203, NIST-SP-800-131A",
            },
            {
                "priority": 2,
                "category": "pqc_key_exchange_deployment",
                "action": (
                    f"Deploy hybrid X25519+Kyber TLS to protect {high_count + critical_count} "
                    "high/critical assets from further harvest."
                ),
                "applies_to_count": high_count + critical_count,
                "estimated_effort_days": 14,
                "nist_reference": "FIPS-203, NIST-SP-800-227",
            },
            {
                "priority": 3,
                "category": "data_minimisation",
                "action": "Audit and purge data with expired retention requirements to reduce harvest surface.",
                "applies_to_count": len(risks),
                "estimated_effort_days": 5,
                "nist_reference": "NIST-SP-800-53 Rev5 SI-12",
            },
            {
                "priority": 4,
                "category": "monitoring",
                "action": "Deploy automated HNDL monitoring to detect anomalous encrypted data exfiltration.",
                "applies_to_count": len(risks),
                "estimated_effort_days": 7,
                "nist_reference": "NIST-SP-800-137",
            },
        ]
        return strategies

    def _model_threat_timeline(self, threat_model: dict[str, Any]) -> dict[str, Any]:
        """Model the quantum threat timeline with probability weighting.

        Args:
            threat_model: Threat model configuration dict.

        Returns:
            Dict with timeline scenarios and expected value.
        """
        models = list(THREAT_TIMELINE_MODELS.values())
        expected_years = sum(
            m["cryptographically_relevant_qc_years"] * m["confidence"]
            for m in models
        )

        return {
            "threat_model_scenarios": [
                {
                    "name": name,
                    "cryptographically_relevant_qc_years": model["cryptographically_relevant_qc_years"],
                    "description": model["description"],
                    "probability": model["confidence"],
                }
                for name, model in THREAT_TIMELINE_MODELS.items()
            ],
            "expected_threat_years": round(expected_years, 1),
            "harvest_window_already_open": True,
            "recommended_migration_deadline_years": 3,
        }

    def _build_risk_summary(
        self, risks: list[AssetRisk], threat_timeline: dict[str, Any]
    ) -> dict[str, Any]:
        """Build a high-level risk summary across all assessed assets.

        Args:
            risks: Full list of assessed asset risks.
            threat_timeline: Modelled threat timeline.

        Returns:
            Summary statistics dict.
        """
        by_level: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for risk in risks:
            by_level[risk.risk_level] = by_level.get(risk.risk_level, 0) + 1

        already_harvested_likely = sum(1 for r in risks if r.is_already_harvested_likely)
        avg_risk = sum(r.composite_risk_score for r in risks) / max(len(risks), 1)

        return {
            "total_assets_assessed": len(risks),
            "by_risk_level": by_level,
            "assets_likely_already_harvested": already_harvested_likely,
            "average_composite_risk_score": round(avg_risk, 4),
            "immediate_action_required": by_level["critical"] > 0,
            "expected_quantum_threat_years": threat_timeline.get("expected_threat_years", 10),
        }

    def _build_assessment_report(
        self,
        org_name: str,
        tenant_id: uuid.UUID,
        asset_risks: list[AssetRisk],
        risk_summary: dict[str, Any],
        threat_model: dict[str, Any],
    ) -> dict[str, Any]:
        """Produce a structured HNDL assessment report.

        Args:
            org_name: Organisation name.
            tenant_id: Tenant context.
            asset_risks: Full list of assessed asset risks.
            risk_summary: Aggregate risk summary.
            threat_model: Threat model configuration.

        Returns:
            Structured assessment report dict.
        """
        return {
            "report_id": str(uuid.uuid4()),
            "organisation": org_name,
            "tenant_id": str(tenant_id),
            "executive_summary": (
                f"Assessment of {len(asset_risks)} cryptographic assets identified "
                f"{risk_summary['by_risk_level']['critical']} critical and "
                f"{risk_summary['by_risk_level']['high']} high-risk assets exposed to the "
                f"harvest-now-decrypt-later threat. "
                f"Expected quantum threat materialisation: {threat_model['cryptographically_relevant_qc_years']} years."
            ),
            "risk_summary": risk_summary,
            "threat_model": threat_model["description"],
            "compliance_note": (
                "Harvest defense is required under NIST-SP-800-131A and NIST-IR-8547 "
                "as part of the post-quantum cryptography transition mandate."
            ),
        }

    def _risk_to_dict(self, risk: AssetRisk) -> dict[str, Any]:
        """Serialise an AssetRisk to a plain dict.

        Args:
            risk: Asset risk assessment.

        Returns:
            Serialisable dict.
        """
        return {
            "asset_id": risk.asset_id,
            "asset_type": risk.asset_type,
            "data_sensitivity": risk.data_sensitivity,
            "encryption_algorithm": risk.encryption_algorithm,
            "exposure_years": risk.exposure_years,
            "quantum_threat_years": risk.quantum_threat_years,
            "exposure_score": risk.exposure_score,
            "sensitivity_score": risk.sensitivity_score,
            "urgency_score": risk.urgency_score,
            "composite_risk_score": risk.composite_risk_score,
            "risk_level": risk.risk_level,
            "is_already_harvested_likely": risk.is_already_harvested_likely,
            "defense_strategies": risk.defense_strategies,
        }
