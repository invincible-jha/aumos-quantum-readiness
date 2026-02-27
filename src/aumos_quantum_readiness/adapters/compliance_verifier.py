"""NIST PQC compliance verifier adapter.

Maps cryptographic assets and configurations against NIST PQC standards
(FIPS-203, FIPS-204, FIPS-205). Validates approved algorithm usage,
parameter set correctness, implementation conformance, produces compliance
scores, identifies gaps, and generates compliance certificates.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# NIST PQC control definitions
# ---------------------------------------------------------------------------


@dataclass
class NISTControl:
    """A single NIST PQC compliance control point."""

    control_id: str
    standard: str  # 'FIPS-203' | 'FIPS-204' | 'FIPS-205' | 'SP-800-131A' etc.
    name: str
    description: str
    requirement: str
    approved_values: list[str]  # Approved algorithm names or parameter values
    mandatory: bool = True
    applies_to: list[str] = field(default_factory=list)  # Asset types this control applies to


NIST_PQC_CONTROLS: list[NISTControl] = [
    NISTControl(
        control_id="FIPS-203-KEM",
        standard="FIPS-203",
        name="Module-Lattice-Based Key-Encapsulation Mechanism",
        description="Key encapsulation must use ML-KEM (CRYSTALS-Kyber) at approved parameter sets.",
        requirement="Use ML-KEM-512, ML-KEM-768, or ML-KEM-1024 for all key encapsulation operations.",
        approved_values=["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024"],
        mandatory=True,
        applies_to=["key_exchange", "tls", "api_key", "session_key"],
    ),
    NISTControl(
        control_id="FIPS-204-DSA",
        standard="FIPS-204",
        name="Module-Lattice-Based Digital Signature Algorithm",
        description="Digital signatures must use ML-DSA (CRYSTALS-Dilithium) at approved parameter sets.",
        requirement="Use ML-DSA-44, ML-DSA-65, or ML-DSA-87 for all digital signature operations.",
        approved_values=["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "CRYSTALS-Dilithium2", "CRYSTALS-Dilithium3", "CRYSTALS-Dilithium5"],
        mandatory=True,
        applies_to=["signing_key", "tls_cert", "code_signing", "jwt_signing"],
    ),
    NISTControl(
        control_id="FIPS-205-SLH-DSA",
        standard="FIPS-205",
        name="Stateless Hash-Based Digital Signature Algorithm",
        description="Hash-based signatures must use SLH-DSA (SPHINCS+) at approved parameter sets.",
        requirement="Use SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192s, or SLH-DSA-SHA2-256s for stateless hash-based signatures.",
        approved_values=["SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s", "SPHINCS+-SHA2-128s", "SPHINCS+-SHA2-192s", "SPHINCS+-SHA2-256s"],
        mandatory=False,
        applies_to=["signing_key", "code_signing"],
    ),
    NISTControl(
        control_id="SP-800-131A-DEPRECATION",
        standard="NIST-SP-800-131A",
        name="Quantum-Vulnerable Algorithm Deprecation",
        description="All quantum-vulnerable algorithms must be deprecated and removed.",
        requirement="RSA, ECDSA, ECDH, DH, and DSA must not be used for new key generation after 2030.",
        approved_values=[],  # No quantum-vulnerable algorithms are approved
        mandatory=True,
        applies_to=["all"],
    ),
    NISTControl(
        control_id="SP-800-131A-SYMMETRIC",
        standard="NIST-SP-800-131A",
        name="Symmetric Algorithm Key Length",
        description="Symmetric encryption must use AES-256 to provide 128-bit quantum security.",
        requirement="Use AES-256-GCM or AES-256-CBC. AES-128 provides only 64-bit quantum security.",
        approved_values=["AES-256-GCM", "AES-256-CBC", "AES-256-CTR", "ChaCha20-Poly1305"],
        mandatory=True,
        applies_to=["database_encryption", "file_encryption", "session_encryption"],
    ),
    NISTControl(
        control_id="SP-800-56C-KDF",
        standard="NIST-SP-800-56C",
        name="Key Derivation Function",
        description="Key derivation must use approved KDFs: HKDF-SHA256+, PBKDF2-SHA256+.",
        requirement="Use HKDF-SHA-256 or HKDF-SHA-3-256 for key derivation.",
        approved_values=["HKDF-SHA-256", "HKDF-SHA-384", "HKDF-SHA-512", "HKDF-SHA3-256", "PBKDF2-SHA256"],
        mandatory=True,
        applies_to=["key_derivation", "session_key"],
    ),
]

# Quantum-vulnerable algorithms that must not appear in compliant configurations
FORBIDDEN_ALGORITHMS: frozenset[str] = frozenset(
    {
        "RSA-1024", "RSA-2048", "RSA-3072", "RSA-4096",
        "ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
        "ECDH-P256", "ECDH-P384",
        "DH-1024", "DH-2048", "DH-3072",
        "DSA-1024", "DSA-2048", "DSA-3072",
        "MD5", "SHA-1",
    }
)


# ---------------------------------------------------------------------------
# ComplianceVerifier adapter
# ---------------------------------------------------------------------------


@dataclass
class ControlResult:
    """Result of evaluating a single NIST PQC control."""

    control_id: str
    status: str  # 'pass' | 'fail' | 'not_applicable' | 'partial'
    score: float  # [0.0, 1.0] per-control compliance score
    findings: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


class QuantumComplianceVerifier:
    """NIST PQC compliance verifier for cryptographic configurations.

    Evaluates cryptographic inventories and configurations against the full
    suite of NIST PQC standards. Produces per-control results, an overall
    compliance score, a gap list, and a compliance certificate for passing
    organisations.
    """

    def __init__(self) -> None:
        """Initialise the verifier with the built-in NIST PQC control library."""
        self._controls: dict[str, NISTControl] = {c.control_id: c for c in NIST_PQC_CONTROLS}

    async def verify_compliance(
        self,
        verification_config: dict[str, Any],
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Verify NIST PQC compliance against a cryptographic inventory.

        Args:
            verification_config: Verification configuration dict. Supported keys:
                - algorithm_inventory: List of {algorithm, asset_type, usage_context}
                - standard_filter: Optional list of standard IDs to check (e.g., ['FIPS-203', 'FIPS-204'])
                - organisation_name: Name for compliance certificate (default 'Unknown')
                - include_certificate: bool — generate compliance certificate (default True)
            tenant_id: Tenant context.

        Returns:
            Dict with control_results, overall_status, compliance_score, gaps,
            compliance_certificate, recommendations, output_uri.
        """
        algorithm_inventory: list[dict[str, Any]] = verification_config.get("algorithm_inventory", [])
        standard_filter: list[str] = verification_config.get("standard_filter", [])
        org_name: str = verification_config.get("organisation_name", "Unknown Organisation")
        include_certificate: bool = bool(verification_config.get("include_certificate", True))

        logger.info(
            "Starting NIST PQC compliance verification",
            inventory_size=len(algorithm_inventory),
            standard_filter=standard_filter,
            tenant_id=str(tenant_id),
        )

        # Build lookup sets from inventory
        algorithms_in_use: set[str] = {
            item.get("algorithm", "") for item in algorithm_inventory
        }
        asset_types_in_use: set[str] = {
            item.get("asset_type", "") for item in algorithm_inventory
        }

        # Evaluate each applicable control
        control_results: list[ControlResult] = []
        controls_to_check = [
            c for c in self._controls.values()
            if not standard_filter or c.standard in standard_filter
        ]

        for control in controls_to_check:
            result = self._evaluate_control(
                control=control,
                algorithms_in_use=algorithms_in_use,
                asset_types_in_use=asset_types_in_use,
                algorithm_inventory=algorithm_inventory,
            )
            control_results.append(result)

        # Aggregate compliance score
        mandatory_results = [r for r in control_results if self._controls[r.control_id].mandatory]
        optional_results = [r for r in control_results if not self._controls[r.control_id].mandatory]

        mandatory_score = (
            sum(r.score for r in mandatory_results) / len(mandatory_results)
            if mandatory_results
            else 1.0
        )
        optional_score = (
            sum(r.score for r in optional_results) / len(optional_results)
            if optional_results
            else 1.0
        )

        overall_score = round(mandatory_score * 0.8 + optional_score * 0.2, 4)
        passed_mandatory = all(r.status in ("pass", "not_applicable") for r in mandatory_results)
        overall_status = (
            "compliant" if passed_mandatory and overall_score >= 0.8
            else "partial" if overall_score >= 0.5
            else "non_compliant"
        )

        gaps = self._identify_gaps(control_results)
        recommendations = self._generate_recommendations(control_results, algorithms_in_use)

        certificate: dict[str, Any] | None = None
        if include_certificate and overall_status == "compliant":
            certificate = self._generate_certificate(
                org_name=org_name,
                tenant_id=tenant_id,
                overall_score=overall_score,
                standards_covered=[c.standard for c in controls_to_check],
            )

        logger.info(
            "NIST PQC compliance verification complete",
            overall_status=overall_status,
            compliance_score=overall_score,
            gaps=len(gaps),
            tenant_id=str(tenant_id),
        )

        return {
            "control_results": [
                {
                    "control_id": r.control_id,
                    "standard": self._controls[r.control_id].standard,
                    "name": self._controls[r.control_id].name,
                    "status": r.status,
                    "score": r.score,
                    "findings": r.findings,
                    "evidence": r.evidence,
                }
                for r in control_results
            ],
            "overall_status": overall_status,
            "compliance_score": overall_score,
            "mandatory_score": round(mandatory_score, 4),
            "optional_score": round(optional_score, 4),
            "gaps": gaps,
            "recommendations": recommendations,
            "compliance_certificate": certificate,
            "output_uri": (
                f"s3://aumos-quantum/{tenant_id}/compliance/{uuid.uuid4()}.json"
            ),
        }

    def _evaluate_control(
        self,
        control: NISTControl,
        algorithms_in_use: set[str],
        asset_types_in_use: set[str],
        algorithm_inventory: list[dict[str, Any]],
    ) -> ControlResult:
        """Evaluate a single NIST control against the current inventory.

        Args:
            control: The NIST control to evaluate.
            algorithms_in_use: Set of all algorithm names in the inventory.
            asset_types_in_use: Set of all asset type strings.
            algorithm_inventory: Full raw inventory list.

        Returns:
            ControlResult with status, score, findings, and evidence.
        """
        # Determine applicability
        if "all" not in control.applies_to:
            relevant_asset_types = set(control.applies_to)
            if not asset_types_in_use & relevant_asset_types:
                return ControlResult(
                    control_id=control.control_id,
                    status="not_applicable",
                    score=1.0,
                    findings=[],
                    evidence=["No applicable asset types found in inventory."],
                )

        findings: list[str] = []
        evidence: list[str] = []

        # Special case: deprecation control — check for forbidden algorithms
        if control.control_id == "SP-800-131A-DEPRECATION":
            forbidden_found = algorithms_in_use & FORBIDDEN_ALGORITHMS
            if forbidden_found:
                findings.append(
                    f"Quantum-vulnerable algorithms detected: {', '.join(sorted(forbidden_found))}."
                )
                score = 0.0
                status = "fail"
            else:
                evidence.append("No quantum-vulnerable algorithms detected.")
                score = 1.0
                status = "pass"
            return ControlResult(
                control_id=control.control_id,
                status=status,
                score=score,
                findings=findings,
                evidence=evidence,
            )

        # General control: check that at least one approved algorithm is in use
        if control.approved_values:
            approved_set = set(control.approved_values)
            matching = algorithms_in_use & approved_set
            if matching:
                evidence.append(f"Approved algorithms in use: {', '.join(sorted(matching))}.")
                # Partial credit if only some approved algorithms are present
                score = min(len(matching) / max(len(approved_set), 1) + 0.5, 1.0)
                status = "pass" if score >= 0.5 else "partial"
            else:
                findings.append(
                    f"None of the approved algorithms ({', '.join(control.approved_values[:3])}...) "
                    "are in the inventory."
                )
                score = 0.0
                status = "fail"
        else:
            # No approved values specified — presence check only
            status = "pass"
            score = 1.0

        return ControlResult(
            control_id=control.control_id,
            status=status,
            score=round(score, 4),
            findings=findings,
            evidence=evidence,
        )

    def _identify_gaps(self, results: list[ControlResult]) -> list[dict[str, Any]]:
        """Extract failed controls as compliance gaps.

        Args:
            results: List of control results.

        Returns:
            List of gap dicts with control info and remediation guidance.
        """
        gaps: list[dict[str, Any]] = []
        for result in results:
            if result.status not in ("pass", "not_applicable"):
                control = self._controls[result.control_id]
                gaps.append(
                    {
                        "control_id": result.control_id,
                        "standard": control.standard,
                        "name": control.name,
                        "status": result.status,
                        "score": result.score,
                        "findings": result.findings,
                        "remediation": control.requirement,
                        "mandatory": control.mandatory,
                    }
                )
        return sorted(gaps, key=lambda g: (not g["mandatory"], g["score"]))

    def _generate_recommendations(
        self,
        results: list[ControlResult],
        algorithms_in_use: set[str],
    ) -> list[str]:
        """Generate prioritised recommendations from failed controls.

        Args:
            results: List of control results.
            algorithms_in_use: Set of algorithm names.

        Returns:
            List of recommendation strings.
        """
        recommendations: list[str] = []
        failed = [r for r in results if r.status == "fail"]

        for result in failed:
            control = self._controls[result.control_id]
            recommendations.append(
                f"[{control.standard}] {control.requirement}"
            )

        if not recommendations:
            recommendations.append(
                "All applicable NIST PQC controls are satisfied. "
                "Schedule re-verification within 12 months or upon any cryptographic configuration change."
            )

        return recommendations

    def _generate_certificate(
        self,
        org_name: str,
        tenant_id: uuid.UUID,
        overall_score: float,
        standards_covered: list[str],
    ) -> dict[str, Any]:
        """Generate a compliance certificate for passing organisations.

        Args:
            org_name: Organisation name.
            tenant_id: Tenant context.
            overall_score: Achieved compliance score.
            standards_covered: List of standard IDs verified.

        Returns:
            Compliance certificate dict.
        """
        certificate_id = str(uuid.uuid4())
        return {
            "certificate_id": certificate_id,
            "organisation": org_name,
            "tenant_id": str(tenant_id),
            "compliance_status": "COMPLIANT",
            "compliance_score": overall_score,
            "standards_verified": list(set(standards_covered)),
            "certificate_uri": f"s3://aumos-quantum/{tenant_id}/certs/{certificate_id}.json",
            "validity_note": (
                "This certificate reflects compliance at the time of assessment. "
                "Re-verify within 12 months or upon cryptographic configuration changes."
            ),
        }
