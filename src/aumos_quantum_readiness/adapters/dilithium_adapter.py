"""CRYSTALS-Dilithium digital signature adapter (ML-DSA per FIPS-204).

Provides key pair generation (Dilithium-2, 3, 5 / ML-DSA-44, 65, 87),
message signing, signature verification, parameter set selection,
serialisation/deserialisation, benchmark measurement, and certificate
signing support.

Production deployment requires liboqs-python >= 0.10 or pqcrypto library.
All TODO blocks reference the exact liboqs-python API calls to substitute.

CRITICAL SECURITY RULE: Private key bytes must never be logged or persisted
in application logs. Only fingerprints (SHA-256 hex prefix) are safe.
"""

import hashlib
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Dilithium parameter sets
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DilithiumParameters:
    """Immutable Dilithium parameter set descriptor."""

    variant: str  # 'Dilithium-2' | 'Dilithium-3' | 'Dilithium-5'
    nist_security_level: int  # 2 | 3 | 5
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int
    nist_name: str  # 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87'
    fips_reference: str
    seed_bytes: int = 32  # Deterministic signing seed size


DILITHIUM_PARAMETER_SETS: dict[str, DilithiumParameters] = {
    "Dilithium-2": DilithiumParameters(
        variant="Dilithium-2",
        nist_security_level=2,
        public_key_bytes=1312,
        secret_key_bytes=2528,
        signature_bytes=2420,
        nist_name="ML-DSA-44",
        fips_reference="FIPS-204 Section 5 (ML-DSA-44)",
    ),
    "Dilithium-3": DilithiumParameters(
        variant="Dilithium-3",
        nist_security_level=3,
        public_key_bytes=1952,
        secret_key_bytes=4000,
        signature_bytes=3293,
        nist_name="ML-DSA-65",
        fips_reference="FIPS-204 Section 5 (ML-DSA-65)",
    ),
    "Dilithium-5": DilithiumParameters(
        variant="Dilithium-5",
        nist_security_level=5,
        public_key_bytes=2592,
        secret_key_bytes=4864,
        signature_bytes=4595,
        nist_name="ML-DSA-87",
        fips_reference="FIPS-204 Section 5 (ML-DSA-87)",
    ),
}

# Alias mapping: accept ML-DSA names interchangeably
_ALIAS_MAP: dict[str, str] = {
    "ML-DSA-44": "Dilithium-2",
    "ML-DSA-65": "Dilithium-3",
    "ML-DSA-87": "Dilithium-5",
    "CRYSTALS-Dilithium2": "Dilithium-2",
    "CRYSTALS-Dilithium3": "Dilithium-3",
    "CRYSTALS-Dilithium5": "Dilithium-5",
}


def _resolve_variant(variant_name: str) -> str:
    """Resolve alias or canonical Dilithium variant name.

    Args:
        variant_name: Variant name, alias, or NIST name.

    Returns:
        Canonical variant name (e.g., 'Dilithium-3').

    Raises:
        ValueError: If no matching variant is found.
    """
    if variant_name in DILITHIUM_PARAMETER_SETS:
        return variant_name
    resolved = _ALIAS_MAP.get(variant_name)
    if resolved:
        return resolved
    raise ValueError(
        f"Unsupported Dilithium variant: '{variant_name}'. "
        f"Supported: {list(DILITHIUM_PARAMETER_SETS)} + aliases {list(_ALIAS_MAP)}"
    )


def _fingerprint(key_bytes: bytes) -> str:
    """Compute a safe 16-character fingerprint.

    Args:
        key_bytes: Raw key or signature bytes.

    Returns:
        16-character hex prefix of SHA-256.
    """
    return hashlib.sha256(key_bytes).hexdigest()[:16]


def _serialize_public_key(public_key_bytes: bytes, variant: str) -> dict[str, Any]:
    """Serialise a Dilithium public key into a transportable metadata envelope.

    Args:
        public_key_bytes: Raw public key bytes.
        variant: Canonical Dilithium variant name.

    Returns:
        Metadata dict (no raw bytes included in typical response flows).
    """
    params = DILITHIUM_PARAMETER_SETS[variant]
    return {
        "algorithm": "CRYSTALS-Dilithium",
        "nist_name": params.nist_name,
        "variant": params.variant,
        "key_type": "public",
        "size_bytes": params.public_key_bytes,
        "fingerprint": _fingerprint(public_key_bytes),
        "fips_reference": params.fips_reference,
        "security_level": params.nist_security_level,
    }


# ---------------------------------------------------------------------------
# DilithiumAdapter
# ---------------------------------------------------------------------------


class DilithiumAdapter:
    """CRYSTALS-Dilithium digital signature adapter (FIPS-204 ML-DSA).

    Wraps key pair generation, signing, verification, parameter selection,
    certificate signing support, and performance benchmarking behind a
    stable interface.

    Production: replace stub implementations with liboqs-python calls
    (see TODO comments in each method).
    """

    def __init__(self, default_variant: str = "Dilithium-3") -> None:
        """Initialise the adapter with a default Dilithium parameter set.

        Args:
            default_variant: Canonical or alias variant name.

        Raises:
            ValueError: If variant is not supported.
        """
        self._default_variant = _resolve_variant(default_variant)

    async def generate_keypair(
        self,
        variant: str | None = None,
        deterministic_seed: bytes | None = None,
    ) -> dict[str, Any]:
        """Generate a Dilithium signing key pair.

        Args:
            variant: Dilithium variant (canonical name or alias).
            deterministic_seed: Optional 32-byte seed for deterministic key
                generation (FIPS-204 hedged mode). If None, random seed is used.

        Returns:
            Dict with public_key_metadata, public_key_bytes, secret_key_handle,
            parameter_info, and keygen_ms.

        Raises:
            ValueError: If variant is not supported.
        """
        resolved = _resolve_variant(variant) if variant else self._default_variant
        params = DILITHIUM_PARAMETER_SETS[resolved]

        start_time = time.perf_counter()

        if deterministic_seed is not None and len(deterministic_seed) != params.seed_bytes:
            raise ValueError(
                f"Deterministic seed must be {params.seed_bytes} bytes, "
                f"got {len(deterministic_seed)}."
            )

        # TODO: Replace with liboqs-python:
        #   import oqs
        #   sig = oqs.Signature(params.nist_name)
        #   public_key: bytes = sig.generate_keypair()
        #   secret_key: bytes = sig.export_secret_key()
        public_key = os.urandom(params.public_key_bytes)
        secret_key = os.urandom(params.secret_key_bytes)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        logger.info(
            "Dilithium key pair generated",
            variant=resolved,
            nist_name=params.nist_name,
            public_key_fingerprint=_fingerprint(public_key),
            keygen_ms=round(elapsed_ms, 2),
            deterministic=deterministic_seed is not None,
        )

        return {
            "public_key_metadata": _serialize_public_key(public_key, resolved),
            "public_key_bytes": public_key,
            "secret_key_handle": {
                "variant": resolved,
                "fingerprint": _fingerprint(secret_key),
                "size_bytes": params.secret_key_bytes,
                # In production store in aumos-secrets-vault; never log raw bytes
                "_raw_for_test_only": secret_key,
            },
            "parameter_info": {
                "variant": params.variant,
                "nist_name": params.nist_name,
                "security_level": params.nist_security_level,
                "fips_reference": params.fips_reference,
                "signature_bytes": params.signature_bytes,
            },
            "keygen_ms": round(elapsed_ms, 2),
        }

    async def sign(
        self,
        message: bytes,
        secret_key_bytes: bytes,
        variant: str | None = None,
        context: bytes = b"",
    ) -> dict[str, Any]:
        """Sign a message using a Dilithium private key.

        Dilithium signatures are deterministic (randomised internally by the
        library) — no external randomness is required from the caller.

        Args:
            message: Message bytes to sign.
            secret_key_bytes: Signer's private key bytes.
            variant: Dilithium variant matching the key's parameter set.
            context: Optional context string for domain separation (FIPS-204 §5.2).

        Returns:
            Dict with signature_bytes, signature_metadata, sign_ms.

        Raises:
            ValueError: If variant is unsupported or secret key size is wrong.
        """
        resolved = _resolve_variant(variant) if variant else self._default_variant
        params = DILITHIUM_PARAMETER_SETS[resolved]

        if len(secret_key_bytes) != params.secret_key_bytes:
            raise ValueError(
                f"Secret key size mismatch for {resolved}: "
                f"expected {params.secret_key_bytes} bytes, got {len(secret_key_bytes)}."
            )

        start_time = time.perf_counter()

        # TODO: Replace with liboqs-python:
        #   import oqs
        #   sig = oqs.Signature(params.nist_name, secret_key=secret_key_bytes)
        #   signature: bytes = sig.sign(message)
        signature = os.urandom(params.signature_bytes)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        logger.info(
            "Dilithium message signed",
            variant=resolved,
            message_bytes=len(message),
            signature_fingerprint=_fingerprint(signature),
            sign_ms=round(elapsed_ms, 2),
        )

        return {
            "signature_bytes": signature,
            "signature_metadata": {
                "algorithm": "CRYSTALS-Dilithium",
                "nist_name": params.nist_name,
                "variant": resolved,
                "signature_size_bytes": params.signature_bytes,
                "fingerprint": _fingerprint(signature),
                "message_digest": hashlib.sha256(message).hexdigest(),
                "context_used": len(context) > 0,
            },
            "sign_ms": round(elapsed_ms, 2),
        }

    async def verify(
        self,
        message: bytes,
        signature_bytes: bytes,
        public_key_bytes: bytes,
        variant: str | None = None,
        context: bytes = b"",
    ) -> dict[str, Any]:
        """Verify a Dilithium digital signature.

        Args:
            message: Original message bytes.
            signature_bytes: Signature to verify.
            public_key_bytes: Signer's public key bytes.
            variant: Dilithium variant matching the key pair.
            context: Context bytes (must match those used during signing).

        Returns:
            Dict with is_valid, variant, verify_ms, and verification_details.

        Raises:
            ValueError: If variant is unsupported or sizes are wrong.
        """
        resolved = _resolve_variant(variant) if variant else self._default_variant
        params = DILITHIUM_PARAMETER_SETS[resolved]

        if len(public_key_bytes) != params.public_key_bytes:
            raise ValueError(
                f"Public key size mismatch for {resolved}: "
                f"expected {params.public_key_bytes} bytes, got {len(public_key_bytes)}."
            )
        if len(signature_bytes) != params.signature_bytes:
            raise ValueError(
                f"Signature size mismatch for {resolved}: "
                f"expected {params.signature_bytes} bytes, got {len(signature_bytes)}."
            )

        start_time = time.perf_counter()

        # TODO: Replace with liboqs-python:
        #   import oqs
        #   sig = oqs.Signature(params.nist_name)
        #   is_valid: bool = sig.verify(message, signature_bytes, public_key_bytes)
        is_valid = True  # Stub: always valid in test mode

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        logger.info(
            "Dilithium signature verification",
            variant=resolved,
            is_valid=is_valid,
            message_bytes=len(message),
            signature_fingerprint=_fingerprint(signature_bytes),
            public_key_fingerprint=_fingerprint(public_key_bytes),
            verify_ms=round(elapsed_ms, 2),
        )

        return {
            "is_valid": is_valid,
            "variant": resolved,
            "nist_name": params.nist_name,
            "verify_ms": round(elapsed_ms, 2),
            "verification_details": {
                "message_digest": hashlib.sha256(message).hexdigest(),
                "public_key_fingerprint": _fingerprint(public_key_bytes),
                "signature_fingerprint": _fingerprint(signature_bytes),
                "context_used": len(context) > 0,
            },
        }

    async def sign_certificate(
        self,
        certificate_tbs: bytes,
        ca_secret_key_bytes: bytes,
        subject_public_key_bytes: bytes,
        subject_metadata: dict[str, Any],
        variant: str | None = None,
    ) -> dict[str, Any]:
        """Sign a TBS (to-be-signed) certificate with a Dilithium CA key.

        Args:
            certificate_tbs: DER-encoded TBS certificate bytes.
            ca_secret_key_bytes: CA private key bytes.
            subject_public_key_bytes: Subject's Dilithium public key bytes.
            subject_metadata: Dict with subject_cn, validity_days, etc.
            variant: Dilithium variant for the CA key.

        Returns:
            Dict with certificate_metadata, signature_result, cert_fingerprint.
        """
        resolved = _resolve_variant(variant) if variant else self._default_variant
        params = DILITHIUM_PARAMETER_SETS[resolved]

        logger.info(
            "Signing certificate with Dilithium CA key",
            variant=resolved,
            subject_cn=subject_metadata.get("subject_cn", ""),
            validity_days=subject_metadata.get("validity_days", 365),
        )

        sign_result = await self.sign(
            message=certificate_tbs,
            secret_key_bytes=ca_secret_key_bytes,
            variant=resolved,
        )

        cert_fingerprint = hashlib.sha256(
            certificate_tbs + sign_result["signature_bytes"]
        ).hexdigest()[:32]

        return {
            "certificate_metadata": {
                "subject_cn": subject_metadata.get("subject_cn", ""),
                "validity_days": subject_metadata.get("validity_days", 365),
                "signature_algorithm": params.nist_name,
                "fips_reference": params.fips_reference,
                "cert_fingerprint": cert_fingerprint,
                "public_key_fingerprint": _fingerprint(subject_public_key_bytes),
            },
            "signature_result": sign_result,
            "cert_fingerprint": cert_fingerprint,
        }

    async def benchmark(
        self,
        variant: str | None = None,
        iterations: int = 100,
        message_size_bytes: int = 1024,
    ) -> dict[str, Any]:
        """Benchmark key generation, signing, and verification throughput.

        Args:
            variant: Dilithium variant to benchmark.
            iterations: Number of iterations per operation.
            message_size_bytes: Message size for signing/verification benchmarks.

        Returns:
            Dict with keygen_ms, sign_ms, verify_ms (mean over iterations).
        """
        resolved = _resolve_variant(variant) if variant else self._default_variant
        params = DILITHIUM_PARAMETER_SETS[resolved]

        logger.info(
            "Dilithium benchmark starting",
            variant=resolved,
            iterations=iterations,
            message_size=message_size_bytes,
        )

        keygen_times: list[float] = []
        sign_times: list[float] = []
        verify_times: list[float] = []

        for _ in range(iterations):
            t0 = time.perf_counter()
            os.urandom(params.public_key_bytes)
            keygen_times.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            os.urandom(params.signature_bytes)
            sign_times.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            # Stub verification — just hash the message
            hashlib.sha256(os.urandom(message_size_bytes)).digest()
            verify_times.append((time.perf_counter() - t0) * 1000)

        results = {
            "variant": resolved,
            "nist_name": params.nist_name,
            "iterations": iterations,
            "message_size_bytes": message_size_bytes,
            "keygen_mean_ms": round(sum(keygen_times) / iterations, 4),
            "sign_mean_ms": round(sum(sign_times) / iterations, 4),
            "sign_min_ms": round(min(sign_times), 4),
            "sign_max_ms": round(max(sign_times), 4),
            "verify_mean_ms": round(sum(verify_times) / iterations, 4),
            "note": (
                "Benchmark uses stub random operations. Replace with liboqs-python "
                "for realistic performance measurements."
            ),
        }

        logger.info(
            "Dilithium benchmark complete",
            variant=resolved,
            sign_mean_ms=results["sign_mean_ms"],
            verify_mean_ms=results["verify_mean_ms"],
        )
        return results

    def select_variant(
        self,
        min_security_level: int = 3,
        max_signature_bytes: int | None = None,
    ) -> DilithiumParameters:
        """Select the best Dilithium parameter set for given constraints.

        Args:
            min_security_level: Minimum NIST security level (2, 3, or 5).
            max_signature_bytes: Optional upper bound on signature size.

        Returns:
            Best-matching DilithiumParameters.

        Raises:
            ValueError: If no parameter set satisfies the constraints.
        """
        candidates = [
            p for p in DILITHIUM_PARAMETER_SETS.values()
            if p.nist_security_level >= min_security_level
            and (max_signature_bytes is None or p.signature_bytes <= max_signature_bytes)
        ]
        if not candidates:
            raise ValueError(
                f"No Dilithium variant satisfies security_level >= {min_security_level} "
                f"and signature_bytes <= {max_signature_bytes}."
            )
        return max(candidates, key=lambda p: p.nist_security_level)

    def get_parameter_info(self, variant: str | None = None) -> dict[str, Any]:
        """Return parameter information for a Dilithium variant.

        Args:
            variant: Canonical or alias variant name (defaults to adapter default).

        Returns:
            Parameter info dict.

        Raises:
            ValueError: If variant is not supported.
        """
        resolved = _resolve_variant(variant) if variant else self._default_variant
        params = DILITHIUM_PARAMETER_SETS[resolved]
        return {
            "variant": params.variant,
            "nist_name": params.nist_name,
            "nist_security_level": params.nist_security_level,
            "public_key_bytes": params.public_key_bytes,
            "secret_key_bytes": params.secret_key_bytes,
            "signature_bytes": params.signature_bytes,
            "fips_reference": params.fips_reference,
            "aliases": [
                alias for alias, canonical in _ALIAS_MAP.items()
                if canonical == resolved
            ],
        }
