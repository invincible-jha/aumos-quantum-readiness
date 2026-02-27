"""CRYSTALS-Kyber KEM adapter (ML-KEM per FIPS-203).

Provides key pair generation (Kyber-512, 768, 1024), encapsulation,
decapsulation, parameter set selection, serialisation/deserialisation,
benchmark measurement, and integration points with TLS and homomorphic
encryption workflows.

Production deployment requires liboqs-python >= 0.10 or pqcrypto library.
All TODO blocks reference the exact liboqs-python API calls to substitute.

CRITICAL SECURITY RULE: Private key bytes must never be logged.
Only fingerprints (SHA-256 hex prefix) are safe to persist or log.
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
# Kyber parameter sets
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KyberParameters:
    """Immutable Kyber parameter set descriptor."""

    variant: str  # 'Kyber-512' | 'Kyber-768' | 'Kyber-1024'
    nist_security_level: int  # 1 | 3 | 5
    public_key_bytes: int
    secret_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int
    nist_name: str  # ML-KEM-512 | ML-KEM-768 | ML-KEM-1024
    fips_reference: str


KYBER_PARAMETER_SETS: dict[str, KyberParameters] = {
    "Kyber-512": KyberParameters(
        variant="Kyber-512",
        nist_security_level=1,
        public_key_bytes=800,
        secret_key_bytes=1632,
        ciphertext_bytes=768,
        shared_secret_bytes=32,
        nist_name="ML-KEM-512",
        fips_reference="FIPS-203 Section 6 (Parameter Set 1)",
    ),
    "Kyber-768": KyberParameters(
        variant="Kyber-768",
        nist_security_level=3,
        public_key_bytes=1184,
        secret_key_bytes=2400,
        ciphertext_bytes=1088,
        shared_secret_bytes=32,
        nist_name="ML-KEM-768",
        fips_reference="FIPS-203 Section 6 (Parameter Set 3)",
    ),
    "Kyber-1024": KyberParameters(
        variant="Kyber-1024",
        nist_security_level=5,
        public_key_bytes=1568,
        secret_key_bytes=3168,
        ciphertext_bytes=1568,
        shared_secret_bytes=32,
        nist_name="ML-KEM-1024",
        fips_reference="FIPS-203 Section 6 (Parameter Set 5)",
    ),
}


def _fingerprint(key_bytes: bytes) -> str:
    """Compute a safe 16-character fingerprint from key bytes.

    Args:
        key_bytes: Raw key material.

    Returns:
        16-character hex fingerprint of SHA-256(key_bytes).
    """
    return hashlib.sha256(key_bytes).hexdigest()[:16]


def _serialize_key(key_bytes: bytes, key_type: str, variant: str) -> dict[str, Any]:
    """Wrap key bytes in a metadata envelope for transport.

    Args:
        key_bytes: Raw key bytes.
        key_type: 'public' | 'ciphertext'.  (Private keys are never serialised.)
        variant: Kyber variant name.

    Returns:
        Metadata dict with algorithm, variant, size_bytes, fingerprint.
        Does NOT include raw key bytes to prevent accidental logging.
    """
    params = KYBER_PARAMETER_SETS[variant]
    return {
        "algorithm": "CRYSTALS-Kyber",
        "nist_name": params.nist_name,
        "variant": variant,
        "key_type": key_type,
        "size_bytes": len(key_bytes),
        "fingerprint": _fingerprint(key_bytes),
        "fips_reference": params.fips_reference,
    }


# ---------------------------------------------------------------------------
# KyberAdapter
# ---------------------------------------------------------------------------


class KyberAdapter:
    """CRYSTALS-Kyber Key Encapsulation Mechanism adapter.

    Wraps key pair generation, encapsulation, decapsulation, serialisation,
    and benchmarking operations behind a stable interface.

    Production: replace stub implementations with liboqs-python calls
    (see TODO comments in each method).
    """

    def __init__(self, default_variant: str = "Kyber-1024") -> None:
        """Initialise the adapter with a default Kyber parameter set.

        Args:
            default_variant: Default variant name.

        Raises:
            ValueError: If default_variant is not a supported Kyber variant.
        """
        if default_variant not in KYBER_PARAMETER_SETS:
            raise ValueError(
                f"Unsupported Kyber variant: {default_variant}. "
                f"Supported: {list(KYBER_PARAMETER_SETS)}"
            )
        self._default_variant = default_variant

    async def generate_keypair(
        self,
        variant: str | None = None,
    ) -> dict[str, Any]:
        """Generate a Kyber key pair for the specified parameter set.

        Args:
            variant: Kyber variant ('Kyber-512', 'Kyber-768', 'Kyber-1024').
                Defaults to the adapter's default_variant.

        Returns:
            Dict with public_key_metadata (safe to log/store), secret_key_handle
            (opaque reference — never log raw bytes), and parameter_info.

        Raises:
            ValueError: If variant is not supported.
        """
        resolved_variant = variant or self._default_variant
        if resolved_variant not in KYBER_PARAMETER_SETS:
            raise ValueError(f"Unsupported Kyber variant: {resolved_variant}")

        params = KYBER_PARAMETER_SETS[resolved_variant]

        start_time = time.perf_counter()

        # TODO: Replace with liboqs-python:
        #   import oqs
        #   kem = oqs.KeyEncapsulation(params.nist_name)
        #   public_key: bytes = kem.generate_keypair()
        #   secret_key: bytes = kem.export_secret_key()
        public_key = os.urandom(params.public_key_bytes)
        secret_key = os.urandom(params.secret_key_bytes)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        logger.info(
            "Kyber key pair generated",
            variant=resolved_variant,
            nist_name=params.nist_name,
            public_key_fingerprint=_fingerprint(public_key),
            keygen_ms=round(elapsed_ms, 2),
            # NEVER log secret_key
        )

        # Expose public key metadata only; return secret key as an opaque dict
        # In production, secret_key would be stored in aumos-secrets-vault, not returned raw
        return {
            "public_key_metadata": _serialize_key(public_key, "public", resolved_variant),
            "public_key_bytes": public_key,  # Safe to transmit
            "secret_key_handle": {
                "variant": resolved_variant,
                "fingerprint": _fingerprint(secret_key),
                "size_bytes": params.secret_key_bytes,
                # Raw bytes omitted — store in secrets vault in production
                "_raw_for_test_only": secret_key,
            },
            "parameter_info": {
                "variant": params.variant,
                "nist_name": params.nist_name,
                "security_level": params.nist_security_level,
                "fips_reference": params.fips_reference,
            },
            "keygen_ms": round(elapsed_ms, 2),
        }

    async def encapsulate(
        self,
        public_key_bytes: bytes,
        variant: str | None = None,
    ) -> dict[str, Any]:
        """Encapsulate a shared secret using a Kyber public key.

        The sender calls this method with the recipient's public key. The
        resulting ciphertext is sent to the recipient; the shared secret
        is used locally to derive session key material.

        Args:
            public_key_bytes: Recipient's Kyber public key bytes.
            variant: Kyber variant matching the public key's parameter set.

        Returns:
            Dict with ciphertext_metadata, ciphertext_bytes, shared_secret_fingerprint.
            Shared secret raw bytes are not returned — derive keys via HKDF immediately.

        Raises:
            ValueError: If variant is not supported or public key size is wrong.
        """
        resolved_variant = variant or self._default_variant
        params = KYBER_PARAMETER_SETS.get(resolved_variant)
        if params is None:
            raise ValueError(f"Unsupported Kyber variant: {resolved_variant}")

        if len(public_key_bytes) != params.public_key_bytes:
            raise ValueError(
                f"Public key size mismatch for {resolved_variant}: "
                f"expected {params.public_key_bytes} bytes, got {len(public_key_bytes)}."
            )

        start_time = time.perf_counter()

        # TODO: Replace with liboqs-python:
        #   import oqs
        #   kem = oqs.KeyEncapsulation(params.nist_name)
        #   ciphertext: bytes
        #   shared_secret: bytes
        #   ciphertext, shared_secret = kem.encap_secret(public_key_bytes)
        ciphertext = os.urandom(params.ciphertext_bytes)
        shared_secret = os.urandom(params.shared_secret_bytes)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        logger.info(
            "Kyber encapsulation complete",
            variant=resolved_variant,
            ciphertext_fingerprint=_fingerprint(ciphertext),
            secret_fingerprint=_fingerprint(shared_secret),
            encap_ms=round(elapsed_ms, 2),
        )

        return {
            "ciphertext_metadata": _serialize_key(ciphertext, "ciphertext", resolved_variant),
            "ciphertext_bytes": ciphertext,
            "shared_secret_fingerprint": _fingerprint(shared_secret),
            "shared_secret_size_bytes": params.shared_secret_bytes,
            "encap_ms": round(elapsed_ms, 2),
            # NOTE: In production derive TLS keys from shared_secret via HKDF immediately;
            # do not persist or return shared_secret_bytes.
        }

    async def decapsulate(
        self,
        secret_key_bytes: bytes,
        ciphertext_bytes: bytes,
        variant: str | None = None,
    ) -> dict[str, Any]:
        """Decapsulate a shared secret from a Kyber ciphertext.

        The recipient calls this method with their private key and the received
        ciphertext to recover the same shared secret the sender derived.

        Args:
            secret_key_bytes: Recipient's Kyber private key bytes.
            ciphertext_bytes: Ciphertext bytes received from the sender.
            variant: Kyber variant matching the key pair's parameter set.

        Returns:
            Dict with shared_secret_fingerprint and decap_ms.
            Shared secret raw bytes are NOT returned — use HKDF immediately in production.

        Raises:
            ValueError: If variant is unsupported or sizes are wrong.
        """
        resolved_variant = variant or self._default_variant
        params = KYBER_PARAMETER_SETS.get(resolved_variant)
        if params is None:
            raise ValueError(f"Unsupported Kyber variant: {resolved_variant}")

        if len(secret_key_bytes) != params.secret_key_bytes:
            raise ValueError(
                f"Secret key size mismatch for {resolved_variant}: "
                f"expected {params.secret_key_bytes} bytes, got {len(secret_key_bytes)}."
            )
        if len(ciphertext_bytes) != params.ciphertext_bytes:
            raise ValueError(
                f"Ciphertext size mismatch for {resolved_variant}: "
                f"expected {params.ciphertext_bytes} bytes, got {len(ciphertext_bytes)}."
            )

        start_time = time.perf_counter()

        # TODO: Replace with liboqs-python:
        #   import oqs
        #   kem = oqs.KeyEncapsulation(params.nist_name, secret_key=secret_key_bytes)
        #   shared_secret: bytes = kem.decap_secret(ciphertext_bytes)
        shared_secret = os.urandom(params.shared_secret_bytes)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        logger.info(
            "Kyber decapsulation complete",
            variant=resolved_variant,
            secret_fingerprint=_fingerprint(shared_secret),
            decap_ms=round(elapsed_ms, 2),
            # NEVER log secret_key_bytes or shared_secret raw bytes
        )

        return {
            "shared_secret_fingerprint": _fingerprint(shared_secret),
            "shared_secret_size_bytes": params.shared_secret_bytes,
            "decap_ms": round(elapsed_ms, 2),
            "success": True,
        }

    async def benchmark(
        self,
        variant: str | None = None,
        iterations: int = 100,
    ) -> dict[str, Any]:
        """Benchmark key generation, encapsulation, and decapsulation throughput.

        Args:
            variant: Kyber variant to benchmark.
            iterations: Number of iterations per operation (default 100).

        Returns:
            Dict with keygen_ms, encap_ms, decap_ms (mean over iterations).
        """
        resolved_variant = variant or self._default_variant
        params = KYBER_PARAMETER_SETS.get(resolved_variant)
        if params is None:
            raise ValueError(f"Unsupported Kyber variant: {resolved_variant}")

        logger.info(
            "Kyber benchmark starting",
            variant=resolved_variant,
            iterations=iterations,
        )

        keygen_times: list[float] = []
        encap_times: list[float] = []
        decap_times: list[float] = []

        for _ in range(iterations):
            t0 = time.perf_counter()
            public_key = os.urandom(params.public_key_bytes)
            secret_key = os.urandom(params.secret_key_bytes)
            keygen_times.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            ciphertext = os.urandom(params.ciphertext_bytes)
            encap_times.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            _ = os.urandom(params.shared_secret_bytes)
            decap_times.append((time.perf_counter() - t0) * 1000)

        results = {
            "variant": resolved_variant,
            "nist_name": params.nist_name,
            "iterations": iterations,
            "keygen_mean_ms": round(sum(keygen_times) / iterations, 4),
            "keygen_min_ms": round(min(keygen_times), 4),
            "keygen_max_ms": round(max(keygen_times), 4),
            "encap_mean_ms": round(sum(encap_times) / iterations, 4),
            "decap_mean_ms": round(sum(decap_times) / iterations, 4),
            "note": (
                "Benchmark uses stub random operations. Replace with liboqs-python "
                "for realistic performance measurements."
            ),
        }

        logger.info(
            "Kyber benchmark complete",
            variant=resolved_variant,
            keygen_mean_ms=results["keygen_mean_ms"],
            encap_mean_ms=results["encap_mean_ms"],
        )
        return results

    def select_variant(
        self,
        min_security_level: int = 3,
        max_public_key_bytes: int | None = None,
    ) -> KyberParameters:
        """Select the best Kyber parameter set for given constraints.

        Args:
            min_security_level: Minimum NIST security level (1, 3, or 5).
            max_public_key_bytes: Optional upper bound on public key size.

        Returns:
            The best-matching KyberParameters instance.

        Raises:
            ValueError: If no parameter set satisfies the constraints.
        """
        candidates = [
            p for p in KYBER_PARAMETER_SETS.values()
            if p.nist_security_level >= min_security_level
            and (max_public_key_bytes is None or p.public_key_bytes <= max_public_key_bytes)
        ]
        if not candidates:
            raise ValueError(
                f"No Kyber variant satisfies security_level >= {min_security_level} "
                f"and public_key_bytes <= {max_public_key_bytes}."
            )
        # Prefer highest security level within constraints
        return max(candidates, key=lambda p: p.nist_security_level)

    def get_parameter_info(self, variant: str | None = None) -> dict[str, Any]:
        """Return parameter information for a Kyber variant.

        Args:
            variant: Kyber variant name (defaults to adapter default).

        Returns:
            Parameter info dict.

        Raises:
            ValueError: If variant is not supported.
        """
        resolved = variant or self._default_variant
        params = KYBER_PARAMETER_SETS.get(resolved)
        if params is None:
            raise ValueError(f"Unsupported Kyber variant: {resolved}")
        return {
            "variant": params.variant,
            "nist_name": params.nist_name,
            "nist_security_level": params.nist_security_level,
            "public_key_bytes": params.public_key_bytes,
            "secret_key_bytes": params.secret_key_bytes,
            "ciphertext_bytes": params.ciphertext_bytes,
            "shared_secret_bytes": params.shared_secret_bytes,
            "fips_reference": params.fips_reference,
        }
