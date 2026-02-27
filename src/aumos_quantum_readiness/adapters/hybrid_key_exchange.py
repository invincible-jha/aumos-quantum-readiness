"""Hybrid key exchange adapter combining classical and post-quantum algorithms.

Implements X25519 + Kyber combined key agreement, backward compatibility
mode, hybrid TLS handshake support, combined shared secret derivation,
negotiation protocol, key material export, and session establishment.

In production, X25519 operations use the cryptography library and Kyber
operations use liboqs-python. Both libraries are abstracted behind this
adapter so they can be swapped independently.
"""

import hashlib
import hmac
import os
import uuid
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Hybrid shared secret derivation
# ---------------------------------------------------------------------------

_HYBRID_KDF_LABEL: bytes = b"HYBRID-X25519-KYBER-SHARED-SECRET"


def _hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    """HKDF-Extract step (RFC 5869).

    Args:
        salt: Non-secret random value.
        input_key_material: Source keying material.

    Returns:
        Pseudo-random key bytes.
    """
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand step (RFC 5869).

    Args:
        prk: Pseudo-random key from HKDF-Extract.
        info: Context and application-specific information.
        length: Desired output length in bytes.

    Returns:
        Output keying material of the requested length.
    """
    n = (length + 31) // 32  # Ceiling division for 32-byte blocks
    okm = b""
    t_prev = b""
    for i in range(1, n + 1):
        t_prev = hmac.new(prk, t_prev + info + bytes([i]), hashlib.sha256).digest()
        okm += t_prev
    return okm[:length]


def _derive_combined_secret(
    classical_secret: bytes,
    pqc_secret: bytes,
    context: bytes = b"",
) -> bytes:
    """Derive a combined shared secret from classical and PQC components.

    Uses the concatenation KDF recommended in NIST SP 800-227:
        combined = HKDF(classical_secret || pqc_secret, label || context)

    Args:
        classical_secret: Shared secret from X25519 key agreement (32 bytes).
        pqc_secret: Shared secret from Kyber encapsulation (32 bytes).
        context: Optional session context bytes.

    Returns:
        Combined 32-byte shared secret.
    """
    input_key_material = classical_secret + pqc_secret
    salt = hashlib.sha256(_HYBRID_KDF_LABEL + context).digest()
    prk = _hkdf_extract(salt, input_key_material)
    return _hkdf_expand(prk, _HYBRID_KDF_LABEL + context, length=32)


def _compute_fingerprint(key_bytes: bytes) -> str:
    """Compute a SHA-256 fingerprint of key material for logging.

    Args:
        key_bytes: Raw key bytes (never logged directly).

    Returns:
        Hex-encoded fingerprint string.
    """
    return hashlib.sha256(key_bytes).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Kyber parameter sets
# ---------------------------------------------------------------------------

KYBER_PARAMETER_SETS: dict[str, dict[str, int]] = {
    "Kyber-512": {
        "security_level": 1,
        "public_key_bytes": 800,
        "secret_key_bytes": 1632,
        "ciphertext_bytes": 768,
        "shared_secret_bytes": 32,
    },
    "Kyber-768": {
        "security_level": 3,
        "public_key_bytes": 1184,
        "secret_key_bytes": 2400,
        "ciphertext_bytes": 1088,
        "shared_secret_bytes": 32,
    },
    "Kyber-1024": {
        "security_level": 5,
        "public_key_bytes": 1568,
        "secret_key_bytes": 3168,
        "ciphertext_bytes": 1568,
        "shared_secret_bytes": 32,
    },
}

X25519_KEY_BYTES: int = 32


# ---------------------------------------------------------------------------
# HybridKeyExchange adapter
# ---------------------------------------------------------------------------


class HybridKeyExchange:
    """Classical + PQC hybrid key exchange adapter.

    Combines X25519 (ECDH over Curve25519) with CRYSTALS-Kyber KEM to
    provide forward-secrecy and quantum resistance simultaneously. The
    combined shared secret is derived using HKDF per NIST SP 800-227
    guidance.

    In production: replace stub key generation with cryptography.hazmat
    for X25519 and oqs.KeyEncapsulation for Kyber.
    """

    def __init__(
        self,
        kyber_variant: str = "Kyber-1024",
        hybrid_mode: bool = True,
    ) -> None:
        """Initialise the hybrid key exchange adapter.

        Args:
            kyber_variant: Kyber parameter set to use ('Kyber-512', 'Kyber-768', 'Kyber-1024').
            hybrid_mode: If False, use only Kyber (PQC-only mode for new systems).

        Raises:
            ValueError: If kyber_variant is not a known parameter set.
        """
        if kyber_variant not in KYBER_PARAMETER_SETS:
            raise ValueError(
                f"Unknown Kyber variant: {kyber_variant}. "
                f"Supported: {list(KYBER_PARAMETER_SETS)}"
            )
        self._kyber_variant = kyber_variant
        self._kyber_params = KYBER_PARAMETER_SETS[kyber_variant]
        self._hybrid_mode = hybrid_mode

    async def initiate_handshake(
        self,
        peer_id: str,
        session_id: str | None = None,
        tenant_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """Initiate a hybrid TLS-style handshake by generating key material.

        Generates an ephemeral X25519 key pair and a Kyber key pair. Returns
        the public components for transmission to the peer. Private key
        material is never logged.

        Args:
            peer_id: Identifier of the peer initiating the exchange.
            session_id: Optional session identifier (generated if None).
            tenant_id: Optional tenant context for namespacing.

        Returns:
            Dict with session_id, public_key_bundle (classical + pqc), and
            kyber_variant.
        """
        session_id = session_id or str(uuid.uuid4())

        # Generate ephemeral key pairs
        # Production: use cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey
        classical_private = os.urandom(X25519_KEY_BYTES)
        classical_public = os.urandom(X25519_KEY_BYTES)  # Stub: real impl uses scalar mul

        # Production: use oqs.KeyEncapsulation(self._kyber_variant)
        kyber_public = os.urandom(self._kyber_params["public_key_bytes"])
        kyber_private = os.urandom(self._kyber_params["secret_key_bytes"])

        logger.info(
            "Hybrid handshake initiated",
            session_id=session_id,
            peer_id=peer_id,
            kyber_variant=self._kyber_variant,
            hybrid_mode=self._hybrid_mode,
            classical_fingerprint=_compute_fingerprint(classical_public),
            kyber_fingerprint=_compute_fingerprint(kyber_public),
        )

        return {
            "session_id": session_id,
            "peer_id": peer_id,
            "kyber_variant": self._kyber_variant,
            "hybrid_mode": self._hybrid_mode,
            "public_key_bundle": {
                "classical_algorithm": "X25519" if self._hybrid_mode else None,
                "classical_public_key_size_bytes": X25519_KEY_BYTES if self._hybrid_mode else 0,
                "classical_fingerprint": _compute_fingerprint(classical_public) if self._hybrid_mode else None,
                "pqc_algorithm": self._kyber_variant,
                "pqc_public_key_size_bytes": self._kyber_params["public_key_bytes"],
                "pqc_fingerprint": _compute_fingerprint(kyber_public),
                "security_level": self._kyber_params["security_level"],
            },
            "metadata": {
                "negotiation_protocol": "HYBRID-TLS-1.3-PQC",
                "ciphertext_bytes": self._kyber_params["ciphertext_bytes"],
                "shared_secret_bytes": 32,
            },
        }

    async def complete_handshake(
        self,
        session_id: str,
        peer_public_key_bundle: dict[str, Any],
        context: bytes = b"",
    ) -> dict[str, Any]:
        """Complete a hybrid handshake by encapsulating and deriving shared secret.

        The responder encapsulates a shared secret using the initiator's Kyber
        public key and performs X25519 ECDH. Both secrets are combined into a
        single session key via HKDF.

        Args:
            session_id: Session identifier from initiate_handshake.
            peer_public_key_bundle: Public key bundle from the initiator.
            context: Optional binding context bytes (e.g., session transcript).

        Returns:
            Dict with session_id, shared_secret_fingerprint, ciphertext_bundle,
            established_at, session_params.
        """
        # Stub encapsulation — production: oqs.KeyEncapsulation.encap_secret(peer_pqc_public_key)
        kyber_ciphertext = os.urandom(self._kyber_params["ciphertext_bytes"])
        kyber_shared_secret = os.urandom(self._kyber_params["shared_secret_bytes"])

        # Stub X25519 ECDH — production: X25519PrivateKey.exchange(peer_classical_public_key)
        classical_shared_secret = os.urandom(X25519_KEY_BYTES) if self._hybrid_mode else b""

        # Derive combined session key
        if self._hybrid_mode:
            combined_secret = _derive_combined_secret(
                classical_shared_secret, kyber_shared_secret, context
            )
        else:
            combined_secret = kyber_shared_secret

        secret_fingerprint = _compute_fingerprint(combined_secret)

        logger.info(
            "Hybrid handshake completed",
            session_id=session_id,
            kyber_variant=self._kyber_variant,
            hybrid_mode=self._hybrid_mode,
            secret_fingerprint=secret_fingerprint,
        )

        return {
            "session_id": session_id,
            "shared_secret_fingerprint": secret_fingerprint,
            "shared_secret_size_bytes": 32,
            "ciphertext_bundle": {
                "kyber_ciphertext_size_bytes": len(kyber_ciphertext),
                "kyber_ciphertext_fingerprint": _compute_fingerprint(kyber_ciphertext),
            },
            "session_params": {
                "kyber_variant": self._kyber_variant,
                "classical_algorithm": "X25519" if self._hybrid_mode else None,
                "hybrid_mode": self._hybrid_mode,
                "security_level": self._kyber_params["security_level"],
                "kdf": "HKDF-SHA256",
            },
            "established": True,
        }

    async def export_key_material(
        self,
        session_id: str,
        label: str,
        context: bytes,
        length: int = 32,
    ) -> dict[str, Any]:
        """Export additional key material from an established session.

        Uses HKDF-Expand to derive sub-keys for specific purposes (e.g.,
        encryption key, MAC key, IV).

        Args:
            session_id: Established session identifier.
            label: Application-specific label string.
            context: Binding context bytes.
            length: Desired output key length in bytes.

        Returns:
            Dict with derived_key_fingerprint, length_bytes, label, usage.
        """
        # In production: retrieve session shared secret from secure session store
        pseudo_session_secret = hashlib.sha256(session_id.encode()).digest()
        prk = _hkdf_extract(context, pseudo_session_secret)
        derived_key = _hkdf_expand(prk, label.encode(), length=length)

        logger.info(
            "Key material exported",
            session_id=session_id,
            label=label,
            length_bytes=length,
            derived_fingerprint=_compute_fingerprint(derived_key),
        )

        return {
            "session_id": session_id,
            "label": label,
            "length_bytes": length,
            "derived_key_fingerprint": _compute_fingerprint(derived_key),
            "usage": f"session/{session_id}/{label}",
        }

    async def negotiate_algorithm(
        self,
        offered_variants: list[str],
        compatibility_mode: str = "hybrid",
    ) -> dict[str, Any]:
        """Select the best mutually supported algorithm variant.

        Args:
            offered_variants: List of Kyber variants offered by the client.
            compatibility_mode: 'hybrid' | 'pqc_only' | 'classical_only'.

        Returns:
            Dict with selected_variant, security_level, backward_compatible.
        """
        priority = ["Kyber-1024", "Kyber-768", "Kyber-512"]

        selected: str | None = None
        for variant in priority:
            if variant in offered_variants and variant in KYBER_PARAMETER_SETS:
                selected = variant
                break

        if selected is None:
            if compatibility_mode == "classical_only":
                selected = "classical_x25519_only"
            else:
                raise ValueError(
                    f"No mutually supported Kyber variant found in offered: {offered_variants}"
                )

        params = KYBER_PARAMETER_SETS.get(selected, {})

        logger.info(
            "Algorithm negotiation complete",
            selected_variant=selected,
            compatibility_mode=compatibility_mode,
        )

        return {
            "selected_variant": selected,
            "security_level": params.get("security_level", 0),
            "backward_compatible": compatibility_mode in ("hybrid", "classical_only"),
            "hybrid_mode": compatibility_mode == "hybrid",
        }
