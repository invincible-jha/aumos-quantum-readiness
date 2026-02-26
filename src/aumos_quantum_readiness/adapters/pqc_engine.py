"""PQC cryptographic operations adapter for aumos-quantum-readiness.

This adapter wraps post-quantum cryptography library operations.
It abstracts the underlying PQC implementation (e.g., liboqs, pqcrypto)
behind a stable interface, enabling algorithm swaps without service changes.

Currently stubbed — integrate with liboqs-python or a FIPS-certified PQC
library once the runtime environment is confirmed.
"""

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class PQCEngine:
    """Adapter for post-quantum cryptographic operations.

    Wraps CRYSTALS-Kyber, CRYSTALS-Dilithium, and SPHINCS+ operations.
    Uses crypto-agility pattern — algorithm selection is runtime-configurable.
    """

    # NIST-standardized algorithm identifiers (FIPS-203, FIPS-204, FIPS-205)
    SUPPORTED_KEMS: frozenset[str] = frozenset(
        {
            "ML-KEM-512",
            "ML-KEM-768",
            "ML-KEM-1024",
            "CRYSTALS-Kyber-512",
            "CRYSTALS-Kyber-768",
            "CRYSTALS-Kyber-1024",
        }
    )

    SUPPORTED_SIGNATURES: frozenset[str] = frozenset(
        {
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
            "CRYSTALS-Dilithium2",
            "CRYSTALS-Dilithium3",
            "CRYSTALS-Dilithium5",
            "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-256s",
            "FALCON-512",
            "FALCON-1024",
        }
    )

    def generate_kem_keypair(self, algorithm: str) -> dict[str, bytes]:
        """Generate a KEM key pair using the specified PQC algorithm.

        Args:
            algorithm: The KEM algorithm to use (e.g., 'ML-KEM-1024').

        Returns:
            Dict with 'public_key' and 'private_key' as bytes.

        Raises:
            ValueError: If the algorithm is not supported.
        """
        if algorithm not in self.SUPPORTED_KEMS:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}. Supported: {self.SUPPORTED_KEMS}")

        logger.info("Generating KEM keypair", algorithm=algorithm)
        # TODO: Integrate with liboqs-python:
        #   import oqs
        #   kem = oqs.KeyEncapsulation(algorithm)
        #   public_key = kem.generate_keypair()
        #   private_key = kem.export_secret_key()
        #   return {"public_key": public_key, "private_key": private_key}
        return {"public_key": b"stub_public_key", "private_key": b"stub_private_key"}

    def encapsulate(self, algorithm: str, public_key: bytes) -> dict[str, bytes]:
        """Encapsulate a shared secret using a KEM public key.

        Args:
            algorithm: The KEM algorithm to use.
            public_key: The recipient's public key bytes.

        Returns:
            Dict with 'ciphertext' and 'shared_secret' as bytes.

        Raises:
            ValueError: If the algorithm is not supported.
        """
        if algorithm not in self.SUPPORTED_KEMS:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")

        logger.info("Encapsulating shared secret", algorithm=algorithm)
        # TODO: Integrate with liboqs-python:
        #   import oqs
        #   kem = oqs.KeyEncapsulation(algorithm)
        #   ciphertext, shared_secret = kem.encap_secret(public_key)
        #   return {"ciphertext": ciphertext, "shared_secret": shared_secret}
        return {"ciphertext": b"stub_ciphertext", "shared_secret": b"stub_shared_secret"}

    def decapsulate(self, algorithm: str, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using a KEM private key.

        Args:
            algorithm: The KEM algorithm to use.
            private_key: The recipient's private key bytes.
            ciphertext: The ciphertext from encapsulation.

        Returns:
            The decapsulated shared secret bytes.

        Raises:
            ValueError: If the algorithm is not supported.
        """
        if algorithm not in self.SUPPORTED_KEMS:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")

        logger.info("Decapsulating shared secret", algorithm=algorithm)
        # TODO: Integrate with liboqs-python:
        #   import oqs
        #   kem = oqs.KeyEncapsulation(algorithm, secret_key=private_key)
        #   shared_secret = kem.decap_secret(ciphertext)
        #   return shared_secret
        return b"stub_shared_secret"

    def generate_signature_keypair(self, algorithm: str) -> dict[str, bytes]:
        """Generate a digital signature key pair.

        Args:
            algorithm: The signature algorithm to use (e.g., 'ML-DSA-65').

        Returns:
            Dict with 'public_key' and 'private_key' as bytes.

        Raises:
            ValueError: If the algorithm is not supported.
        """
        if algorithm not in self.SUPPORTED_SIGNATURES:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")

        logger.info("Generating signature keypair", algorithm=algorithm)
        # TODO: Integrate with liboqs-python:
        #   import oqs
        #   sig = oqs.Signature(algorithm)
        #   public_key = sig.generate_keypair()
        #   private_key = sig.export_secret_key()
        #   return {"public_key": public_key, "private_key": private_key}
        return {"public_key": b"stub_public_key", "private_key": b"stub_private_key"}

    def sign(self, algorithm: str, private_key: bytes, message: bytes) -> bytes:
        """Sign a message using a PQC signature algorithm.

        Args:
            algorithm: The signature algorithm to use.
            private_key: The signer's private key bytes.
            message: The message to sign.

        Returns:
            The signature bytes.

        Raises:
            ValueError: If the algorithm is not supported.
        """
        if algorithm not in self.SUPPORTED_SIGNATURES:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")

        logger.info("Signing message", algorithm=algorithm, message_length=len(message))
        # TODO: Integrate with liboqs-python:
        #   import oqs
        #   sig = oqs.Signature(algorithm, secret_key=private_key)
        #   signature = sig.sign(message)
        #   return signature
        return b"stub_signature"

    def verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a PQC digital signature.

        Args:
            algorithm: The signature algorithm used for signing.
            public_key: The signer's public key bytes.
            message: The original message.
            signature: The signature to verify.

        Returns:
            True if the signature is valid, False otherwise.

        Raises:
            ValueError: If the algorithm is not supported.
        """
        if algorithm not in self.SUPPORTED_SIGNATURES:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")

        logger.info("Verifying signature", algorithm=algorithm)
        # TODO: Integrate with liboqs-python:
        #   import oqs
        #   sig = oqs.Signature(algorithm)
        #   is_valid = sig.verify(message, signature, public_key)
        #   return is_valid
        return True
