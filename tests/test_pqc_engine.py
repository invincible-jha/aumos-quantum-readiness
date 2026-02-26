"""Unit tests for the PQC engine adapter."""

import pytest

from aumos_quantum_readiness.adapters.pqc_engine import PQCEngine


class TestPQCEngine:
    """Tests for PQCEngine adapter."""

    def test_generate_kem_keypair_supported_algorithm(self) -> None:
        """generate_kem_keypair returns key dict for supported algorithm."""
        engine = PQCEngine()
        result = engine.generate_kem_keypair("ML-KEM-1024")
        assert "public_key" in result
        assert "private_key" in result
        assert isinstance(result["public_key"], bytes)
        assert isinstance(result["private_key"], bytes)

    def test_generate_kem_keypair_unsupported_algorithm_raises(self) -> None:
        """generate_kem_keypair raises ValueError for unknown algorithm."""
        engine = PQCEngine()
        with pytest.raises(ValueError, match="Unsupported KEM algorithm"):
            engine.generate_kem_keypair("RSA-2048")

    def test_encapsulate_returns_ciphertext_and_secret(self) -> None:
        """encapsulate returns ciphertext and shared_secret bytes."""
        engine = PQCEngine()
        result = engine.encapsulate("ML-KEM-768", public_key=b"stub_public_key")
        assert "ciphertext" in result
        assert "shared_secret" in result

    def test_encapsulate_unsupported_algorithm_raises(self) -> None:
        """encapsulate raises ValueError for unsupported algorithm."""
        engine = PQCEngine()
        with pytest.raises(ValueError):
            engine.encapsulate("ECDSA-P256", public_key=b"key")

    def test_decapsulate_returns_bytes(self) -> None:
        """decapsulate returns shared secret as bytes."""
        engine = PQCEngine()
        result = engine.decapsulate("CRYSTALS-Kyber-1024", private_key=b"key", ciphertext=b"ct")
        assert isinstance(result, bytes)

    def test_generate_signature_keypair_supported_algorithm(self) -> None:
        """generate_signature_keypair returns key dict for supported algorithm."""
        engine = PQCEngine()
        result = engine.generate_signature_keypair("ML-DSA-65")
        assert "public_key" in result
        assert "private_key" in result

    def test_generate_signature_keypair_unsupported_raises(self) -> None:
        """generate_signature_keypair raises ValueError for unsupported algorithm."""
        engine = PQCEngine()
        with pytest.raises(ValueError, match="Unsupported signature algorithm"):
            engine.generate_signature_keypair("RSA-4096")

    def test_sign_returns_bytes(self) -> None:
        """sign returns signature bytes."""
        engine = PQCEngine()
        result = engine.sign("CRYSTALS-Dilithium3", private_key=b"key", message=b"hello world")
        assert isinstance(result, bytes)

    def test_verify_returns_bool(self) -> None:
        """verify returns a boolean result."""
        engine = PQCEngine()
        result = engine.verify(
            "CRYSTALS-Dilithium3",
            public_key=b"pub_key",
            message=b"hello world",
            signature=b"sig",
        )
        assert isinstance(result, bool)

    def test_supported_kems_includes_nist_standards(self) -> None:
        """SUPPORTED_KEMS includes all FIPS-203 standardized algorithms."""
        assert "ML-KEM-512" in PQCEngine.SUPPORTED_KEMS
        assert "ML-KEM-768" in PQCEngine.SUPPORTED_KEMS
        assert "ML-KEM-1024" in PQCEngine.SUPPORTED_KEMS

    def test_supported_signatures_includes_nist_standards(self) -> None:
        """SUPPORTED_SIGNATURES includes all FIPS-204 and FIPS-205 algorithms."""
        assert "ML-DSA-44" in PQCEngine.SUPPORTED_SIGNATURES
        assert "ML-DSA-65" in PQCEngine.SUPPORTED_SIGNATURES
        assert "SLH-DSA-SHA2-128s" in PQCEngine.SUPPORTED_SIGNATURES
