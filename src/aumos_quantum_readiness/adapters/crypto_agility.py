"""Crypto-agility adapter providing algorithm-agnostic cryptographic interfaces.

Implements an algorithm registry supporting symmetric, asymmetric, hash,
and KEM primitives. Enables runtime algorithm selection, migration-safe API
(swap algorithms without code changes), algorithm deprecation management,
capability matrix computation, and configuration-driven selection.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Algorithm type enumerations
# ---------------------------------------------------------------------------


class AlgorithmCategory(str, Enum):
    """Top-level cryptographic algorithm category."""

    SYMMETRIC = "symmetric"
    ASYMMETRIC = "asymmetric"
    HASH = "hash"
    KEM = "kem"
    SIGNATURE = "signature"
    MAC = "mac"


class QuantumStatus(str, Enum):
    """Quantum-safety classification of an algorithm."""

    QUANTUM_SAFE = "quantum_safe"
    HYBRID = "hybrid"
    QUANTUM_VULNERABLE = "quantum_vulnerable"
    UNKNOWN = "unknown"


class AlgorithmLifecycle(str, Enum):
    """Operational lifecycle state of an algorithm."""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    FORBIDDEN = "forbidden"
    EXPERIMENTAL = "experimental"


# ---------------------------------------------------------------------------
# Algorithm descriptor
# ---------------------------------------------------------------------------


@dataclass
class AlgorithmDescriptor:
    """Complete descriptor for a cryptographic algorithm.

    All fields are populated at registry registration time and never mutated
    post-registration (treat as immutable after construction).
    """

    name: str
    category: AlgorithmCategory
    quantum_status: QuantumStatus
    lifecycle: AlgorithmLifecycle
    key_sizes_bits: list[int]
    nist_reference: str
    min_security_level: int  # NIST security level 1-5 (0 = not rated)
    output_size_bits: int | None = None
    notes: str = ""
    replaces: list[str] = field(default_factory=list)  # Names of algorithms this supersedes
    replaced_by: str | None = None  # Name of the algorithm that replaces this one


# ---------------------------------------------------------------------------
# Algorithm registry
# ---------------------------------------------------------------------------


class AlgorithmRegistry:
    """Mutable algorithm registry with crypto-agile lookup and migration support.

    The registry is the single source of truth for which algorithms are
    approved, deprecated, or forbidden within an organisation's cryptographic
    policy. Services consume algorithms through the registry so that a
    single policy change takes effect everywhere.
    """

    def __init__(self) -> None:
        """Initialise the registry with NIST-approved and legacy algorithms."""
        self._algorithms: dict[str, AlgorithmDescriptor] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Populate registry with built-in algorithm descriptors."""
        defaults: list[AlgorithmDescriptor] = [
            # ------------------------------------------------------------------
            # KEM — NIST PQC standards
            # ------------------------------------------------------------------
            AlgorithmDescriptor(
                name="ML-KEM-512",
                category=AlgorithmCategory.KEM,
                quantum_status=QuantumStatus.QUANTUM_SAFE,
                lifecycle=AlgorithmLifecycle.ACTIVE,
                key_sizes_bits=[6400],  # 800-byte public key × 8
                nist_reference="FIPS-203",
                min_security_level=1,
                output_size_bits=256,
                notes="CRYSTALS-Kyber-512 standardised as ML-KEM-512 in FIPS-203.",
                replaces=["RSA-2048"],
            ),
            AlgorithmDescriptor(
                name="ML-KEM-768",
                category=AlgorithmCategory.KEM,
                quantum_status=QuantumStatus.QUANTUM_SAFE,
                lifecycle=AlgorithmLifecycle.ACTIVE,
                key_sizes_bits=[9472],
                nist_reference="FIPS-203",
                min_security_level=3,
                output_size_bits=256,
                notes="CRYSTALS-Kyber-768 standardised as ML-KEM-768 in FIPS-203.",
                replaces=["RSA-3072", "ECDH-P256"],
            ),
            AlgorithmDescriptor(
                name="ML-KEM-1024",
                category=AlgorithmCategory.KEM,
                quantum_status=QuantumStatus.QUANTUM_SAFE,
                lifecycle=AlgorithmLifecycle.ACTIVE,
                key_sizes_bits=[12544],
                nist_reference="FIPS-203",
                min_security_level=5,
                output_size_bits=256,
                notes="CRYSTALS-Kyber-1024 standardised as ML-KEM-1024 in FIPS-203.",
                replaces=["RSA-4096", "ECDH-P384"],
            ),
            # ------------------------------------------------------------------
            # Signature — NIST PQC standards
            # ------------------------------------------------------------------
            AlgorithmDescriptor(
                name="ML-DSA-44",
                category=AlgorithmCategory.SIGNATURE,
                quantum_status=QuantumStatus.QUANTUM_SAFE,
                lifecycle=AlgorithmLifecycle.ACTIVE,
                key_sizes_bits=[2048],
                nist_reference="FIPS-204",
                min_security_level=2,
                output_size_bits=2048 * 8,
                notes="CRYSTALS-Dilithium2 standardised as ML-DSA-44 in FIPS-204.",
                replaces=["ECDSA-P256", "RSA-PSS-2048"],
            ),
            AlgorithmDescriptor(
                name="ML-DSA-65",
                category=AlgorithmCategory.SIGNATURE,
                quantum_status=QuantumStatus.QUANTUM_SAFE,
                lifecycle=AlgorithmLifecycle.ACTIVE,
                key_sizes_bits=[2048],
                nist_reference="FIPS-204",
                min_security_level=3,
                output_size_bits=3293 * 8,
                notes="CRYSTALS-Dilithium3 standardised as ML-DSA-65 in FIPS-204.",
            ),
            AlgorithmDescriptor(
                name="ML-DSA-87",
                category=AlgorithmCategory.SIGNATURE,
                quantum_status=QuantumStatus.QUANTUM_SAFE,
                lifecycle=AlgorithmLifecycle.ACTIVE,
                key_sizes_bits=[2048],
                nist_reference="FIPS-204",
                min_security_level=5,
                output_size_bits=4595 * 8,
                notes="CRYSTALS-Dilithium5 standardised as ML-DSA-87 in FIPS-204.",
                replaces=["ECDSA-P521"],
            ),
            # ------------------------------------------------------------------
            # Symmetric — quantum-safe (AES key size ≥ 256)
            # ------------------------------------------------------------------
            AlgorithmDescriptor(
                name="AES-256-GCM",
                category=AlgorithmCategory.SYMMETRIC,
                quantum_status=QuantumStatus.QUANTUM_SAFE,
                lifecycle=AlgorithmLifecycle.ACTIVE,
                key_sizes_bits=[256],
                nist_reference="FIPS-197",
                min_security_level=5,
                output_size_bits=128,
                notes="AES-256 provides 128-bit quantum security (Grover's algorithm halves key length).",
            ),
            AlgorithmDescriptor(
                name="AES-128-GCM",
                category=AlgorithmCategory.SYMMETRIC,
                quantum_status=QuantumStatus.HYBRID,
                lifecycle=AlgorithmLifecycle.DEPRECATED,
                key_sizes_bits=[128],
                nist_reference="FIPS-197",
                min_security_level=2,
                notes="64-bit quantum security is insufficient for long-term data protection.",
                replaced_by="AES-256-GCM",
            ),
            # ------------------------------------------------------------------
            # Hash — quantum-safe
            # ------------------------------------------------------------------
            AlgorithmDescriptor(
                name="SHA-3-256",
                category=AlgorithmCategory.HASH,
                quantum_status=QuantumStatus.QUANTUM_SAFE,
                lifecycle=AlgorithmLifecycle.ACTIVE,
                key_sizes_bits=[],
                nist_reference="FIPS-202",
                min_security_level=4,
                output_size_bits=256,
            ),
            AlgorithmDescriptor(
                name="SHA-2-256",
                category=AlgorithmCategory.HASH,
                quantum_status=QuantumStatus.HYBRID,
                lifecycle=AlgorithmLifecycle.ACTIVE,
                key_sizes_bits=[],
                nist_reference="FIPS-180-4",
                min_security_level=3,
                output_size_bits=256,
                notes="128-bit quantum security. Acceptable for most uses; prefer SHA-3-256.",
            ),
            # ------------------------------------------------------------------
            # Vulnerable legacy algorithms
            # ------------------------------------------------------------------
            AlgorithmDescriptor(
                name="RSA-2048",
                category=AlgorithmCategory.ASYMMETRIC,
                quantum_status=QuantumStatus.QUANTUM_VULNERABLE,
                lifecycle=AlgorithmLifecycle.DEPRECATED,
                key_sizes_bits=[2048],
                nist_reference="NIST-SP-800-131A",
                min_security_level=0,
                notes="Broken by Shor's algorithm on a fault-tolerant quantum computer.",
                replaced_by="ML-KEM-768",
            ),
            AlgorithmDescriptor(
                name="ECDSA-P256",
                category=AlgorithmCategory.SIGNATURE,
                quantum_status=QuantumStatus.QUANTUM_VULNERABLE,
                lifecycle=AlgorithmLifecycle.DEPRECATED,
                key_sizes_bits=[256],
                nist_reference="NIST-SP-800-131A",
                min_security_level=0,
                notes="Broken by Shor's algorithm. Migrate to ML-DSA-44.",
                replaced_by="ML-DSA-44",
            ),
        ]
        for algo in defaults:
            self._algorithms[algo.name] = algo

    def register(self, descriptor: AlgorithmDescriptor) -> None:
        """Add or update an algorithm in the registry.

        Args:
            descriptor: AlgorithmDescriptor to register.
        """
        self._algorithms[descriptor.name] = descriptor
        logger.info(
            "Algorithm registered",
            name=descriptor.name,
            category=descriptor.category,
            lifecycle=descriptor.lifecycle,
        )

    def get(self, name: str) -> AlgorithmDescriptor | None:
        """Retrieve an algorithm descriptor by name.

        Args:
            name: Algorithm name string.

        Returns:
            AlgorithmDescriptor or None if not registered.
        """
        return self._algorithms.get(name)

    def list_by_category(
        self,
        category: AlgorithmCategory,
        active_only: bool = True,
    ) -> list[AlgorithmDescriptor]:
        """List algorithms filtered by category.

        Args:
            category: Algorithm category to filter.
            active_only: If True, exclude deprecated and forbidden algorithms.

        Returns:
            Filtered list of AlgorithmDescriptors.
        """
        results = [
            algo for algo in self._algorithms.values()
            if algo.category == category
        ]
        if active_only:
            results = [
                algo for algo in results
                if algo.lifecycle == AlgorithmLifecycle.ACTIVE
            ]
        return sorted(results, key=lambda a: -a.min_security_level)

    def deprecate(self, name: str, replaced_by: str | None = None) -> None:
        """Mark an algorithm as deprecated.

        Args:
            name: Algorithm name to deprecate.
            replaced_by: Optional name of the successor algorithm.

        Raises:
            KeyError: If the algorithm is not registered.
        """
        algo = self._algorithms.get(name)
        if algo is None:
            raise KeyError(f"Algorithm '{name}' not found in registry")
        algo.lifecycle = AlgorithmLifecycle.DEPRECATED
        if replaced_by:
            algo.replaced_by = replaced_by
        logger.info("Algorithm deprecated", name=name, replaced_by=replaced_by)

    def capability_matrix(self) -> list[dict[str, Any]]:
        """Build a capability matrix across all registered algorithms.

        Returns:
            List of algorithm capability dicts ordered by security level.
        """
        matrix: list[dict[str, Any]] = []
        for algo in sorted(
            self._algorithms.values(),
            key=lambda a: (-a.min_security_level, a.name),
        ):
            matrix.append(
                {
                    "name": algo.name,
                    "category": algo.category.value,
                    "quantum_status": algo.quantum_status.value,
                    "lifecycle": algo.lifecycle.value,
                    "security_level": algo.min_security_level,
                    "nist_reference": algo.nist_reference,
                    "approved": (
                        algo.lifecycle == AlgorithmLifecycle.ACTIVE
                        and algo.quantum_status == QuantumStatus.QUANTUM_SAFE
                    ),
                    "notes": algo.notes,
                    "replaced_by": algo.replaced_by,
                }
            )
        return matrix


# ---------------------------------------------------------------------------
# CryptoAgility adapter
# ---------------------------------------------------------------------------


class CryptoAgility:
    """Algorithm-agnostic cryptographic interface with runtime selection.

    Wraps the AlgorithmRegistry to provide a stable API for selecting,
    validating, and migrating between cryptographic algorithms without
    changing service code. Configuration-driven selection enables policy
    changes via environment variables or database records.
    """

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        registry: AlgorithmRegistry | None = None,
    ) -> None:
        """Initialise the crypto-agility adapter.

        Args:
            config: Optional configuration overrides:
                - preferred_kem: Preferred KEM algorithm name.
                - preferred_signature: Preferred signature algorithm name.
                - preferred_symmetric: Preferred symmetric algorithm name.
                - min_security_level: Minimum acceptable NIST security level.
            registry: Optional pre-populated registry; creates a default one if None.
        """
        self._config: dict[str, Any] = config or {}
        self._registry: AlgorithmRegistry = registry or AlgorithmRegistry()

    async def select_algorithm(
        self,
        category: str,
        min_security_level: int = 3,
        quantum_safe_only: bool = True,
    ) -> dict[str, Any]:
        """Select the best available algorithm for a given category.

        Args:
            category: Algorithm category ('kem', 'signature', 'symmetric', 'hash', 'mac').
            min_security_level: Minimum NIST security level required (1-5).
            quantum_safe_only: If True, only return QUANTUM_SAFE algorithms.

        Returns:
            Dict with selected algorithm name, category, security_level, nist_reference.

        Raises:
            ValueError: If no suitable algorithm is available.
        """
        try:
            cat = AlgorithmCategory(category)
        except ValueError:
            raise ValueError(
                f"Unknown algorithm category: {category}. "
                f"Supported: {[c.value for c in AlgorithmCategory]}"
            )

        override_key = f"preferred_{category}"
        if override_key in self._config:
            preferred_name = self._config[override_key]
            descriptor = self._registry.get(preferred_name)
            if descriptor and descriptor.lifecycle == AlgorithmLifecycle.ACTIVE:
                logger.info(
                    "Algorithm selected via config override",
                    name=preferred_name,
                    category=category,
                )
                return self._descriptor_to_dict(descriptor)

        candidates = self._registry.list_by_category(cat, active_only=True)
        if quantum_safe_only:
            candidates = [c for c in candidates if c.quantum_status == QuantumStatus.QUANTUM_SAFE]
        candidates = [c for c in candidates if c.min_security_level >= min_security_level]

        if not candidates:
            raise ValueError(
                f"No suitable {category} algorithm found at security level >= {min_security_level} "
                f"with quantum_safe_only={quantum_safe_only}"
            )

        selected = candidates[0]
        logger.info(
            "Algorithm selected",
            name=selected.name,
            category=category,
            security_level=selected.min_security_level,
        )
        return self._descriptor_to_dict(selected)

    async def validate_algorithm(
        self, algorithm_name: str, usage_context: str = ""
    ) -> dict[str, Any]:
        """Validate that an algorithm is approved for use.

        Args:
            algorithm_name: Algorithm name to validate.
            usage_context: Optional description of how the algorithm will be used.

        Returns:
            Dict with approved, lifecycle, quantum_status, replacement, warnings.
        """
        descriptor = self._registry.get(algorithm_name)
        if descriptor is None:
            return {
                "approved": False,
                "reason": f"Algorithm '{algorithm_name}' is not in the algorithm registry.",
                "warnings": ["Unknown algorithm — do not use in production."],
                "replacement": None,
            }

        approved = (
            descriptor.lifecycle == AlgorithmLifecycle.ACTIVE
            and descriptor.quantum_status == QuantumStatus.QUANTUM_SAFE
        )
        warnings: list[str] = []

        if descriptor.lifecycle == AlgorithmLifecycle.DEPRECATED:
            warnings.append(
                f"Algorithm '{algorithm_name}' is deprecated. "
                f"Migrate to '{descriptor.replaced_by or 'a NIST-approved PQC alternative'}'."
            )
        if descriptor.lifecycle == AlgorithmLifecycle.FORBIDDEN:
            warnings.append(f"Algorithm '{algorithm_name}' is FORBIDDEN — do not use.")
        if descriptor.quantum_status == QuantumStatus.QUANTUM_VULNERABLE:
            warnings.append(
                f"Algorithm '{algorithm_name}' is quantum-vulnerable. "
                "Replace before quantum computers become operational."
            )

        logger.info(
            "Algorithm validation",
            name=algorithm_name,
            approved=approved,
            lifecycle=descriptor.lifecycle,
            usage_context=usage_context,
        )

        return {
            "approved": approved,
            "algorithm_name": algorithm_name,
            "category": descriptor.category.value,
            "lifecycle": descriptor.lifecycle.value,
            "quantum_status": descriptor.quantum_status.value,
            "security_level": descriptor.min_security_level,
            "nist_reference": descriptor.nist_reference,
            "replacement": descriptor.replaced_by,
            "warnings": warnings,
        }

    async def plan_migration(
        self,
        from_algorithm: str,
        to_algorithm: str | None = None,
    ) -> dict[str, Any]:
        """Plan the migration from one algorithm to another.

        If to_algorithm is not specified, the registry's replacement is used.

        Args:
            from_algorithm: The algorithm to migrate away from.
            to_algorithm: The target algorithm (optional; inferred from registry).

        Returns:
            Dict with migration_path, compatibility_notes, estimated_effort, steps.

        Raises:
            ValueError: If no migration target is found.
        """
        source = self._registry.get(from_algorithm)
        if source is None:
            raise ValueError(f"Source algorithm '{from_algorithm}' not found in registry")

        target_name = to_algorithm or source.replaced_by
        if target_name is None:
            # Find a suitable replacement by category
            replacements = self._registry.list_by_category(source.category, active_only=True)
            replacements = [
                r for r in replacements
                if r.quantum_status == QuantumStatus.QUANTUM_SAFE
            ]
            if not replacements:
                raise ValueError(
                    f"No quantum-safe replacement found for category '{source.category}'"
                )
            target_name = replacements[0].name

        target = self._registry.get(target_name)
        if target is None:
            raise ValueError(f"Target algorithm '{target_name}' not found in registry")

        steps = [
            {
                "step": 1,
                "action": f"Inventory all uses of {from_algorithm} across all services.",
                "duration_weeks": 2,
            },
            {
                "step": 2,
                "action": f"Deploy {target_name} in hybrid mode alongside {from_algorithm}.",
                "duration_weeks": 4,
            },
            {
                "step": 3,
                "action": f"Migrate all new key generation to {target_name}.",
                "duration_weeks": 4,
            },
            {
                "step": 4,
                "action": f"Re-encrypt / re-sign existing data with {target_name}.",
                "duration_weeks": 8,
            },
            {
                "step": 5,
                "action": f"Remove {from_algorithm} from all codebases and configurations.",
                "duration_weeks": 2,
            },
        ]

        logger.info(
            "Migration plan generated",
            from_algorithm=from_algorithm,
            to_algorithm=target_name,
        )

        return {
            "from_algorithm": from_algorithm,
            "to_algorithm": target_name,
            "migration_path": f"{from_algorithm} → {target_name}",
            "nist_reference": target.nist_reference,
            "compatibility_notes": (
                f"Key sizes change: {source.key_sizes_bits} → {target.key_sizes_bits}. "
                "Update all key serialisation and storage layers."
            ),
            "estimated_total_weeks": sum(s["duration_weeks"] for s in steps),
            "steps": steps,
        }

    async def get_capability_matrix(self) -> list[dict[str, Any]]:
        """Return the full algorithm capability matrix.

        Returns:
            List of algorithm capability dicts.
        """
        return self._registry.capability_matrix()

    def _descriptor_to_dict(self, descriptor: AlgorithmDescriptor) -> dict[str, Any]:
        """Convert an AlgorithmDescriptor to a plain dict.

        Args:
            descriptor: Algorithm descriptor.

        Returns:
            Serialisable dict.
        """
        return {
            "name": descriptor.name,
            "category": descriptor.category.value,
            "quantum_status": descriptor.quantum_status.value,
            "lifecycle": descriptor.lifecycle.value,
            "key_sizes_bits": descriptor.key_sizes_bits,
            "nist_reference": descriptor.nist_reference,
            "security_level": descriptor.min_security_level,
            "output_size_bits": descriptor.output_size_bits,
            "notes": descriptor.notes,
            "replaced_by": descriptor.replaced_by,
        }
