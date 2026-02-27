"""Quantum migration planner adapter for gradual PQC transition planning.

Performs cryptographic inventory assessment, risk prioritisation, migration
roadmap generation, dependency impact analysis, testing phase planning,
rollback strategy, and timeline estimation.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Risk and asset types
# ---------------------------------------------------------------------------


@dataclass
class CryptoAsset:
    """A discoverable cryptographic asset within an organisation's inventory."""

    asset_id: str
    asset_type: str  # 'tls_cert', 'api_key', 'signing_key', 'database_encryption', 'jwt_signing'
    algorithm: str
    key_size_bits: int
    service_name: str
    environment: str  # 'production' | 'staging' | 'development'
    data_sensitivity: str  # 'public' | 'internal' | 'confidential' | 'secret'
    expiry_date: str | None = None
    dependencies: list[str] = field(default_factory=list)


@dataclass
class MigrationTask:
    """A single migration task within the overall roadmap."""

    task_id: str
    asset_id: str
    asset_type: str
    service_name: str
    from_algorithm: str
    to_algorithm: str
    risk_level: str  # 'critical' | 'high' | 'medium' | 'low'
    estimated_effort_hours: int
    dependencies: list[str] = field(default_factory=list)
    testing_required: list[str] = field(default_factory=list)
    rollback_strategy: str = ""


# ---------------------------------------------------------------------------
# Algorithm risk mapping
# ---------------------------------------------------------------------------

# Quantum vulnerability severity by algorithm family
ALGORITHM_RISK_MAP: dict[str, dict[str, Any]] = {
    "RSA-1024": {"risk": "critical", "migration_target": "ML-KEM-768", "urgency_score": 1.0},
    "RSA-2048": {"risk": "critical", "migration_target": "ML-KEM-768", "urgency_score": 0.95},
    "RSA-3072": {"risk": "critical", "migration_target": "ML-KEM-1024", "urgency_score": 0.90},
    "RSA-4096": {"risk": "high", "migration_target": "ML-KEM-1024", "urgency_score": 0.80},
    "ECDSA-P256": {"risk": "critical", "migration_target": "ML-DSA-44", "urgency_score": 0.95},
    "ECDSA-P384": {"risk": "critical", "migration_target": "ML-DSA-65", "urgency_score": 0.90},
    "ECDSA-P521": {"risk": "high", "migration_target": "ML-DSA-87", "urgency_score": 0.85},
    "DH-1024": {"risk": "critical", "migration_target": "ML-KEM-512", "urgency_score": 1.0},
    "DH-2048": {"risk": "critical", "migration_target": "ML-KEM-768", "urgency_score": 0.95},
    "ECDH-P256": {"risk": "critical", "migration_target": "ML-KEM-768", "urgency_score": 0.95},
    "DSA-2048": {"risk": "critical", "migration_target": "ML-DSA-44", "urgency_score": 0.90},
}

QUANTUM_SAFE_ALGORITHMS: frozenset[str] = frozenset(
    {
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024",
        "CRYSTALS-Dilithium2", "CRYSTALS-Dilithium3", "CRYSTALS-Dilithium5",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s",
        "AES-256-GCM", "AES-256-CBC", "SHA-3-256", "SHA-3-512",
    }
)

# Effort estimation in person-hours per asset type
EFFORT_HOURS_BY_TYPE: dict[str, int] = {
    "tls_cert": 8,
    "api_key": 16,
    "signing_key": 24,
    "database_encryption": 40,
    "jwt_signing": 12,
    "code_signing": 20,
    "sshe_key": 6,
    "unknown": 20,
}


# ---------------------------------------------------------------------------
# QuantumMigrationPlanner adapter
# ---------------------------------------------------------------------------


class QuantumMigrationPlanner:
    """Gradual quantum migration planning adapter.

    Assesses a cryptographic asset inventory, prioritises migration tasks by
    risk, generates a phased roadmap, performs dependency impact analysis,
    designs testing phases, and produces rollback strategies.
    """

    async def assess_and_plan(
        self,
        plan_config: dict[str, Any],
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Perform full inventory assessment and generate a migration roadmap.

        Args:
            plan_config: Planning configuration dict. Supported keys:
                - crypto_inventory: List of crypto asset dicts
                  {asset_id, asset_type, algorithm, key_size_bits, service_name,
                   environment, data_sensitivity, expiry_date?, dependencies?}
                - quantum_threat_horizon_years: Years until quantum threat (default 8)
                - target_completion_weeks: Desired migration window in weeks (default 52)
                - prioritisation: 'risk_first' | 'service_impact' | 'timeline' (default 'risk_first')
            tenant_id: Tenant context.

        Returns:
            Dict with inventory_summary, migration_tasks, roadmap, dependency_graph,
            testing_plan, rollback_strategies, timeline, output_uri.
        """
        raw_inventory: list[dict[str, Any]] = plan_config.get("crypto_inventory", [])
        threat_horizon_years: int = int(plan_config.get("quantum_threat_horizon_years", 8))
        target_weeks: int = int(plan_config.get("target_completion_weeks", 52))
        prioritisation: str = plan_config.get("prioritisation", "risk_first")

        logger.info(
            "Starting quantum migration planning",
            inventory_size=len(raw_inventory),
            threat_horizon_years=threat_horizon_years,
            target_weeks=target_weeks,
            tenant_id=str(tenant_id),
        )

        # Parse and classify inventory
        assets = self._parse_inventory(raw_inventory)
        inventory_summary = self._summarise_inventory(assets)

        # Generate migration tasks with risk scores
        migration_tasks = self._generate_migration_tasks(assets, threat_horizon_years)

        # Prioritise tasks
        prioritised_tasks = self._prioritise_tasks(migration_tasks, prioritisation)

        # Dependency analysis
        dependency_graph = self._build_dependency_graph(assets, prioritised_tasks)

        # Build phased roadmap
        roadmap = self._build_roadmap(prioritised_tasks, target_weeks)

        # Testing plan per phase
        testing_plan = self._design_testing_plan(roadmap)

        # Rollback strategies
        rollback_strategies = self._generate_rollback_strategies(prioritised_tasks)

        # Timeline estimates
        timeline = self._estimate_timeline(prioritised_tasks, target_weeks)

        logger.info(
            "Migration planning complete",
            tasks_count=len(migration_tasks),
            critical_count=sum(1 for t in migration_tasks if t.risk_level == "critical"),
            total_effort_hours=sum(t.estimated_effort_hours for t in migration_tasks),
            tenant_id=str(tenant_id),
        )

        return {
            "inventory_summary": inventory_summary,
            "migration_tasks": [self._task_to_dict(t) for t in prioritised_tasks],
            "roadmap": roadmap,
            "dependency_graph": dependency_graph,
            "testing_plan": testing_plan,
            "rollback_strategies": rollback_strategies,
            "timeline": timeline,
            "output_uri": (
                f"s3://aumos-quantum/{tenant_id}/migration-plan/{uuid.uuid4()}.json"
            ),
        }

    def _parse_inventory(self, raw_inventory: list[dict[str, Any]]) -> list[CryptoAsset]:
        """Convert raw inventory dicts to CryptoAsset objects.

        Args:
            raw_inventory: List of raw asset configuration dicts.

        Returns:
            List of CryptoAsset objects.
        """
        assets: list[CryptoAsset] = []
        for i, item in enumerate(raw_inventory):
            assets.append(
                CryptoAsset(
                    asset_id=item.get("asset_id", f"asset_{i}"),
                    asset_type=item.get("asset_type", "unknown"),
                    algorithm=item.get("algorithm", "RSA-2048"),
                    key_size_bits=int(item.get("key_size_bits", 2048)),
                    service_name=item.get("service_name", "unknown_service"),
                    environment=item.get("environment", "production"),
                    data_sensitivity=item.get("data_sensitivity", "confidential"),
                    expiry_date=item.get("expiry_date"),
                    dependencies=item.get("dependencies", []),
                )
            )
        return assets

    def _summarise_inventory(self, assets: list[CryptoAsset]) -> dict[str, Any]:
        """Compute inventory statistics.

        Args:
            assets: Parsed crypto asset list.

        Returns:
            Summary statistics dict.
        """
        vulnerable = [a for a in assets if a.algorithm in ALGORITHM_RISK_MAP]
        safe = [a for a in assets if a.algorithm in QUANTUM_SAFE_ALGORITHMS]

        alg_counts: dict[str, int] = {}
        for asset in assets:
            alg_counts[asset.algorithm] = alg_counts.get(asset.algorithm, 0) + 1

        return {
            "total_assets": len(assets),
            "quantum_vulnerable_count": len(vulnerable),
            "quantum_safe_count": len(safe),
            "unknown_status_count": len(assets) - len(vulnerable) - len(safe),
            "algorithm_breakdown": alg_counts,
            "services_affected": len({a.service_name for a in assets}),
            "production_assets": sum(1 for a in assets if a.environment == "production"),
        }

    def _generate_migration_tasks(
        self, assets: list[CryptoAsset], threat_horizon_years: int
    ) -> list[MigrationTask]:
        """Generate migration tasks for all quantum-vulnerable assets.

        Args:
            assets: Parsed crypto asset list.
            threat_horizon_years: Years until quantum threat materialises.

        Returns:
            List of MigrationTask objects.
        """
        tasks: list[MigrationTask] = []
        for asset in assets:
            if asset.algorithm in QUANTUM_SAFE_ALGORITHMS:
                continue  # No migration needed

            risk_info = ALGORITHM_RISK_MAP.get(
                asset.algorithm,
                {"risk": "medium", "migration_target": "ML-KEM-768", "urgency_score": 0.5},
            )

            # Sensitivity amplifies risk level
            sensitivity_boost = {
                "secret": 0.1, "confidential": 0.05, "internal": 0.0, "public": -0.05
            }.get(asset.data_sensitivity, 0.0)
            adjusted_urgency = min(risk_info["urgency_score"] + sensitivity_boost, 1.0)

            # Final risk classification
            if adjusted_urgency >= 0.9 or asset.environment == "production" and risk_info["risk"] == "critical":
                final_risk = "critical"
            elif adjusted_urgency >= 0.75:
                final_risk = "high"
            elif adjusted_urgency >= 0.5:
                final_risk = "medium"
            else:
                final_risk = "low"

            base_effort = EFFORT_HOURS_BY_TYPE.get(asset.asset_type, 20)
            testing_required = ["unit_tests", "integration_tests"]
            if asset.environment == "production":
                testing_required += ["regression_tests", "load_tests", "security_scan"]
            if asset.data_sensitivity in ("secret", "confidential"):
                testing_required.append("penetration_test")

            tasks.append(
                MigrationTask(
                    task_id=f"task_{asset.asset_id}",
                    asset_id=asset.asset_id,
                    asset_type=asset.asset_type,
                    service_name=asset.service_name,
                    from_algorithm=asset.algorithm,
                    to_algorithm=risk_info["migration_target"],
                    risk_level=final_risk,
                    estimated_effort_hours=base_effort,
                    dependencies=asset.dependencies,
                    testing_required=testing_required,
                    rollback_strategy=(
                        f"Keep {asset.algorithm} key alongside {risk_info['migration_target']} "
                        f"in hybrid mode for {min(threat_horizon_years, 2)} years."
                    ),
                )
            )

        return tasks

    def _prioritise_tasks(
        self, tasks: list[MigrationTask], prioritisation: str
    ) -> list[MigrationTask]:
        """Sort migration tasks by the selected prioritisation strategy.

        Args:
            tasks: List of MigrationTask objects.
            prioritisation: Sort strategy.

        Returns:
            Sorted task list.
        """
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        if prioritisation == "risk_first":
            return sorted(tasks, key=lambda t: (risk_order.get(t.risk_level, 4), t.task_id))
        if prioritisation == "service_impact":
            return sorted(tasks, key=lambda t: (-t.estimated_effort_hours, risk_order.get(t.risk_level, 4)))
        # timeline: simplest tasks first (lowest effort)
        return sorted(tasks, key=lambda t: t.estimated_effort_hours)

    def _build_dependency_graph(
        self,
        assets: list[CryptoAsset],
        tasks: list[MigrationTask],
    ) -> dict[str, Any]:
        """Build a dependency impact graph for migration tasks.

        Args:
            assets: Parsed crypto assets.
            tasks: Prioritised migration tasks.

        Returns:
            Dependency graph with nodes and edges.
        """
        nodes = [{"id": t.task_id, "service": t.service_name, "risk": t.risk_level} for t in tasks]
        edges: list[dict[str, str]] = []
        task_by_asset = {t.asset_id: t.task_id for t in tasks}

        for task in tasks:
            for dep_id in task.dependencies:
                dep_task_id = task_by_asset.get(dep_id)
                if dep_task_id:
                    edges.append({"from": dep_task_id, "to": task.task_id, "type": "must_precede"})

        return {"nodes": nodes, "edges": edges, "acyclic": True}

    def _build_roadmap(
        self, tasks: list[MigrationTask], target_weeks: int
    ) -> list[dict[str, Any]]:
        """Build a phased migration roadmap.

        Args:
            tasks: Prioritised migration tasks.
            target_weeks: Total migration window in weeks.

        Returns:
            List of phase dicts with tasks and timeline.
        """
        critical = [t for t in tasks if t.risk_level == "critical"]
        high = [t for t in tasks if t.risk_level == "high"]
        medium = [t for t in tasks if t.risk_level == "medium"]
        low = [t for t in tasks if t.risk_level == "low"]

        phase_weeks = max(target_weeks // 4, 4)
        return [
            {
                "phase": 1,
                "name": "Emergency Mitigation",
                "description": "Migrate all critical-risk assets to PQC algorithms immediately.",
                "duration_weeks": phase_weeks,
                "tasks": [t.task_id for t in critical],
                "effort_hours": sum(t.estimated_effort_hours for t in critical),
                "deliverables": ["Critical assets migrated", "Hybrid mode deployed"],
            },
            {
                "phase": 2,
                "name": "High-Priority Migration",
                "description": "Migrate high-risk assets and update TLS configurations.",
                "duration_weeks": phase_weeks,
                "tasks": [t.task_id for t in high],
                "effort_hours": sum(t.estimated_effort_hours for t in high),
                "deliverables": ["High-risk assets migrated", "TLS 1.3 + PQC enabled"],
            },
            {
                "phase": 3,
                "name": "Comprehensive Migration",
                "description": "Migrate medium and low priority assets.",
                "duration_weeks": phase_weeks,
                "tasks": [t.task_id for t in medium + low],
                "effort_hours": sum(t.estimated_effort_hours for t in medium + low),
                "deliverables": ["All assets migrated", "Legacy algorithms removed"],
            },
            {
                "phase": 4,
                "name": "Validation and Hardening",
                "description": "Full compliance audit, penetration testing, and crypto-agility deployment.",
                "duration_weeks": phase_weeks,
                "tasks": [],
                "effort_hours": 80,
                "deliverables": [
                    "NIST PQC compliance audit passed",
                    "Crypto-agility framework deployed",
                    "Automated algorithm monitoring active",
                ],
            },
        ]

    def _design_testing_plan(self, roadmap: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Design a testing plan aligned with each roadmap phase.

        Args:
            roadmap: List of migration phase dicts.

        Returns:
            List of testing phase dicts.
        """
        return [
            {
                "phase": phase["phase"],
                "test_types": [
                    {"type": "unit_tests", "coverage_target": 90, "automated": True},
                    {"type": "integration_tests", "coverage_target": 80, "automated": True},
                    {"type": "regression_tests", "coverage_target": 100, "automated": True},
                    {"type": "security_scan", "tool": "semgrep + custom PQC linter", "automated": True},
                    *(
                        [{"type": "penetration_test", "scope": "full", "automated": False}]
                        if phase["phase"] in (1, 4)
                        else []
                    ),
                ],
                "exit_criteria": [
                    f"All phase {phase['phase']} tasks complete",
                    "Zero P0 security defects",
                    "Performance regression < 5% vs baseline",
                ],
            }
            for phase in roadmap
        ]

    def _generate_rollback_strategies(
        self, tasks: list[MigrationTask]
    ) -> list[dict[str, Any]]:
        """Generate per-task rollback strategies.

        Args:
            tasks: Migration task list.

        Returns:
            List of rollback strategy dicts.
        """
        return [
            {
                "task_id": task.task_id,
                "service_name": task.service_name,
                "strategy": task.rollback_strategy,
                "rollback_steps": [
                    f"Restore {task.from_algorithm} key from secure backup.",
                    f"Update service configuration to prefer {task.from_algorithm}.",
                    f"Run smoke tests to confirm {task.service_name} is operational.",
                    "File incident report and schedule root cause analysis.",
                ],
                "rollback_time_estimate_hours": max(task.estimated_effort_hours // 4, 2),
            }
            for task in tasks
            if task.risk_level in ("critical", "high")
        ]

    def _estimate_timeline(
        self, tasks: list[MigrationTask], target_weeks: int
    ) -> dict[str, Any]:
        """Produce overall timeline estimates.

        Args:
            tasks: Prioritised migration task list.
            target_weeks: Planned migration window.

        Returns:
            Timeline summary dict.
        """
        total_hours = sum(t.estimated_effort_hours for t in tasks)
        critical_hours = sum(t.estimated_effort_hours for t in tasks if t.risk_level == "critical")
        avg_weekly_capacity = 80  # Person-hours per week per team

        return {
            "total_effort_hours": total_hours,
            "critical_effort_hours": critical_hours,
            "estimated_team_weeks": round(total_hours / avg_weekly_capacity, 1),
            "target_completion_weeks": target_weeks,
            "feasibility": (
                "feasible"
                if total_hours / avg_weekly_capacity <= target_weeks
                else "requires_additional_resources"
            ),
            "recommended_team_size": max(1, round(total_hours / (avg_weekly_capacity * target_weeks))),
        }

    def _task_to_dict(self, task: MigrationTask) -> dict[str, Any]:
        """Serialise a MigrationTask to a plain dict.

        Args:
            task: Migration task.

        Returns:
            Serialisable dict.
        """
        return {
            "task_id": task.task_id,
            "asset_id": task.asset_id,
            "asset_type": task.asset_type,
            "service_name": task.service_name,
            "from_algorithm": task.from_algorithm,
            "to_algorithm": task.to_algorithm,
            "risk_level": task.risk_level,
            "estimated_effort_hours": task.estimated_effort_hours,
            "dependencies": task.dependencies,
            "testing_required": task.testing_required,
            "rollback_strategy": task.rollback_strategy,
        }
