"""Service-specific settings for aumos-quantum-readiness.

All standard AumOS configuration is inherited from AumOSSettings.
Repo-specific settings use the AUMOS_QUANTUM_ env prefix.
"""

from pydantic_settings import SettingsConfigDict

from aumos_common.config import AumOSSettings


class Settings(AumOSSettings):
    """Settings for aumos-quantum-readiness.

    Inherits all standard AumOS settings (database, kafka, keycloak, etc.)
    and adds quantum-readiness-specific configuration.

    Environment variable prefix: AUMOS_QUANTUM_
    """

    service_name: str = "aumos-quantum-readiness"

    # PQC engine settings
    pqc_kyber_key_size: int = 1024
    pqc_dilithium_security_level: int = 3
    pqc_hybrid_mode_enabled: bool = True

    # Harvest defense settings
    harvest_risk_threshold: float = 0.75
    harvest_scan_interval_hours: int = 24

    # Compliance settings
    nist_pqc_standard_version: str = "FIPS-203"
    compliance_check_timeout_seconds: int = 30

    model_config = SettingsConfigDict(env_prefix="AUMOS_QUANTUM_")
