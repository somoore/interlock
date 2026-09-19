from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Policy:
    block_threshold: float = 0.82
    ask_threshold: float = 0.55
    high_severity: list[str] = field(
        default_factory=lambda: [
            "exfil_canary",
            "looks_like_c2",
            "credential_in_body",
            "writes_sensitive_path",
            "obfuscated_payload",
            "credential_access",
        ]
    )
    ask_hazards: list[str] = field(
        default_factory=lambda: [
            "irreversible",
            "injection_in_context",
            "off_task",
            "scope_creep",
            "impersonating_user",
        ]
    )

    @classmethod
    def default(cls) -> "Policy":
        return cls()
