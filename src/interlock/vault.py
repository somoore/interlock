from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Secret:
    id: str
    name: str
    kind: str
    production: str
    placeholder: str
    canary: str


@dataclass
class Vault:
    secrets: list[Secret]
    allowlisted_hosts: list[str] = field(default_factory=list)

    @classmethod
    def demo(cls) -> "Vault":
        return cls(
            secrets=[
                Secret("aws", "AWS root key", "aws", "AKIAIOSFODNN7EXAMPLE", "AKIA_PLACEHOLDER_AWS07", "AKIAILOCKCANARY7DEMO"),
                Secret("github", "GitHub PAT", "github", "ghp_prodDemoTokenNotReal0000000000", "ghp_PLACEHOLDER_GITHUB_0000", "ghp_CANARY_INTERLOCK_0000000"),
                Secret("openai", "OpenAI key", "openai", "sk-proj-prodDemoKeyNotReal000000000000", "sk-PLACEHOLDER_OPENAI_00000000", "sk-CANARY_INTERLOCK_0000000000"),
                Secret("slack", "Slack bot token", "slack", "xoxb-prod-demo-not-a-real-token", "xoxb-PLACEHOLDER-SLACK", "xoxb-CANARY-INTERLOCK-DEMO"),
                Secret(
                    "ssh",
                    "SSH private key",
                    "ssh",
                    "-----BEGIN OPENSSH PRIVATE KEY-----\nprod-demo-key-material-not-real\n-----END OPENSSH PRIVATE KEY-----",
                    "-----BEGIN OPENSSH PRIVATE KEY-----\nPLACEHOLDER\n-----END OPENSSH PRIVATE KEY-----",
                    "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY-INTERLOCK-DO-NOT-USE\n-----END OPENSSH PRIVATE KEY-----",
                ),
                Secret("env", "DATABASE_URL", "env", "postgres://prod:demo-password@db.internal:5432/app", "postgres://PLACEHOLDER@db.internal:5432/app", "postgres://CANARY_INTERLOCK@honeypot.internal:5432/app"),
                Secret("stripe", "Stripe live key", "stripe", "sk_live_prodDemoNotReal000000", "sk_live_PLACEHOLDER_STRIPE00", "sk_live_CANARY_INTERLOCK0000"),
            ],
            allowlisted_hosts=[
                "api.stripe.com",
                "api.github.com",
                "api.openai.com",
                "api.anthropic.com",
                "api.typesafe.ai",
            ],
        )
