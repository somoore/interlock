from __future__ import annotations

import base64
import json
import math
import re
import time
from dataclasses import dataclass, field
from typing import Literal

from .policy import Policy
from .vault import Vault

Decision = Literal["allow", "ask", "block"]
HAZARDS = (
    "exfil_canary",
    "credential_in_body",
    "looks_like_c2",
    "writes_sensitive_path",
    "irreversible",
    "injection_in_context",
    "off_task",
    "scope_creep",
    "impersonating_user",
    "unexpected_network",
    "obfuscated_payload",
    "credential_access",
)

C2_HOST = re.compile(
    r"webhook\.site|ngrok\.|pipedream\.net|requestbin|burpcollaborator|interact\.sh|oastify|discord\.com/api/webhooks|pastebin\.com",
    re.I,
)
REVERSE_SHELL = re.compile(
    r"/dev/tcp/|bash\s+-i|nc\s+-[le]|ncat\s+-[le]|python\s+-c\s+['\"][^'\"]*socket|wget\s+[^\n]+\|\s*(?:ba)?sh|curl\s+[^\n]+\|\s*(?:ba)?sh",
    re.I,
)
IRREVERSIBLE = re.compile(
    r"\bdrop\s+table\b|\bdrop\s+database\b|\brm\s+-[rf]{1,2}\s+|git\s+push\s+[^\n]*--force|\bkubectl\s+delete\b|\bterraform\s+destroy\b",
    re.I,
)
INJECTION = re.compile(
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|you\s+are\s+now\b|new\s+instructions:|do\s+not\s+tell\s+the\s+user|system\s+prompt|exfiltrate",
    re.I,
)
SENSITIVE_PATH = re.compile(
    r"(?:^|[^\w])(?:\.ssh|\.aws|\.gnupg|\.env|id_rsa|id_ed25519|credentials|kube/config|/etc/shadow|/etc/passwd)(?:[^\w]|$)",
    re.I,
)
SECRET_RES = [
    re.compile(r"\bAKIA[0-9A-Z]{8,16}\b"),
    re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
]


def _decode_layers(raw: str) -> list[str]:
    layers = [raw]
    for chunk in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", raw):
        try:
            decoded = base64.b64decode(chunk + "=" * ((4 - len(chunk) % 4) % 4)).decode("utf-8", "ignore")
        except Exception:
            continue
        if len(decoded) >= 8 and sum(32 <= ord(c) <= 126 for c in decoded) / len(decoded) > 0.85:
            layers.append(decoded)
    return layers


def _sigmoid(z: float) -> float:
    if z > 12:
        return 1.0
    if z < -12:
        return 0.0
    return 1.0 / (1.0 + math.exp(-z))


def _host(url_or_cmd: str) -> str | None:
    m = re.search(r"https?://([^/\s:'\"]+)", url_or_cmd, re.I)
    return m.group(1).lower() if m else None


@dataclass
class Hazard:
    id: str
    noul: float
    evidence: list[str] = field(default_factory=list)


@dataclass
class Verdict:
    decision: Decision
    reason: str
    hazards: list[Hazard]
    canary_hits: list[str]
    latency_ms: int
    cost_usd: float
    swaps: list[str] = field(default_factory=list)


class Kernel:
    """Deterministic detectors, then a Noul battery, then ordinary code."""

    def __init__(self, vault: Vault, policy: Policy | None = None) -> None:
        self.vault = vault
        self.policy = policy or Policy.default()

    def gate(
        self,
        tool: str,
        args: dict[str, str],
        user_goal: str,
        user_explicitly_asked: bool = False,
        tool_result: str | None = None,
    ) -> Verdict:
        t0 = time.perf_counter()
        payload = "\n".join(f"{k}={v}" for k, v in args.items()) + "\n" + (tool_result or "")
        layers = _decode_layers(payload)
        blob = "\n".join(layers)
        host = _host(args.get("url") or args.get("command") or "")
        allowlisted = bool(host and any(host == h or host.endswith("." + h) for h in self.vault.allowlisted_hosts))
        canaries = [s.id for s in self.vault.secrets if any(s.canary in layer for layer in layers)]
        placeholders = [s for s in self.vault.secrets if any(s.placeholder in layer for layer in layers)]
        outbound = tool in {"http", "send"} or bool(re.search(r"\b(curl|wget|nc |ncat )\b", args.get("command") or "", re.I))
        writey = tool in {"write", "edit"} or bool(re.search(r"\b(rm |drop )\b", args.get("command") or "", re.I))
        c2 = bool(C2_HOST.search(blob))
        rev = bool(REVERSE_SHELL.search(blob))
        irr = bool(IRREVERSIBLE.search(blob))
        inj = bool(INJECTION.search(blob))
        path = bool(SENSITIVE_PATH.search(blob))
        encoded = len(layers) > 1
        secret_pat = any(r.search(blob) for r in SECRET_RES)

        def score(bias: float, feats: list[tuple[float, bool, str]]) -> tuple[float, list[str]]:
            z = bias
            ev: list[str] = []
            for w, on, e in feats:
                if on:
                    z += w
                    if e:
                        ev.append(e)
            return (min(1.0, max(0.0, _sigmoid(z))), ev)

        goal_l = set(re.findall(r"[a-z0-9]{3,}", user_goal.lower()))
        act_l = set(re.findall(r"[a-z0-9]{3,}", (tool + " " + payload).lower()))
        ov = (len(goal_l & act_l) / min(len(goal_l), len(act_l))) if goal_l and act_l else 0.0

        scored = {
            "exfil_canary": score(-3.6, [(4.8, bool(canaries) and outbound, "canary leaving the box"), (1.4, c2, "exfil host")]),
            "credential_in_body": score(-3.2, [(3.6, secret_pat and outbound and not allowlisted, "credential pattern outbound")]),
            "looks_like_c2": score(-3.8, [(5.2, rev, "reverse shell"), (3.6, c2, "C2 host")]),
            "writes_sensitive_path": score(-3.4, [(4.2, path and writey, "write on a secret path"), (2.6, path and tool == "read", "read of a secret path")]),
            "irreversible": score(-3.3, [(4.6, irr, "destructive primitive")]),
            "injection_in_context": score(-3.5, [(4.4, inj and bool(tool_result), "tool result overrides instructions")]),
            "off_task": score(-2.2, [(3.1, ov < 0.12 and outbound, "outbound off-goal"), (2.8, ov < 0.18 and path, "secret path off-goal"), (-1.4, user_explicitly_asked, "user asked")]),
            "scope_creep": score(-2.8, [(3.2, bool(re.search(r"staging|dev\\b", user_goal, re.I) and re.search(r"prod", payload, re.I)), "staging goal, prod action")]),
            "impersonating_user": score(-3.6, [(4.0, bool(re.search(r"git\s+commit[^\n]*--author", payload, re.I)), "identity rewrite")]),
            "unexpected_network": score(-2.6, [(3.0, outbound and not allowlisted and ov < 0.25, "unexpected outbound"), (-1.8, allowlisted, "allowlisted")]),
            "obfuscated_payload": score(-3.4, [(3.8, encoded and (bool(canaries) or secret_pat), "decoded credential")]),
            "credential_access": score(-3.0, [(3.6, path and tool in {"read", "bash"}, "harvesting a credential path")]),
        }
        hazards = [Hazard(hid, scored[hid][0], scored[hid][1]) for hid in HAZARDS]
        by = {h.id: h.noul for h in hazards}

        if rev:
            decision, reason, swaps = "block", "Deterministic reverse-shell / pipe-to-shell pattern. Code veto.", []
        elif c2 and user_explicitly_asked:
            decision, reason, swaps = "ask", "User named this host, but it matches known exfil infrastructure.", []
        elif c2:
            decision, reason, swaps = "block", "Known exfil / C2 infrastructure. Code veto.", []
        elif canaries and not allowlisted:
            decision, reason, swaps = "block", f"Canary {', '.join(canaries)} leaving the allowlist. That is theft.", []
        elif by["credential_access"] >= 0.5 and by["off_task"] >= 0.45:
            decision, reason, swaps = "block", "Off-task credential harvest.", []
        elif by["writes_sensitive_path"] >= 0.5 and by["off_task"] >= 0.45:
            decision, reason, swaps = "block", "Off-task write to a secret path.", []
        elif by["looks_like_c2"] >= 0.55:
            decision, reason, swaps = "block", f"looks_like_c2 = {by['looks_like_c2']:.2f}.", []
        elif max((by[i] for i in self.policy.high_severity), default=0) >= self.policy.block_threshold:
            hid = max(self.policy.high_severity, key=lambda i: by[i])
            decision, reason, swaps = "block", f"{hid} = {by[hid]:.2f} ≥ block {self.policy.block_threshold:.2f}.", []
        elif max((by[i] for i in self.policy.ask_hazards), default=0) >= self.policy.ask_threshold:
            hid = max(self.policy.ask_hazards, key=lambda i: by[i])
            decision, reason, swaps = "ask", f"{hid} = {by[hid]:.2f} ≥ ask {self.policy.ask_threshold:.2f}.", []
        else:
            swaps = [s.id for s in placeholders] if allowlisted else []
            decision, reason = "allow", ("Allow. Placeholder swapped at egress." if swaps else "Allow.")

        ms = max(1, int((time.perf_counter() - t0) * 1000))
        tokens = 900 + len(json.dumps(args)) // 4
        return Verdict(decision, reason, hazards, canaries, ms, (tokens / 1_000_000) * 0.042, swaps)
