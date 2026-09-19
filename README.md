# Interlock

Wrap every tool call. That is the whole product.

Your agent already does `plan → tool → execute`. Interlock sits on the last arrow. The model keeps planning. The kernel decides whether bash, HTTP, write, or send actually happens.

The LLM never holds a real secret. It gets canaries and placeholders. Real keys live in a vault process. On ALLOW to an allowlisted host, Interlock swaps the placeholder at egress — outside the model.

```
agent proposes a tool call
        │
        ▼
   interlock.gate()     detectors → Jev Noul battery → policy in code
        │
        ├── BLOCK   refuse, tell the agent no
        ├── ASK     you confirm (drop table, force-push, …)
        └── ALLOW   execute; swap placeholder → real secret at egress
```

You do not “run Interlock” as an app. You call `gate()`.

## Install

```bash
pip install -e .
# optional: export TYPESAFE_API_KEY=…  and Kernel(..., sensor="jev")
```

## Use it

```python
from interlock import Kernel, Vault

kernel = Kernel(Vault.demo())

def run_tool(name, args, goal):
    v = kernel.gate(tool=name, args=args, user_goal=goal)
    if v.decision == "block":
        raise PermissionError(v.reason)
    if v.decision == "ask":
        return v  # surface to the human
    return execute(name, kernel.swap_at_egress(args, v.swaps))
```

### Claude Code

Put this in `~/.claude/settings.json`. Stdin is the tool call; exit 2 blocks.

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "*",
      "hooks": [{ "type": "command", "command": "interlock gate --claude-code" }]
    }]
  }
}
```

Tonight: put canaries in the agent env, not real AWS keys. Ask it to “run the tests” in a repo with a poisoned README. Unguarded POSTs the key. Interlock blocks.

## Why this is not another firewall

Launch-week Jev firewalls ask *“is this tool call dangerous?”* after the LLM already decided, with **real secrets still in scope**.

1. Secrets never enter the agent.
2. Canaries are active. Any use off-allowlist is a catch — including silent scheming with no injection.
3. Jev scores hazards. **This policy file picks allow / ask / block.** A model that cannot generate text cannot be talked into emitting a secret.

## Regression suite

38 cases: attacks, benign, and hard negatives (authorized destruction). This is a regression set, **not a blind paper**. Wire Jev and run your own held-out attacks before you trust a number.

## License

MIT
