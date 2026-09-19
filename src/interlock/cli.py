from __future__ import annotations

import argparse
import json
import sys

from .kernel import Kernel
from .vault import Vault


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="interlock", description="Gate a tool call.")
    parser.add_argument("command", choices=["gate"])
    parser.add_argument("--claude-code", action="store_true")
    parser.add_argument("--tool", default="bash")
    parser.add_argument("--args", default="{}")
    parser.add_argument("--goal", default="")
    parser.add_argument("--asked", action="store_true")
    args = parser.parse_args(argv)

    payload = json.loads(sys.stdin.read() or args.args)
    if args.claude_code and isinstance(payload, dict) and "tool_name" in payload:
        tool = str(payload.get("tool_name") or args.tool)
        call_args = {str(k): str(v) for k, v in (payload.get("tool_input") or {}).items()}
        goal = str(payload.get("user_goal") or args.goal)
        asked = bool(payload.get("user_explicitly_asked") or args.asked)
    else:
        tool = args.tool
        call_args = {str(k): str(v) for k, v in payload.items()} if isinstance(payload, dict) else {"command": str(payload)}
        goal = args.goal
        asked = args.asked

    verdict = Kernel(Vault.demo()).gate(tool=tool, args=call_args, user_goal=goal, user_explicitly_asked=asked)
    print(json.dumps({"decision": verdict.decision, "reason": verdict.reason, "canary_hits": verdict.canary_hits}, indent=2))
    if verdict.decision == "block":
        return 2
    if verdict.decision == "ask":
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
