#!/usr/bin/env python3
"""
Claude Code Hook: Sensitive File Protection
============================================
This hook runs as a PreToolUse hook for Edit, Write, and Bash tools.
It prevents Claude Code from viewing, modifying, or leaking sensitive files
(such as .env, private keys, cloud credentials, or certificates).

Read more about hooks here: https://docs.anthropic.com/en/docs/claude-code/hooks

Configuration in .claude/settings.json:

{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit|Write|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/claude-code/examples/hooks/sensitive_file_protection_example.py"
          }
        ]
      }
    ]
  }
}
"""

import json
import re
import sys
from pathlib import PurePath

# Regex patterns matching sensitive file names or paths
_PROTECTED_PATTERNS = [
    r"(^|/)\.env(\.(local|production|staging|test))?$",
    r"(^|/)\.git(/|$)",
    r"(^|/)\.aws/(credentials|config)$",
    r"(^|/)\.ssh/(id_[^/]+|known_hosts|authorized_keys)$",
    r".*\.(pem|key|p12|pfx|pkcs12)$",
    r"(^|/)id_rsa(\.pub)?$",
    r"(^|/)\.netrc$",
]

# Patterns in shell commands that directly target protected resources
_BASH_PROTECTED_PATTERNS = [
    (
        r"(?:cat|less|more|head|tail|nano|vi|vim)\s+[^\s|&;]*\.(?:env|pem|key)\b",
        "Directly inspecting secrets or environment files in shell commands is restricted.",
    ),
    (
        r"rm\s+-(?:rf?|fr?)\s+(?:/|~|\$HOME|\.\.)",
        "Destructive recursive deletion of critical system or parent directories is blocked.",
    ),
]


def _is_protected_path(path_str: str) -> bool:
    """Check whether a given path string matches any protected pattern."""
    if not path_str:
        return False
    normalized = PurePath(path_str).as_posix()
    for pattern in _PROTECTED_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            # Allow harmless template/example files like .env.example
            if normalized.endswith((".example", ".sample", ".template")):
                continue
            return True
    return False


def _validate_tool_call(tool_name: str, tool_input: dict) -> list[str]:
    """Validate incoming tool payload and return a list of error messages if violations occur."""
    issues = []

    # Check file modification or inspection tools
    if tool_name in {"Edit", "Write", "View"}:
        file_path = tool_input.get("file_path", "") or tool_input.get("path", "")
        if _is_protected_path(file_path):
            issues.append(
                f"Access to protected sensitive file '{file_path}' is blocked. "
                "Do not read, modify, or expose credentials or private environment secrets. "
                "Use sample configuration files (e.g., .env.example) instead."
            )

    # Check shell commands
    elif tool_name == "Bash":
        command = tool_input.get("command", "")
        for pattern, message in _BASH_PROTECTED_PATTERNS:
            if re.search(pattern, command):
                issues.append(message)

    return issues


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        # Exit code 1 shows stderr to the user but not to Claude
        sys.exit(1)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    issues = _validate_tool_call(tool_name, tool_input)
    if issues:
        for message in issues:
            print(f"• {message}", file=sys.stderr)
        # Exit code 2 blocks the tool call and feeds stderr back to Claude
        sys.exit(2)

    # Exit code 0 allows the tool execution
    sys.exit(0)


if __name__ == "__main__":
    main()
