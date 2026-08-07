"""Validation helpers for dashboard terminal command execution."""

import shlex
from pathlib import Path

ALLOWED_TERMINAL_COMMANDS = ("status", "diff", "export")

_COMMAND_SPECS = {
    "status": {
        "flags_no_value": {"--json"},
        "flags_with_value": {},
        "allow_positional": False,
    },
    "diff": {
        "flags_no_value": set(),
        "flags_with_value": {"--hours": "int"},
        "allow_positional": False,
    },
    "export": {
        "flags_no_value": set(),
        "flags_with_value": {
            "--format": {"json", "csv", "report", "ips", "targets", "urls", "c2"},
            "--output": "path",
            "-o": "path",
        },
        "allow_positional": False,
    },
}


def _is_safe_output_path(value: str) -> bool:
    path = Path(value)
    if path.is_absolute():
        return False
    if ".." in path.parts:
        return False
    return True


def parse_and_validate_terminal_command(raw_command: str) -> list[str]:
    """Parse and validate a dashboard terminal command."""
    command = (raw_command or "").strip()
    if not command:
        raise ValueError("No command provided")
    if len(command) > 512:
        raise ValueError("Command too long (max 512 chars)")
    if any(ord(ch) < 32 for ch in command):
        raise ValueError("Command contains control characters")

    try:
        parts = shlex.split(command)
    except ValueError as exc:
        raise ValueError(f"Invalid command syntax: {exc}") from exc

    if not parts:
        raise ValueError("No command provided")

    cmd_base = parts[0]
    if cmd_base not in _COMMAND_SPECS:
        raise PermissionError(f"Command not allowed. Permitted: {list(ALLOWED_TERMINAL_COMMANDS)}")

    spec = _COMMAND_SPECS[cmd_base]
    i = 1
    while i < len(parts):
        token = parts[i]
        if token in spec["flags_no_value"]:
            i += 1
            continue

        if token in spec["flags_with_value"]:
            i += 1
            if i >= len(parts):
                raise ValueError(f"Missing value for {token}")
            value = parts[i]
            rule = spec["flags_with_value"][token]
            if rule == "int":
                if not value.isdigit():
                    raise ValueError(f"Invalid value for {token}: {value}")
            elif rule == "path":
                if not _is_safe_output_path(value):
                    raise ValueError(f"Unsafe output path: {value}")
            elif isinstance(rule, set):
                if value not in rule:
                    raise ValueError(f"Invalid value for {token}: {value}")
            i += 1
            continue

        if token.startswith("-"):
            raise PermissionError(f"Argument not allowed: {token}")
        if not spec["allow_positional"]:
            raise PermissionError(f"Positional argument not allowed: {token}")
        i += 1

    return parts
