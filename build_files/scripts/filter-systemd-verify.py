#!/usr/bin/env python3
"""Filter only the known removed CPUAccounting warning from external units."""
from __future__ import annotations

import re
import sys
from pathlib import Path


TRUSTED_HOST_DIRS = tuple(
    Path(path).resolve(strict=False)
    for path in (
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/run/systemd/system",
        "/etc/systemd/system",
    )
)


def resolved(path: str) -> Path:
    return Path(path).resolve(strict=False)


def is_below(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def main() -> int:
    owned = {resolved(path) for path in sys.argv[1:]}
    warning = re.compile(
        r"^(?P<path>[^:]+):\d+: Support for option CPUAccounting= has been removed and it is ignored$"
    )
    unexpected = []
    for line in sys.stdin:
        line = line.rstrip("\n")
        match = warning.fullmatch(line)
        if match:
            path = resolved(match.group("path"))
            if path not in owned and any(is_below(path, root) for root in TRUSTED_HOST_DIRS):
                continue
        if line:
            unexpected.append(line)
    if unexpected:
        print("\n".join(unexpected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
