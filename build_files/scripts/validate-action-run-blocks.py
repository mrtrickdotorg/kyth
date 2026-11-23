#!/usr/bin/env python3
"""Lint the `run:` bodies of the repository's composite actions.

`actionlint` and `zizmor` in validate.sh only scan `.github/workflows`, so the
shell inside `.github/actions/*/action.yml` was never parsed or linted. A
mispathed script reference in `.github/actions/upload-r2/action.yml` survived
review and every ISO publish for weeks because nothing in the pipeline looked
at that file's run block. This walks every composite action, extracts each
bash run body, and checks it the way a shell script is checked: `bash -n`
first, then `shellcheck` at the same severity validate.sh uses for `*.sh`.

Actions are read with PyYAML (`requirements-validation.txt`) instead of a
hand-rolled reader: block scalars, quoting, anchors and flow mappings are
exactly the shapes a bespoke parser gets wrong, and getting one wrong here
would hide a step rather than fail it. A step that cannot be understood is an
error, never a silent skip.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

try:
    import yaml
except ImportError as exc:  # pragma: no cover - the message itself is the point
    raise ImportError(
        "PyYAML is required to lint composite actions; install "
        "requirements-validation.txt (python3 -m pip install -r requirements-validation.txt)"
    ) from exc

ROOT = Path(__file__).resolve().parents[2]
ACTIONS = ROOT / ".github/actions"
SEVERITY = "warning"


@dataclass(frozen=True)
class Step:
    """One step of a composite action, with its shell body ready to lint."""

    action: str
    name: str
    shell: str
    run: str


def parse_action(path: Path) -> list[Step]:
    """Every `run:` step in a composite action, whatever its shell."""
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: not valid YAML: {exc}") from exc

    runs = document.get("runs") if isinstance(document, dict) else None
    steps = runs.get("steps") if isinstance(runs, dict) else None
    if not isinstance(steps, list) or not steps:
        raise ValueError(f"{path}: runs.steps lists no steps")

    parsed: list[Step] = []
    for position, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            raise ValueError(f"{path}: step {position} is not a mapping")
        if "run" not in step:
            continue
        body = step["run"]
        if not isinstance(body, str) or not body.strip():
            raise ValueError(f"{path}: step {position} has an empty run key")
        # Every body is linted as a script, so normalise the terminator that
        # block and flow scalars would otherwise disagree on.
        normalised = body if body.endswith("\n") else body + "\n"
        parsed.append(
            Step(
                action=path.parent.name,
                name=str(step.get("name") or f"step {position}"),
                shell=str(step.get("shell") or "bash"),
                run=normalised,
            )
        )
    return parsed


def find_step(path: Path, name: str) -> Step:
    """The named step of one action; raises when the action has no such step."""
    steps = parse_action(path)
    for step in steps:
        if step.name == name:
            return step
    raise KeyError(f"{path}: no step named {name!r} (have {[step.name for step in steps]})")


def lint(step: Step, tool_dir: Path) -> list[str]:
    """Findings for one step body; empty means the shell is clean."""
    slug = re.sub(r"[^A-Za-z0-9]+", "-", step.name).strip("-").lower() or "step"
    script = tool_dir / f"{step.action}__{slug}.sh"
    script.write_text(step.run, encoding="utf-8")

    findings: list[str] = []
    parse = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True, check=False)
    if parse.returncode != 0:
        findings.append(f"{step.action} step {step.name!r}: bash -n failed\n{parse.stderr.strip()}")
    linted = subprocess.run(
        ["shellcheck", f"--severity={SEVERITY}", "--shell=bash", str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    if linted.returncode != 0:
        findings.append(f"{step.action} step {step.name!r}: shellcheck\n{linted.stdout.strip()}")
    return findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actions-dir", type=Path, default=ACTIONS)
    args = parser.parse_args(argv)

    if shutil.which("shellcheck") is None:
        print("shellcheck is not on PATH; run install-validation-tools.sh first", file=sys.stderr)
        return 1

    action_files = sorted(args.actions_dir.glob("*/action.yml"))
    if not action_files:
        print(f"No composite actions found under {args.actions_dir}", file=sys.stderr)
        return 1

    loaded: list[Step] = []
    for path in action_files:
        try:
            loaded += parse_action(path)
        except ValueError as exc:
            print(f"::error::{exc}", file=sys.stderr)
            return 1

    bash_steps = [step for step in loaded if step.shell.split()[0] == "bash"]
    findings: list[str] = []
    with tempfile.TemporaryDirectory(prefix="kyth-action-shell-") as tmp:
        for step in bash_steps:
            findings += lint(step, Path(tmp))

    for finding in findings:
        print(finding, file=sys.stderr)
    if findings:
        print(f"{len(findings)} problem(s) in {len(bash_steps)} bash run blocks", file=sys.stderr)
        return 1
    print(f"Checked {len(bash_steps)} bash run blocks in {len(action_files)} composite actions")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
