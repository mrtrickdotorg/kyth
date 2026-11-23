#!/usr/bin/env python3
"""Lint the `run:` bodies of the repository's composite actions.

`actionlint` and `zizmor` in validate.sh only scan `.github/workflows`, so the
shell inside `.github/actions/*/action.yml` was never parsed or linted. A
mispathed script reference in `.github/actions/upload-r2/action.yml` survived
review and every ISO publish for weeks because nothing in the pipeline looked
at that file's run block. This walks every composite action, extracts each
bash run body, and checks it the way a shell script is checked: `bash -n`
first, then `shellcheck` at the same severity validate.sh uses for `*.sh`.

Composite actions are read without a YAML library: validate.sh must not depend
on PyYAML being installed. The parser understands the block forms actions use
(`run: |`, `run: |-`, `run: >`, `run: >-`) and single-line scalars; an
unrecognised form is an error, never a silent skip, because silently skipping
is the failure mode this check exists to remove.
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

ROOT = Path(__file__).resolve().parents[2]
ACTIONS = ROOT / ".github/actions"
SEVERITY = "warning"
BLOCK_SCALAR = re.compile(r"^[|>][+-]?$")


@dataclass(frozen=True)
class Step:
    """One step of a composite action, with its shell body already dedented."""

    action: str
    name: str
    shell: str
    run: str


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _scalar(value: str) -> str:
    """A YAML scalar with its quotes removed only when the whole value is quoted.

    Stripping quote characters from both ends unconditionally truncates a plain
    scalar like `rm -f "${HOME}/config.json"`, whose trailing quote is content.
    """
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _block_body(lines: list[str], start: int, indent: int, folded: bool = False) -> tuple[str, int]:
    """The block scalar beginning at `start`, dedented; returns it and the last index."""
    body: list[str] = []
    index = start
    while index < len(lines):
        line = lines[index]
        if line.strip() and _indent(line) <= indent:
            break
        body.append(line)
        index += 1
    while body and not body[-1].strip():
        body.pop()
    levels = [_indent(line) for line in body if line.strip()]
    dedent = min(levels) if levels else indent + 1
    text = [line[dedent:] if line.strip() else "" for line in body]
    if not folded:
        return "\n".join(text), index - 1
    # `>` joins consecutive non-blank lines with a space and keeps a blank line
    # as a line break; without this the linted body would not be what runs.
    folded_lines: list[str] = []
    pending: list[str] = []
    for line in text:
        if line.strip():
            pending.append(line.strip())
            continue
        folded_lines.append(" ".join(pending))
        pending = []
    folded_lines.append(" ".join(pending))
    return "\n".join(folded_lines), index - 1


def parse_action(path: Path) -> list[Step]:
    """Every `run:` step in a composite action, whatever its shell."""
    lines = path.read_text(encoding="utf-8").splitlines()
    try:
        runs_at = next(i for i, line in enumerate(lines) if line.rstrip() == "runs:")
        steps_at = next(
            i for i in range(runs_at, len(lines))
            if lines[i].strip() == "steps:" and _indent(lines[i]) > _indent(lines[runs_at])
        )
    except StopIteration:
        raise ValueError(f"{path}: no runs.steps section") from None

    step_indent = _indent(lines[steps_at]) + 2
    starts = [
        i for i in range(steps_at + 1, len(lines))
        if lines[i].lstrip().startswith("- ") and _indent(lines[i]) == step_indent
    ]
    if not starts:
        raise ValueError(f"{path}: runs.steps lists no steps")

    key_indent = step_indent + 2
    parsed: list[Step] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        name = ""
        shell = ""
        body: str | None = None
        index = start
        while index < end:
            line = lines[index]
            if index == start:
                # `- name: Foo` puts the first key on the dash line; re-indent
                # it so the key scan below sees it like every other key.
                line = " " * key_indent + line.strip()[2:]
            if _indent(line) == key_indent and line.strip():
                key, _, value = line.strip().partition(":")
                value = value.strip()
                if BLOCK_SCALAR.match(value):
                    # Skip any block scalar, not just run's: a `with: body: |`
                    # payload can contain lines shaped like step keys.
                    block, last = _block_body(
                        lines, index + 1, key_indent, folded=value.startswith(">"))
                    if key == "run":
                        body = block
                    index = last
                elif key == "name":
                    name = _scalar(value)
                elif key == "shell":
                    shell = _scalar(value)
                elif key == "run":
                    if not value:
                        raise ValueError(f"{path}: step {name or start} has an empty run key")
                    body = _scalar(value) + "\n"
            index += 1
        if body is None:
            continue
        # Every body is linted as a script, so normalise the terminator that a
        # block scalar and an inline scalar would otherwise disagree on.
        normalised = body if body.endswith("\n") else body + "\n"
        parsed.append(Step(action=path.parent.name, name=name or f"step {position + 1}",
                           shell=shell or "bash", run=normalised))
    return parsed


def find_step(path: Path, name: str) -> Step:
    """The named step of one action; raises when the action has no such step."""
    for step in parse_action(path):
        if step.name == name:
            return step
    available = [step.name for step in parse_action(path)]
    raise KeyError(f"{path}: no step named {name!r} (have {available})")


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
        capture_output=True, text=True, check=False,
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
