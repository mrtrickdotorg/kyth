#!/usr/bin/env python3
"""Fail when the build_files/ mirror of kyth_shared / kyth-installer drifts.

The image's config stage installs ``src/kyth_shared`` and ``src/kyth-installer``
(Dockerfile), while the tests, ruff and the coverage floors read
``build_files/kyth_shared`` and ``build_files/kyth-installer``. The repo keeps
those two paths as tracked symlinks to ``../src/...`` so there is exactly one
copy of the bytes and drift cannot happen. A checkout can still lose that
guarantee: a merge or a stray ``cp -r`` can materialize a real directory, and
someone can repoint the link at a stale tree. Either way validation would pass
for bytes the image never runs while the image carries edits no test saw.

So each pair must be a symlink resolving to its src/ tree, or — if it is a
real directory — be byte-identical to it.
"""

import argparse
import hashlib
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# (tree the image installs, tree the tests and coverage gate read)
MIRROR_PAIRS = (
    ("src/kyth_shared", "build_files/kyth_shared"),
    ("src/kyth-installer", "build_files/kyth-installer"),
)

# Generated in place by running the tests against either copy; comparing them
# would fail on whichever side happened to be imported last.
IGNORED_DIRS = frozenset({"__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"})
IGNORED_DIR_SUFFIXES = (".egg-info",)
IGNORED_SUFFIXES = frozenset({".pyc", ".pyo"})
IGNORED_NAMES = frozenset({".DS_Store"})


def _is_ignored(relative: Path) -> bool:
    if relative.name in IGNORED_NAMES or relative.suffix in IGNORED_SUFFIXES:
        return True
    return any(
        part in IGNORED_DIRS or part.endswith(IGNORED_DIR_SUFFIXES)
        for part in relative.parts[:-1]
    )


def snapshot(root: Path) -> dict[str, str]:
    """Map every comparable file under ``root`` to its SHA-256."""
    files = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if _is_ignored(relative):
            continue
        files[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def compare_pair(repo_root: Path, image_tree: str, tested_tree: str) -> list[str]:
    """Return one message per difference; an empty list means the pair mirrors."""
    image = repo_root / image_tree
    tested = repo_root / tested_tree
    if not image.is_dir():
        return [f"missing tree: {image_tree}"]
    if tested.is_symlink():
        # The supported shape: one copy of the bytes, reached from both paths.
        resolved = tested.resolve()
        if resolved != image.resolve():
            return [
                f"{tested_tree} is a symlink to {os.readlink(tested)!r}, but it "
                f"must resolve to {image_tree}"
            ]
        return []
    if not tested.is_dir():
        return [
            f"missing tree: {tested_tree} (expected a symlink to {image_tree}; "
            "enable core.symlinks if this is a checkout that drops them)"
        ]
    image_files = snapshot(image)
    tested_files = snapshot(tested)
    problems = [
        f"{tested_tree} is a real copy of {image_tree}, not a symlink, and "
        f"{image_tree}/{name} has no copy in {tested_tree}/{name}"
        for name in sorted(image_files.keys() - tested_files.keys())
    ]
    problems.extend(
        f"{tested_tree}/{name} has no copy in {image_tree}/{name}"
        for name in sorted(tested_files.keys() - image_files.keys())
    )
    problems.extend(
        f"{name} differs between {image_tree}/ and {tested_tree}/"
        for name in sorted(image_files.keys() & tested_files.keys())
        if image_files[name] != tested_files[name]
    )
    return problems


def describe_pair(repo_root: Path, image_tree: str, tested_tree: str) -> str:
    tested = repo_root / tested_tree
    if tested.is_symlink():
        return f"{tested_tree} -> {os.readlink(tested)} (one copy of {image_tree})"
    return f"{image_tree} == {tested_tree} ({len(snapshot(tested))} files byte-identical)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="repository root to inspect (tests point this at a fixture)",
    )
    args = parser.parse_args(argv)

    failed = False
    for image_tree, tested_tree in MIRROR_PAIRS:
        problems = compare_pair(args.root, image_tree, tested_tree)
        if not problems:
            print(describe_pair(args.root, image_tree, tested_tree))
            continue
        failed = True
        print(f"{tested_tree} no longer mirrors {image_tree}:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)

    if failed:
        print(
            "The image installs src/, but the tests and coverage floors read "
            "build_files/. Keep build_files/kyth_shared and "
            "build_files/kyth-installer as symlinks to ../src/... so the "
            "shipped modules and the tested modules stay the same bytes.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
