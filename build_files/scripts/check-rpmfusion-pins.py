#!/usr/bin/env python3
"""Detect upstream republishes of the RPM Fusion bootstrap RPMs.

The image build installs two RPM Fusion release RPMs after verifying them
against SHA256 pins in
build_files/scripts/packages/03-rpmfusion-and-repo-hygiene.sh. RPM Fusion
republishes those RPMs inside a Fedora release (45-1 -> 45-2 shipped mid-cycle
in November 2026), so a pin goes stale with no change on our side and the next
build dies at the checksum gate. This check compares each pin with what is
published today and prints the replacement hash, so the bump can land on its
own schedule instead of being discovered by a red build.

Two hosts must agree before drift is reported: the origin the build itself
downloads from (download1.rpmfusion.org) and an independent member of the
mirrors.rpmfusion.org pool. A mismatch confirmed by only one host is a
mid-rollout, not a reason to rewrite a security pin.

Exit codes:
  0  every pin matches upstream
  1  drift confirmed by two hosts (bump the pins)
  2  inconclusive: fetch failure or hosts disagree (re-run; do not bump blind)
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

ROOT = Path(__file__).resolve().parents[2]
FRAGMENT = ROOT / "build_files/scripts/packages/03-rpmfusion-and-repo-hygiene.sh"

ORIGIN_URL = "https://download1.rpmfusion.org/{channel}/fedora/{filename}"
MIRROR_URL = "https://mirrors.rpmfusion.org/{channel}/fedora/{filename}"
PIN_VARIABLES = (
    ("free", "RPMFUSION_FREE_SHA256"),
    ("nonfree", "RPMFUSION_NONFREE_SHA256"),
)
GUARD_PATTERN = re.compile(r'fedora_release\}?"\s*==\s*"(\d+)"')

OK = "OK"
DRIFT = "DRIFT"
INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class Pins:
    """The Fedora release the fragment enforces, and the hash pinned for it."""

    release: str
    hashes: dict[str, str]


@dataclass(frozen=True)
class Artifact:
    sha256: str
    size: int
    last_modified: str


@dataclass(frozen=True)
class Verdict:
    channel: str
    filename: str
    pinned: str
    status: str
    note: str
    origin: Artifact | None
    mirror: Artifact | None
    origin_error: str | None = None
    mirror_error: str | None = None


def parse_pins(text: str) -> Pins:
    """Read the enforced release and both pins out of the build fragment."""
    guard = GUARD_PATTERN.search(text)
    if guard is None:
        raise ValueError(
            'no Fedora release guard (fedora_release" == "NN") found; '
            "the fragment no longer pins a single release"
        )
    hashes: dict[str, str] = {}
    for channel, variable in PIN_VARIABLES:
        match = re.search(rf'^{variable}="([0-9a-f]{{64}})"$', text, re.MULTILINE)
        if match is None:
            raise ValueError(f"{variable} is missing or is not a 64-character hex digest")
        hashes[channel] = match.group(1)
    return Pins(release=guard.group(1), hashes=hashes)


def bootstrap_filename(release: str, channel: str) -> str:
    return f"rpmfusion-{channel}-release-{release}.noarch.rpm"


def probe(url: str, timeout: float = 60.0) -> Artifact:
    """Download one URL and fingerprint exactly the bytes served."""
    request = urllib.request.Request(url, headers={"User-Agent": "kyth-rpmfusion-pin-check"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https URLs
        payload = response.read()
        headers = response.headers
    return Artifact(
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
        last_modified=headers.get("Last-Modified", "unknown"),
    )


def judge(pinned: str, origin: Artifact | None, mirror: Artifact | None) -> tuple[str, str]:
    """Decide one channel from what the origin and the mirror pool serve."""
    if origin is None:
        return INCONCLUSIVE, "origin unreachable"
    if origin.sha256 == pinned:
        if mirror is not None and mirror.sha256 != pinned:
            return OK, f"mirror lags (serves {mirror.sha256[:12]}); origin still matches the pin"
        return OK, "origin matches the pin"
    if mirror is None:
        return INCONCLUSIVE, "origin differs from the pin and no second host confirmed it"
    if mirror.sha256 == origin.sha256:
        return DRIFT, "origin and its mirror pool both serve bytes the pin does not match"
    if mirror.sha256 == pinned:
        return INCONCLUSIVE, "origin republished ahead of the mirror pool; re-run to confirm"
    return INCONCLUSIVE, "origin, mirror and pin all differ; re-run to confirm"


def fetch(prober: Callable[[str, float], Artifact], url: str, timeout: float) -> tuple[Artifact | None, str | None]:
    try:
        return prober(url, timeout), None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, str(exc)


def verify(pins: Pins, prober: Callable[[str, float], Artifact] = probe, timeout: float = 60.0) -> list[Verdict]:
    verdicts: list[Verdict] = []
    for channel, _variable in PIN_VARIABLES:
        filename = bootstrap_filename(pins.release, channel)
        origin, origin_error = fetch(prober, ORIGIN_URL.format(channel=channel, filename=filename), timeout)
        mirror, mirror_error = fetch(prober, MIRROR_URL.format(channel=channel, filename=filename), timeout)
        status, note = judge(pins.hashes[channel], origin, mirror)
        verdicts.append(
            Verdict(
                channel=channel,
                filename=filename,
                pinned=pins.hashes[channel],
                status=status,
                note=note,
                origin=origin,
                mirror=mirror,
                origin_error=origin_error,
                mirror_error=mirror_error,
            )
        )
    return verdicts


def exit_code(verdicts: Sequence[Verdict]) -> int:
    statuses = {verdict.status for verdict in verdicts}
    if DRIFT in statuses:
        return 1
    if INCONCLUSIVE in statuses:
        return 2
    return 0


def _describe(label: str, artifact: Artifact | None, error: str | None) -> str:
    if artifact is None:
        return f"  {label:<7} unreachable ({error})"
    return f"  {label:<7} {artifact.sha256}  {artifact.size} B  {artifact.last_modified}"


def render(verdicts: Sequence[Verdict], pins: Pins, fragment: Path, root: Path) -> None:
    try:
        fragment_label = fragment.resolve().relative_to(root).as_posix()
    except ValueError:
        fragment_label = str(fragment)

    print("Online check of the RPM Fusion bootstrap pins")
    print()
    print(f"  fragment: {fragment_label}")
    print(f"  release:  {pins.release} (the only release this fragment pins)")
    print()
    for verdict in verdicts:
        print(verdict.filename)
        print(f"  pinned  {verdict.pinned}")
        print(_describe("origin", verdict.origin, verdict.origin_error))
        print(_describe("mirror", verdict.mirror, verdict.mirror_error))
        print(f"  status  {verdict.status} - {verdict.note}")
        print()

    code = exit_code(verdicts)
    if code == 0:
        print(f"All {len(verdicts)} pins match upstream. Nothing to do.")
        return

    drifting = [verdict for verdict in verdicts if verdict.status == DRIFT]
    if drifting:
        print(f"ERROR: upstream republished {len(drifting)} bootstrap RPM(s); the pins are stale.", file=sys.stderr)
        print(f"Update {fragment_label} with:", file=sys.stderr)
        for verdict in drifting:
            variable = dict(PIN_VARIABLES)[verdict.channel]
            print(f'  {variable}="{verdict.origin.sha256}"', file=sys.stderr)
        print(
            "Then refresh the NVR in the comment above each pin "
            "(`rpm -qp --qf '%{VERSION}-%{RELEASE}' <file>`) and rebuild on testing.",
            file=sys.stderr,
        )

    inconclusive = [verdict for verdict in verdicts if verdict.status == INCONCLUSIVE]
    if inconclusive:
        print(
            "Inconclusive for: " + ", ".join(verdict.filename for verdict in inconclusive) + ". "
            "Check the failure above and re-run; do not rewrite a pin on one host's word.",
            file=sys.stderr,
        )


def main(argv: Sequence[str] | None = None, prober: Callable[[str, float], Artifact] = probe) -> int:
    parser = argparse.ArgumentParser(description="Compare the RPM Fusion bootstrap pins with upstream.")
    parser.add_argument("--fragment", type=Path, default=FRAGMENT, help="build fragment holding the pins")
    parser.add_argument("--timeout", type=float, default=60.0, help="per-request timeout in seconds")
    args = parser.parse_args(argv)

    try:
        pins = parse_pins(args.fragment.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read the pins: {exc}", file=sys.stderr)
        return 2

    verdicts = verify(pins, prober, args.timeout)
    render(verdicts, pins, args.fragment, ROOT)
    return exit_code(verdicts)


if __name__ == "__main__":
    raise SystemExit(main())
