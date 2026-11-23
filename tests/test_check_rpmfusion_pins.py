from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "build_files/scripts/check-rpmfusion-pins.py"
SPEC = importlib.util.spec_from_file_location("check_rpmfusion_pins", SCRIPT)
assert SPEC and SPEC.loader
check_pins = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_pins
SPEC.loader.exec_module(check_pins)

PINNED_FREE = "761100efc44f57e16dadec1780582f725028e212593740e955dbc7d5b2de81bb"
PINNED_NONFREE = "04582bbbb8edf54cc5340d807fb57ae44fea2e8c513b1928a9637b518817328e"
NEW_FREE = "a" * 64
NEW_NONFREE = "b" * 64

FRAGMENT = f"""#!/bin/bash
#   rpmfusion-free-release-45.noarch.rpm (45-2)
RPMFUSION_FREE_SHA256="{PINNED_FREE}"
#   rpmfusion-nonfree-release-45.noarch.rpm (45-2)
RPMFUSION_NONFREE_SHA256="{PINNED_NONFREE}"
if [[ "${{fedora_release}}" == "45" ]]; then
\techo pinned
fi
"""


def url(template: str, channel: str, release: str = "45") -> str:
    return template.format(channel=channel, filename=f"rpmfusion-{channel}-release-{release}.noarch.rpm")


def artifact(digest: str, size: int = 11946, last_modified: str = "Tue, 03 Nov 2026 21:06:30 GMT") -> object:
    return check_pins.Artifact(sha256=digest, size=size, last_modified=last_modified)


class FakeProber:
    """Stands in for the network: canned per-URL results, or an exception."""

    def __init__(self, results: dict[str, object]):
        self.results = dict(results)
        self.requests: list[str] = []

    def __call__(self, address: str, timeout: float) -> object:
        self.requests.append(address)
        result = self.results[address]
        if isinstance(result, Exception):
            raise result
        return result


def prober_for(free_origin, free_mirror, nonfree_origin, nonfree_mirror) -> FakeProber:
    return FakeProber(
        {
            url(check_pins.ORIGIN_URL, "free"): free_origin,
            url(check_pins.MIRROR_URL, "free"): free_mirror,
            url(check_pins.ORIGIN_URL, "nonfree"): nonfree_origin,
            url(check_pins.MIRROR_URL, "nonfree"): nonfree_mirror,
        }
    )


def run_main(prober: FakeProber, fragment: str = FRAGMENT) -> tuple[int, str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "03-rpmfusion-and-repo-hygiene.sh"
        path.write_text(fragment, encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = check_pins.main(["--fragment", str(path)], prober=prober)
    return code, out.getvalue(), err.getvalue()


class ParsePinsTests(unittest.TestCase):
    def test_reads_the_enforced_release_and_both_pins(self):
        pins = check_pins.parse_pins(FRAGMENT)
        self.assertEqual(pins.release, "45")
        self.assertEqual(pins.hashes, {"free": PINNED_FREE, "nonfree": PINNED_NONFREE})

    def test_rejects_a_fragment_without_a_release_guard(self):
        with self.assertRaises(ValueError):
            check_pins.parse_pins(FRAGMENT.replace('"${fedora_release}" == "45"', "true"))

    def test_rejects_a_missing_or_truncated_pin(self):
        for broken in (FRAGMENT.replace(f'"{PINNED_FREE}"', '"abc"'), FRAGMENT.replace(f'"{PINNED_FREE}"', '""')):
            with self.subTest(broken=broken[-40:]):
                with self.assertRaises(ValueError):
                    check_pins.parse_pins(broken)

    def test_the_real_fragment_still_parses(self):
        pins = check_pins.parse_pins(check_pins.FRAGMENT.read_text(encoding="utf-8"))
        self.assertRegex(pins.release, r"^\d+$")
        self.assertEqual(set(pins.hashes), {"free", "nonfree"})


class JudgeTests(unittest.TestCase):
    def test_origin_and_mirror_matching_the_pin_is_ok(self):
        status, _ = check_pins.judge(PINNED_FREE, artifact(PINNED_FREE), artifact(PINNED_FREE))
        self.assertEqual(status, check_pins.OK)

    def test_both_hosts_serving_new_bytes_is_confirmed_drift(self):
        status, note = check_pins.judge(PINNED_FREE, artifact(NEW_FREE), artifact(NEW_FREE))
        self.assertEqual(status, check_pins.DRIFT)
        self.assertIn("mirror pool", note)

    def test_origin_ahead_of_the_mirror_pool_is_inconclusive_not_drift(self):
        status, note = check_pins.judge(PINNED_FREE, artifact(NEW_FREE), artifact(PINNED_FREE))
        self.assertEqual(status, check_pins.INCONCLUSIVE)
        self.assertIn("mirror pool", note)

    def test_three_way_disagreement_is_inconclusive(self):
        status, _ = check_pins.judge(PINNED_FREE, artifact(NEW_FREE), artifact(NEW_NONFREE))
        self.assertEqual(status, check_pins.INCONCLUSIVE)

    def test_mirror_lagging_a_matching_origin_stays_ok(self):
        """The build downloads from the origin, so its match is authoritative."""
        status, note = check_pins.judge(PINNED_FREE, artifact(PINNED_FREE), artifact(NEW_FREE))
        self.assertEqual(status, check_pins.OK)
        self.assertIn("mirror lags", note)

    def test_unreachable_origin_is_inconclusive(self):
        status, _ = check_pins.judge(PINNED_FREE, None, artifact(PINNED_FREE))
        self.assertEqual(status, check_pins.INCONCLUSIVE)

    def test_unconfirmed_origin_mismatch_is_inconclusive(self):
        status, note = check_pins.judge(PINNED_FREE, artifact(NEW_FREE), None)
        self.assertEqual(status, check_pins.INCONCLUSIVE)
        self.assertIn("no second host", note)


class MainTests(unittest.TestCase):
    def test_matching_pins_exit_zero(self):
        prober = prober_for(artifact(PINNED_FREE), artifact(PINNED_FREE),
                            artifact(PINNED_NONFREE), artifact(PINNED_NONFREE))
        code, out, err = run_main(prober)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("Nothing to do", out)
        self.assertEqual(len(prober.requests), 4)

    def test_confirmed_drift_exits_one_and_prints_pasteable_pins(self):
        prober = prober_for(artifact(NEW_FREE), artifact(NEW_FREE),
                            artifact(PINNED_NONFREE), artifact(PINNED_NONFREE))
        code, out, err = run_main(prober)
        self.assertEqual(code, 1)
        self.assertIn(f'RPMFUSION_FREE_SHA256="{NEW_FREE}"', err)
        self.assertNotIn("RPMFUSION_NONFREE_SHA256", err.split("Update")[1])
        self.assertIn("refresh the NVR", err)
        self.assertIn("status  DRIFT", out)

    def test_unreachable_origin_exits_two_without_pin_advice(self):
        prober = prober_for(OSError("connection reset"), artifact(PINNED_FREE),
                            artifact(PINNED_NONFREE), artifact(PINNED_NONFREE))
        code, _, err = run_main(prober)
        self.assertEqual(code, 2)
        self.assertIn("Inconclusive", err)
        self.assertNotIn("SHA256=\"", err)

    def test_unreadable_fragment_exits_two(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = check_pins.main(["--fragment", "/nonexistent/fragment.sh"], prober=prober_for(
                artifact(PINNED_FREE), artifact(PINNED_FREE),
                artifact(PINNED_NONFREE), artifact(PINNED_NONFREE)))
        self.assertEqual(code, 2)
        self.assertIn("cannot read the pins", err.getvalue())


class WorkflowContractTests(unittest.TestCase):
    def test_scheduled_workflow_runs_the_checker_read_only(self):
        workflow = (ROOT / ".github/workflows/rpmfusion-pin-freshness.yml").read_text(encoding="utf-8")
        self.assertIn("schedule:", workflow)
        self.assertIn("python3 build_files/scripts/check-rpmfusion-pins.py", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertNotIn("issues: write", workflow)

    def test_testing_pushes_run_an_advisory_probe_while_the_cron_is_dormant(self):
        """Schedules only fire from the default branch, so testing needs its own."""
        workflow = (ROOT / ".github/workflows/validation.yml").read_text(encoding="utf-8")
        self.assertIn("pin-freshness:", workflow)
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/testing'", workflow)
        job = workflow.split("pin-freshness:", 1)[1].split("\n  hub-shell:", 1)[0]
        self.assertIn("python3 build_files/scripts/check-rpmfusion-pins.py", job)
        self.assertIn("exit 0", job)
        self.assertNotIn("continue-on-error: false", job)


if __name__ == "__main__":
    unittest.main()
