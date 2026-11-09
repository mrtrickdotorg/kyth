"""Execution coverage for the shipped greenboot wrapper scripts.

The three wrappers in build_files/ (kyth-greenboot-required,
kyth-greenboot-success, kyth-greenboot-failure) are the greenboot
required.d / green.d / red.d hooks. Each ends in an absolute-path exec:

    exec /usr/bin/kyth-runtime greenboot-<mode> "$@"

and the kyth-runtime dispatcher (src/kyth-shared-rs/src/runtime_bin.rs)
in turn delegates to /usr/bin/kyth-boot-health, also by absolute path,
with no environment override. Absolute paths defeat PATH stubbing, so
neither hop can be intercepted by putting a fake binary earlier on
PATH. A true end-to-end (real wrapper -> real kyth-runtime -> stub
kyth-boot-health) would require writing a stub into /usr/bin, which a
unit test must never do.

Coverage is therefore split at the hop boundary. The dispatcher hop's
argv contract (check / mark-healthy / record-failure --reason
"greenboot required checks failed") and its 0/non-zero exit contract
are pinned by tests/test_rust_runtime_dispatcher.py. This file covers
the wrapper hop by execution: each shipped wrapper is run for real,
with exactly one mechanical substitution — the absolute
/usr/bin/kyth-runtime path (asserted to occur exactly once before it
is replaced) points at a recording stub instead. That proves the
wrapper execs the runtime with the correct greenboot-<mode> string,
forwards "$@" untouched, and passes the child's exit code through
unlaundered.

If a KYTH_BOOT_HEALTH_BIN-style override ever lands in the dispatcher,
this same substitute-and-execute technique extends to a real-binary
dispatcher test: run the real kyth-runtime against a stub boot-health
and pin the second hop by execution too.
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build_files" / "kyth_shared"))
sys.path.insert(0, str(ROOT / "build_files" / "kyth-installer"))

RUNTIME_PATH = "/usr/bin/kyth-runtime"
BUILD_FILES = ROOT / "build_files"

# Stub for /usr/bin/kyth-runtime: record argv, one argument per line, to
# $KYTH_STUB_LOG, then exit with the status $KYTH_STUB_EXIT requests.
STUB = """#!/usr/bin/env bash
printf '%s\\n' "$@" > "$KYTH_STUB_LOG"
exit "${KYTH_STUB_EXIT:-0}"
"""


class GreenbootWrapperExecutionTests(unittest.TestCase):
    WRAPPERS = {
        "kyth-greenboot-required": "greenboot-required",
        "kyth-greenboot-success": "greenboot-success",
        "kyth-greenboot-failure": "greenboot-failure",
    }

    def test_wrappers_exec_runtime_with_mode_args_and_exit_passthrough(self) -> None:
        for name, mode in self.WRAPPERS.items():
            with self.subTest(wrapper=name):
                shipped = BUILD_FILES / name
                text = shipped.read_text(encoding="utf-8")
                # Assert-your-patch rule: the substitution target must
                # exist exactly once before anything is replaced — a
                # silent no-op replace would test a script that still
                # points at the real runtime (or nowhere).
                self.assertEqual(text.count(RUNTIME_PATH), 1)

                with tempfile.TemporaryDirectory() as tmp:
                    tmp_path = pathlib.Path(tmp)
                    stub = tmp_path / "kyth-runtime-stub"
                    stub.write_text(STUB, encoding="utf-8")
                    stub.chmod(0o755)

                    substituted = text.replace(RUNTIME_PATH, str(stub))
                    # The invocation must remain an exec: the wrapper
                    # hands its process (and therefore its exit status)
                    # to the runtime instead of spawning and translating.
                    self.assertRegex(substituted, r"(?m)^exec ")
                    self.assertIn(str(stub), substituted)

                    script = tmp_path / name
                    script.write_text(substituted, encoding="utf-8")
                    script.chmod(0o755)

                    log = tmp_path / "stub-argv.log"
                    result = subprocess.run(
                        ["bash", str(script), "sentinel-arg"],
                        env={
                            **os.environ,
                            "KYTH_STUB_LOG": str(log),
                            "KYTH_STUB_EXIT": "7",
                        },
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=30,
                    )
                    # exec passthrough: the stub's exit status is the
                    # wrapper's exit status, with no laundering to 0.
                    self.assertEqual(result.returncode, 7, result.stderr)
                    # Correct mode string first, then "$@" forwarded
                    # verbatim.
                    self.assertEqual(
                        log.read_text(encoding="utf-8").splitlines(),
                        [mode, "sentinel-arg"],
                    )


if __name__ == "__main__":
    unittest.main()
