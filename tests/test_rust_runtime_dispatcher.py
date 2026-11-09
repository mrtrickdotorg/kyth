from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "src/kyth-shared-rs/src/runtime_bin.rs"
INVENTORY = ROOT / "build_files/config/runtime-migration-inventory.json"


class RustRuntimeDispatcherTest(unittest.TestCase):
    def test_compatibility_launchers_have_no_runtime_logic(self):
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        native_wrappers = [
            item for item in inventory["entries"]
            if item["surface"] == "launcher"
            and item["status"] == "done-native"
            and item["current_implementation"] == "shell"
            and item["name"] in {
                "kyth-apply-update", "kyth-boot-branding-guard", "kyth-boot-verify",
                "kyth-davinci-install", "kyth-device-info", "kyth-distrobox-root-launch",
                "kyth-enroll-mok", "kyth-full-update", "kyth-gamescope",
                "kyth-greenboot-failure", "kyth-greenboot-required", "kyth-greenboot-success",
                "kyth-hw-setup", "kyth-isolate-game", "kyth-kerver", "kyth-local-bin-migrate",
                "kyth-mok-rotate", "kyth-nearby-share", "kyth-nvme-tuning", "kyth-perf-gate",
                "kyth-power-arbiter", "kyth-readahead-hint", "kyth-readahead-run",
                "kyth-retry-hardware-setup", "kyth-scx", "kyth-scx-loader",
                "kyth-session-splash-guard", "kyth-set-sleep-mode", "kyth-shader-preheat",
                "kyth-shader-prune", "kyth-snappy-bench", "kyth-storage-gate",
                "kyth-vpnc-script", "kyth-windows-friendly-defaults", "kyth-windows-import",
            }
        ]
        self.assertGreater(len(native_wrappers), 20)
        for item in native_wrappers:
            text = (ROOT / item["path"]).read_text(encoding="utf-8")
            self.assertIn("exec /usr/bin/kyth-runtime", text, item["path"])
            self.assertNotIn("rm -rf", text, item["path"])
            if item["name"] != "kyth-full-update":
                self.assertNotIn("sudo", text, item["path"])

    def test_runtime_uses_bounded_non_shell_processes(self):
        text = RUNTIME.read_text(encoding="utf-8")
        self.assertIn("run_bounded", text)
        self.assertNotIn("sh -c", text)
        self.assertNotIn("bash -c", text)
        self.assertIn("write_atomic", text)
        self.assertIn("validate_token", text)

    def test_greenboot_arms_delegate_to_boot_health(self):
        text = RUNTIME.read_text(encoding="utf-8")

        def arm(start_marker: str, end_marker: str) -> str:
            start = text.index(start_marker)
            return text[start:text.index(end_marker, start)]

        required = arm('"greenboot-required" =>', '"greenboot-success" =>')
        success = arm('"greenboot-success" =>', '"greenboot-failure" =>')
        failure = arm('"greenboot-failure" =>', '"vpnc-script" =>')

        # Every hook still stamps the last-hook-ran marker before it
        # delegates; the marker carries no health semantics of its own.
        for segment in (required, success, failure):
            self.assertIn('"/run/kyth-state/greenboot-state"', segment)
            self.assertIn("write_atomic", segment)
            self.assertIn('"/usr/bin/kyth-boot-health"', segment)

        # required.d runs the real checks; the child exit code is the
        # hook's result, under a bound covering the checker's worst case.
        self.assertIn('"check".into()', required)
        self.assertIn("run_timeout", required)
        self.assertIn("GREENBOOT_CHECK_TIMEOUT", required)
        # green.d records the booted digest as known-good.
        self.assertIn('"mark-healthy".into()', success)
        # red.d books the failure toward quarantine/rollback.
        self.assertIn('"record-failure".into()', failure)
        self.assertIn('"--reason".into()', failure)
        self.assertIn('"greenboot required checks failed".into()', failure)
        self.assertIn("GREENBOOT_RECORD_FAILURE_TIMEOUT", failure)

        bounds = dict(re.findall(
            r"const (GREENBOOT_\w+_TIMEOUT): Duration = Duration::from_secs\((\d+)\)",
            text,
        ))
        # The check polls up to 300 s for the display stack; a shorter
        # delegation bound would score slow-but-healthy boots red.
        self.assertGreaterEqual(int(bounds["GREENBOOT_CHECK_TIMEOUT"]), 300)
        # Must outlast the 60 s rollback kyth-boot-health runs internally
        # once the quarantine threshold is crossed.
        self.assertGreater(int(bounds["GREENBOOT_RECORD_FAILURE_TIMEOUT"]), 60)

    def test_runtime_binary_compiles(self):
        result = subprocess.run(
            ["cargo", "check", "--manifest-path", "src/kyth-shared-rs/Cargo.toml", "--bin", "kyth-runtime"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_packaging_builds_and_installs_runtime_binary(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("--bin kyth-runtime", dockerfile)
        self.assertIn("/build/kyth-runtime /usr/bin/kyth-runtime", dockerfile)

    def test_recipe_import_graph_and_acceptance_launcher_are_native(self):
        root_recipe = (ROOT / "build_files/just/kyth.just").read_text(encoding="utf-8")
        self.assertIn('import "kyth/native.just"', root_recipe)
        native_recipe = (ROOT / "build_files/just/kyth/native.just").read_text(encoding="utf-8")
        self.assertIn("exec /usr/bin/kyth-runtime recipe", native_recipe)
        guest = (ROOT / "build_files/kyth-vm-acceptance-guest").read_text(encoding="utf-8")
        self.assertIn("exec /usr/bin/kyth-vm-acceptance-guest", guest)
        unit = (ROOT / "build_files/kyth-vm-acceptance.service").read_text(encoding="utf-8")
        self.assertIn("ExecStart=/usr/libexec/kyth-vm-acceptance-guest run", unit)

    def test_recipe_fallback_rejects_shell_shims(self):
        text = RUNTIME.read_text(encoding="utf-8")
        self.assertIn('bytes.starts_with(b"\\x7fELF")', text)
        self.assertIn("recipe {name} has no Rust owner", text)


if __name__ == "__main__":
    unittest.main()
