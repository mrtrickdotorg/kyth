"""Behavioral tests for the Python KythOS daily-driver smoke check."""
from __future__ import annotations

import pathlib
import subprocess
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build_files" / "kyth_shared"))

from kyth_shared.health import HealthReport, HealthResult, from_smoke_results
from kyth_shared.smoke_check import Result, SmokeCheck


class SmokeCheckTests(unittest.TestCase):
    def test_missing_live_booted_deployment_is_a_warning(self) -> None:
        checker = SmokeCheck(quiet=True)
        status = subprocess.CompletedProcess(
            ["bootc", "status"], 0, '{"status":{"booted":null}}', ""
        )
        with (
            mock.patch("shutil.which", side_effect=lambda command: "/usr/bin/" + command),
            mock.patch.object(checker, "command", return_value=status),
            mock.patch.object(checker, "check_unit"),
            mock.patch.object(checker, "check_command"),
        ):
            checker.identity_and_updates()
        booted = next(item for item in checker.results if item.name == "Booted image")
        self.assertEqual(booted.level, "WARN")
        self.assertIn("no booted deployment", booted.detail)

    def test_results_retain_their_section(self) -> None:
        checker = SmokeCheck()
        with mock.patch("builtins.print"):
            checker.section("Hardware")
            checker.warn("GPU", "not found")
        self.assertEqual(checker.results[0].section, "Hardware")
        self.assertEqual(checker.results[0].level, "WARN")

    def test_failure_always_returns_two(self) -> None:
        checker = SmokeCheck()
        with mock.patch("builtins.print"):
            checker.fail("Required", "missing")
            self.assertEqual(checker.exit_code(strict=False), 2)
            self.assertEqual(checker.exit_code(strict=True), 2)

    def test_warning_only_fails_in_strict_mode(self) -> None:
        checker = SmokeCheck()
        with mock.patch("builtins.print"):
            checker.warn("Optional", "missing")
            self.assertEqual(checker.exit_code(strict=False), 0)
            self.assertEqual(checker.exit_code(strict=True), 1)

    def test_path_absence_check(self) -> None:
        checker = SmokeCheck()
        with (
            mock.patch("pathlib.Path.exists", return_value=False),
            mock.patch("builtins.print"),
        ):
            checker.check_path("/missing", "Removed path", absent=True)
        self.assertEqual(checker.results[0].level, "PASS")

    def test_optional_command_is_warning(self) -> None:
        checker = SmokeCheck()
        with (
            mock.patch("shutil.which", return_value=None),
            mock.patch("builtins.print"),
        ):
            checker.check_command("optional", "Optional", optional=True)
        self.assertEqual(checker.results[0].level, "WARN")

    def test_x11_session_type_is_a_failure(self) -> None:
        checker = SmokeCheck(quiet=True)
        with (
            mock.patch.dict("os.environ", {"XDG_SESSION_TYPE": "x11", "XDG_CURRENT_DESKTOP": "KDE"}),
            mock.patch.object(checker, "check_unit"),
            mock.patch.object(checker, "check_path"),
            mock.patch.object(checker, "check_contains"),
        ):
            checker.desktop()
        session = next(item for item in checker.results if item.name == "Session type")
        self.assertEqual(session.level, "FAIL")
        self.assertIn("journalctl -u plasmalogin", session.detail)

    def _background_with_anchor(self, anchor_text: str | None):
        """Run background_and_tools with a fixtured signing anchor file."""
        checker = SmokeCheck(quiet=True)

        def fake_read_text(path, *args, **kwargs):
            if str(path) == "/usr/share/kyth/updater-signing-keys.asc":
                if anchor_text is None:
                    raise OSError("anchor not installed")
                return anchor_text
            return ""

        with (
            mock.patch.object(checker, "check_unit") as check_unit,
            mock.patch.object(checker, "check_command"),
            mock.patch.object(pathlib.Path, "read_text", fake_read_text),
        ):
            checker.background_and_tools()
        return checker, check_unit

    def test_proton_timer_is_warning_while_anchor_is_placeholder(self) -> None:
        checker, check_unit = self._background_with_anchor("# PLACEHOLDER\n")
        units = [call.args[0] for call in check_unit.call_args_list]
        self.assertNotIn("kyth-proton-cachyos-update.timer", units)
        timer = next(item for item in checker.results if item.name == "GE-Proton timer")
        self.assertEqual(timer.level, "WARN")
        self.assertEqual(timer.detail, "disabled until the updater signing key ships")

    def test_proton_timer_is_warning_when_anchor_is_missing(self) -> None:
        checker, check_unit = self._background_with_anchor(None)
        units = [call.args[0] for call in check_unit.call_args_list]
        self.assertNotIn("kyth-proton-cachyos-update.timer", units)
        timer = next(item for item in checker.results if item.name == "GE-Proton timer")
        self.assertEqual(timer.level, "WARN")

    def test_proton_timer_is_required_once_anchor_has_certificate(self) -> None:
        checker, check_unit = self._background_with_anchor(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n"
        )
        timer_calls = [
            call
            for call in check_unit.call_args_list
            if call.args[0] == "kyth-proton-cachyos-update.timer"
        ]
        self.assertEqual(len(timer_calls), 1)
        self.assertEqual(timer_calls[0].args[1], "GE-Proton timer")
        self.assertEqual(timer_calls[0].kwargs, {"enabled": True})
        self.assertFalse(
            [item for item in checker.results if item.name == "GE-Proton timer"]
        )

    def test_health_report_has_stable_json_schema(self) -> None:
        report = from_smoke_results(
            [
                Result("PASS", "Booted image", "testing", "Updates"),
                Result("WARN", "Firmware service", "inactive", "Updates"),
                Result("FAIL", "Vulkan", "probe failed", "Hardware"),
            ]
        )
        payload = report.to_dict()

        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["overall"], "error")
        self.assertEqual(payload["summary"]["healthy"], 1)
        self.assertEqual(payload["summary"]["warning"], 1)
        self.assertEqual(payload["summary"]["error"], 1)
        self.assertIn("Hub", payload["results"][1]["remediation"])
        self.assertNotIn("Pulse", payload["results"][1]["remediation"])

    def test_health_text_groups_components_by_section(self) -> None:
        report = HealthReport(
            "2026-07-26T00:00:00+00:00",
            (
                HealthResult("bootc", "healthy", "ready", section="System"),
                HealthResult(
                    "Vulkan",
                    "warning",
                    "fallback",
                    "Review graphics",
                    "Hardware",
                ),
            ),
        )

        text = report.to_text()

        self.assertIn("KythOS health: warning", text)
        self.assertIn("== Hardware ==", text)
        self.assertIn("Fix: Review graphics", text)


if __name__ == "__main__":
    unittest.main()
