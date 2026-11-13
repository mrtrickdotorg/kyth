"""Static contract tests for unattended live/install/update/rollback gating."""
from __future__ import annotations

import contextlib
import fcntl
import os
import pathlib
import json
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
GUEST = ROOT / "build_files" / "kyth-vm-acceptance-guest"
HOST = ROOT / "build_files" / "scripts" / "vm-acceptance.sh"
PREP = ROOT / "build_files" / "scripts" / "vm-acceptance-prep-windows.sh"
UNIT = ROOT / "build_files" / "kyth-vm-acceptance.service"
sys.path.insert(0, str(ROOT / "build_files" / "kyth_shared"))

from kyth_shared import vm_acceptance


def _completed(returncode: int = 0, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["x"], returncode, stdout=stdout, stderr="")


class VmAcceptanceTests(unittest.TestCase):
    def test_launchers_parse(self):
        subprocess.run(["bash", "-n", str(GUEST)], check=True)
        self.assertIn("/usr/bin/kyth-vm-acceptance-guest", GUEST.read_text(encoding="utf-8"))
        subprocess.run(["bash", "-n", str(HOST)], check=True)
        subprocess.run(["bash", "-n", str(PREP)], check=True)

    def test_host_display_auto_selects_headless(self):
        """Regression (2026-11-13): -display spice-app makes QEMU spawn a
        SPICE client, which does not exist on headless CI runners — QEMU
        exited before the guest booted and the first real CI acceptance
        run reported every sentinel missing. The host must auto-select
        -display none headless (screenshots use the QEMU monitor and
        readiness the serial log; nothing connects to the SPICE socket),
        keeping spice-app only for workstation sessions."""
        text = HOST.read_text(encoding="utf-8")
        self.assertIn('-display "${DISPLAY_MODE}"', text)
        self.assertNotIn('-display "spice-app"', text)
        self.assertIn('DISPLAY_MODE="spice-app"', text)
        self.assertIn('DISPLAY_MODE="none"', text)
        self.assertIn("remote-viewer", text)

    def test_guest_is_firmware_gated_and_covers_lifecycle(self):
        text = pathlib.Path(vm_acceptance.__file__).read_text(encoding="utf-8")
        self.assertIn("/sys/firmware/qemu_fw_cfg/by_name/opt/com.kyth", text)
        # The unit carries no Condition on the fw_cfg flag: the guest
        # binary self-gates (run() exits SUCCESS when the flag is absent).
        # A ConditionPathExists previously pointed at
        # by_name/kyth/acceptance/raw — a path that never exists, since
        # the real flag is by_name/opt/com.kyth/acceptance/raw — so the
        # unit was skipped on every boot and the guest never ran. There
        # is likewise deliberately no ExecCondition (it would race QEMU
        # exposing the flag); the negative space for both is pinned here.
        unit_text = UNIT.read_text(encoding="utf-8")
        self.assertNotIn("ConditionPathExists=", unit_text)
        self.assertNotIn("ExecCondition=", unit_text)
        for phase in (
            "LIVE_READY", "INSTALL_COMPLETE", "INSTALLED_READY",
            "INSTALLED_SELINUX_OK", "FIRSTBOOT_OK",
            "UPDATE_STAGED", "UPDATE_BOOTED", "ROLLBACK_STAGED",
            "ROLLBACK_BOOTED", "COMPLETE", "FAILED", "HUB_BINARY_OK",
            "HUB_DEEP_LINKS_OK", "HUB_SECOND_LAUNCH_OK",
            "HUB_DASHBOARD_DEGRADED_OK", "HUB_UPDATES_OK",
            "HUB_PRIVILEGED_FAILURE_OK",
        ):
            self.assertIn(phase, text)
        self.assertIn("source_ref = _installer_source_ref()", text)
        self.assertIn("KYTH_SOURCE_IMAGE=", text)
        self.assertIn("virtio-KYTH_ACCEPT", text)

    def test_live_acceptance_uses_pinned_registry_source_from_image_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = pathlib.Path(tmpdir) / "kyth-installer.env"
            env_file.write_text(
                "KYTH_SOURCE_IMAGE=ghcr.io/kyth-os/kyth@sha256:abc123\n",
                encoding="utf-8",
            )
            with mock.patch.object(vm_acceptance, "INSTALLER_ENV_FILE", env_file):
                self.assertEqual(
                    vm_acceptance._installer_source_ref(),
                    "ghcr.io/kyth-os/kyth@sha256:abc123",
                )

    def test_live_acceptance_fails_closed_when_registry_source_is_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = pathlib.Path(tmpdir) / "missing-installer.env"
            with (
                mock.patch.object(vm_acceptance, "INSTALLER_ENV_FILE", env_file),
                mock.patch("kyth_shared.vm_acceptance.fail", side_effect=SystemExit(1)) as fail,
            ):
                with self.assertRaises(SystemExit):
                    vm_acceptance._installer_source_ref()
        fail.assert_called_once_with("pinned installer source is missing from live image")

    def test_live_build_uses_the_pinned_network_image_without_embedding_it(self):
        build = (ROOT / "installer" / "build.sh").read_text(encoding="utf-8")
        containerfile = (ROOT / "installer" / "Containerfile").read_text(encoding="utf-8")

        self.assertNotIn("skopeo copy", build)
        self.assertNotIn("/usr/share/kyth/image:latest", build)
        self.assertIn("skopeo inspect --format", build)
        self.assertIn('source_imgref="${INSTALL_SOURCE_IMAGE}"', build)
        self.assertIn("KYTH_SOURCE_IMAGE=%s", build)
        self.assertIn("KYTH_SOURCE_DIGEST=%s", build)
        self.assertIn("${source_imgref#docker://}", build)
        self.assertIn("INSTALL_SOURCE_IMAGE", containerfile)

    def test_update_reference_policy(self):
        self.assertTrue(vm_acceptance.valid_update_ref("ghcr.io/example/kyth:testing"))
        self.assertTrue(vm_acceptance.valid_update_ref(""))
        self.assertFalse(vm_acceptance.valid_update_ref("image; poweroff"))

    def test_bootc_status_json_parsing(self):
        completed = subprocess.CompletedProcess(
            ["bootc"], 0,
            stdout='{"status":{"booted":{"image":{"imageDigest":"sha256:abc"}}}}',
            stderr="",
        )
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=completed):
            self.assertEqual(vm_acceptance.booted_digest(), "sha256:abc")

    def test_host_uses_a_dedicated_disk_and_collects_evidence(self):
        text = HOST.read_text(encoding="utf-8")
        self.assertIn("qemu-img create", text)
        self.assertIn("serial=KYTH_ACCEPT", text)
        self.assertIn("live-desktop.ppm", text)
        self.assertIn("installed-login.ppm", text)
        self.assertIn("KYTH_ACCEPTANCE:FAILED", text)
        self.assertIn("qualification.json", text)
        self.assertIn("qualification.md", text)

    def test_harness_uses_iso_once_then_defaults_to_installed_disk(self):
        text = HOST.read_text(encoding="utf-8")
        self.assertIn("ide-cd,bus=ahci.0,drive=liveiso,bootindex=2", text)
        self.assertIn("virtio-blk-pci,drive=systemdisk,serial=KYTH_ACCEPT,bootindex=1", text)
        self.assertIn("-boot once=d,menu=off", text)

    def test_installed_hub_acceptance_matrix_is_required(self):
        text = pathlib.Path(vm_acceptance.__file__).read_text(encoding="utf-8")
        for marker in (
            "kyth-hub-shell", "hubRoutes.json", "HUB_DEEP_LINKS_OK",
            "HUB_SECOND_LAUNCH_OK", "HUB_DASHBOARD_DEGRADED_OK",
            "HUB_UPDATES_OK", "HUB_PRIVILEGED_FAILURE_OK", "KYTH_HUB_ACCEPTANCE_FILE",
        ):
            self.assertIn(marker, text)

    def test_installed_hub_acceptance_bootstraps_a_disposable_graphical_user(self):
        text = pathlib.Path(vm_acceptance.__file__).read_text(encoding="utf-8")
        self.assertIn("kyth-acceptance", text)
        self.assertIn("useradd", text)
        self.assertIn("90-kyth-vm-acceptance.conf", text)
        self.assertIn("systemctl", text)

    def test_hub_second_launch_does_not_read_first_launch_evidence(self):
        text = pathlib.Path(vm_acceptance.__file__).read_text(encoding="utf-8")
        first = text.index('if _wait_hub_event(evidence, "deep-link") is None:')
        second = text.index('second = _hub_start', first)
        self.assertIn("evidence.unlink(missing_ok=True)", text[first:second])


class ReadFwCfgTests(unittest.TestCase):
    def test_missing_file_returns_empty_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = pathlib.Path(tmp) / "missing"
            self.assertEqual(vm_acceptance._read_fw_cfg(missing), "")

    def test_strips_nul_bytes_and_whitespace(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "raw"
            path.write_bytes(b"1\x00\x00\n")
            self.assertEqual(vm_acceptance._read_fw_cfg(path), "1")

    def test_enabled_and_read_update_ref_use_fw_cfg_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            enable_file = pathlib.Path(tmp) / "enable"
            update_file = pathlib.Path(tmp) / "update"
            enable_file.write_bytes(b"1")
            update_file.write_bytes(b"ghcr.io/example/kyth:testing")
            with mock.patch("kyth_shared.vm_acceptance.ENABLE_FILE", enable_file), \
                 mock.patch("kyth_shared.vm_acceptance.UPDATE_FILE", update_file):
                self.assertTrue(vm_acceptance.enabled())
                self.assertEqual(vm_acceptance.read_update_ref(), "ghcr.io/example/kyth:testing")

    def test_enabled_is_false_when_file_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("kyth_shared.vm_acceptance.ENABLE_FILE", pathlib.Path(tmp) / "absent"):
                self.assertFalse(vm_acceptance.enabled())


class HubAcceptanceHelpersTests(unittest.TestCase):
    def test_active_graphical_session_builds_minimal_environment(self):
        account = mock.Mock(pw_uid=1000, pw_dir="/home/tester")
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "run-user"
            runtime.mkdir()
            with mock.patch(
                "kyth_shared.vm_acceptance.run_text",
                side_effect=[_completed(0, "c1\n"), _completed(0, "tester\n")],
            ), mock.patch("kyth_shared.vm_acceptance.pwd.getpwnam", return_value=account), mock.patch(
                "kyth_shared.vm_acceptance.Path", side_effect=lambda value: runtime if str(value).startswith("/run/user/") else pathlib.Path(tmp) / "x11"
            ):
                result = vm_acceptance._active_graphical_session()
        self.assertEqual(result[0], "tester")
        self.assertEqual(result[1]["XDG_SESSION_TYPE"], "")

    def test_install_from_live_iso_runs_complete_install_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = pathlib.Path(tmp) / "acceptance.log"
            target = mock.Mock()
            target.is_block_device.return_value = True
            target.resolve.return_value = target
            with (
                mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=True),
                mock.patch("kyth_shared.vm_acceptance.run_smoke_check"),
                mock.patch("kyth_shared.vm_acceptance.TARGET_BY_ID", target),
                mock.patch("kyth_shared.vm_acceptance.LOG_FILE", log_file),
                mock.patch(
                    "kyth_shared.vm_acceptance._installer_source_ref",
                    return_value="ghcr.io/kyth-os/kyth@sha256:abc123",
                ),
                mock.patch("kyth_shared.vm_acceptance._installer_target_ref", return_value="ghcr.io/example/kyth:testing"),
                mock.patch("kyth_shared.vm_acceptance.read_update_ref", return_value=""),
                mock.patch("kyth_shared.vm_acceptance.run", return_value=_completed(0)),
                mock.patch("kyth_shared.vm_acceptance.power") as power,
                mock.patch("kyth_shared.vm_acceptance.emit") as emit,
            ):
                vm_acceptance.install_from_live_iso()
        power.assert_called_once_with("reboot")
        self.assertTrue(any(call.args[0] == "INSTALL_COMPLETE" for call in emit.call_args_list))

    def test_hub_pages_expands_destinations_and_sections_from_manifest(self):
        manifest = {
            "destinations": [{
                "key": "Move In",
                "route": "/move-in",
                "sections": [{"key": "Network Shares"}],
            }],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "hubRoutes.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with mock.patch("kyth_shared.vm_acceptance.HUB_ROUTE_MANIFEST", path):
                self.assertEqual(
                    vm_acceptance._hub_pages(),
                    (("Welcome", "/"), ("Move In", "/move-in"), ("Network Shares", "/move-in?section=Network%20Shares")),
                )

    def test_hub_event_requires_json_object_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = pathlib.Path(tmp) / "hub.log"
            evidence.write_text(
                "KYTH_HUB_ACCEPTANCE:deep-link:{\"page\":\"Updates\",\"route\":\"/updates\"}\n",
                encoding="utf-8",
            )
            self.assertEqual(
                vm_acceptance._hub_event(evidence, "deep-link"),
                {"page": "Updates", "route": "/updates"},
            )
            evidence.write_text("KYTH_HUB_ACCEPTANCE:deep-link:[1]\n", encoding="utf-8")
            self.assertIsNone(vm_acceptance._hub_event(evidence, "deep-link"))

    def test_hub_event_and_wait_handle_missing_invalid_and_delayed_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = pathlib.Path(tmp) / "missing.log"
            self.assertIsNone(vm_acceptance._hub_event(evidence, "deep-link"))
            evidence.write_text("KYTH_HUB_ACCEPTANCE:deep-link:not-json\n", encoding="utf-8")
            self.assertIsNone(vm_acceptance._hub_event(evidence, "deep-link"))
            evidence.write_text("KYTH_HUB_ACCEPTANCE:deep-link:{\"page\":\"Welcome\"}\n", encoding="utf-8")
            with mock.patch("kyth_shared.vm_acceptance.time.monotonic", side_effect=[0, 0, 1]), \
                 mock.patch("kyth_shared.vm_acceptance.time.sleep"):
                self.assertEqual(vm_acceptance._wait_hub_event(evidence, "deep-link", timeout=0.5), {"page": "Welcome"})

    def test_hub_launch_and_stop_helpers_cover_process_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = pathlib.Path(tmp) / "hub.log"
            process = mock.Mock()
            with mock.patch("kyth_shared.vm_acceptance.subprocess.Popen", return_value=process) as popen:
                started = vm_acceptance._hub_start("tester", {"HOME": "/tmp"}, "Updates", evidence, degraded=True)
            self.assertIs(started, process)
            self.assertIn("KYTH_HUB_ACCEPTANCE_DEGRADED=1", popen.call_args.args[0])
            process.poll.return_value = 0
            vm_acceptance._hub_stop(process)
            process.poll.return_value = None
            with mock.patch("kyth_shared.vm_acceptance.os.killpg", side_effect=ProcessLookupError):
                vm_acceptance._hub_stop(process)

    def test_hub_launch_check_handles_start_failure_and_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = pathlib.Path(tmp) / "hub.log"
            process = mock.Mock()
            event = {"page": "Updates", "route": "/updates", "source": "initial"}
            with mock.patch("kyth_shared.vm_acceptance._hub_start", return_value=process), \
                 mock.patch("kyth_shared.vm_acceptance._wait_hub_event", return_value=event), \
                 mock.patch("kyth_shared.vm_acceptance._hub_stop"):
                self.assertTrue(vm_acceptance._hub_launch_check("tester", {}, "Updates", "/updates", evidence))
            with mock.patch("kyth_shared.vm_acceptance._hub_start", side_effect=OSError("missing")):
                self.assertFalse(vm_acceptance._hub_launch_check("tester", {}, "Updates", "/updates", evidence))

    def test_hub_acceptance_emits_all_qualification_phases(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = pathlib.Path(tmp) / "kyth-hub-shell"
            binary.write_bytes(b"hub")
            binary.chmod(0o755)
            evidence = pathlib.Path(f"/tmp/kyth-hub-acceptance-{999991}.log")
            evidence.unlink(missing_ok=True)
            starts = [mock.Mock() for _ in range(4)]
            for process in starts:
                process.poll.return_value = 0
            events = [
                {"page": "Welcome", "source": "initial"},
                {"page": "Updates", "source": "single-instance"},
                {"state": "degraded", "label": "Status unavailable"},
                {"state": "degraded"},
                {"state": "expected"},
            ]
            with mock.patch("kyth_shared.vm_acceptance.HUB_BINARY", binary), \
                 mock.patch("kyth_shared.vm_acceptance._active_graphical_session", return_value=("tester", {"HOME": "/tmp", "DISPLAY": ":0"})), \
                 mock.patch("kyth_shared.vm_acceptance._hub_pages", return_value=(("Welcome", "/"),)), \
                 mock.patch("kyth_shared.vm_acceptance._hub_launch_check", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance._hub_start", side_effect=starts), \
                 mock.patch("kyth_shared.vm_acceptance._wait_hub_event", side_effect=events), \
                 mock.patch("kyth_shared.vm_acceptance._hub_stop"), \
                 mock.patch("kyth_shared.vm_acceptance.emit") as emit:
                vm_acceptance.run_hub_acceptance()
            self.assertEqual(
                [entry.args[0] for entry in emit.call_args_list],
                [
                    "HUB_BINARY_OK", "HUB_DEEP_LINKS_OK", "HUB_SECOND_LAUNCH_OK",
                    "HUB_DASHBOARD_DEGRADED_OK", "HUB_UPDATES_OK", "HUB_PRIVILEGED_FAILURE_OK",
                ],
            )
            evidence.unlink(missing_ok=True)


class EmitAndPowerTests(unittest.TestCase):
    def test_emit_writes_log_and_serial_and_tolerates_write_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = pathlib.Path(tmp) / "log"
            serial = pathlib.Path(tmp) / "serial"
            with mock.patch("kyth_shared.vm_acceptance.LOG_FILE", log_file), \
                 mock.patch("kyth_shared.vm_acceptance.SERIAL_DEVICE", serial):
                vm_acceptance.emit("PHASE", "detail\nwith newline")
            self.assertIn("KYTH_ACCEPTANCE:PHASE:detail with newline", log_file.read_text())
            self.assertIn("KYTH_ACCEPTANCE:PHASE:detail with newline", serial.read_text())

    def test_emit_tolerates_unwritable_log_and_serial(self):
        # Directories can't be opened for append/write_text — both writes
        # should raise OSError internally and be swallowed, not propagate.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            with mock.patch("kyth_shared.vm_acceptance.LOG_FILE", tmp_path), \
                 mock.patch("kyth_shared.vm_acceptance.SERIAL_DEVICE", tmp_path):
                vm_acceptance.emit("PHASE", "detail")  # must not raise

    def test_power_runs_systemctl_no_block(self):
        with mock.patch("kyth_shared.vm_acceptance.run") as mock_run:
            vm_acceptance.power("reboot")
            mock_run.assert_called_once_with(["systemctl", "reboot", "--no-block"])

    def test_fail_emits_powers_off_and_exits_one(self):
        with mock.patch("kyth_shared.vm_acceptance.emit") as mock_emit, \
             mock.patch("kyth_shared.vm_acceptance.power") as mock_power:
            with self.assertRaises(SystemExit) as cm:
                vm_acceptance.fail("boom")
            self.assertEqual(cm.exception.code, 1)
            mock_emit.assert_called_once_with("FAILED", "boom")
            mock_power.assert_called_once_with("poweroff")


class WaitForDesktopTests(unittest.TestCase):
    def test_live_mode_checks_plasmashell_and_succeeds_immediately(self):
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=_completed(0)) as mock_run_text, \
             mock.patch("kyth_shared.vm_acceptance.time.sleep") as mock_sleep:
            self.assertTrue(vm_acceptance.wait_for_desktop("live", attempts=3, delay=0))
            mock_run_text.assert_called_once_with(["pgrep", "-x", "plasmashell"], timeout=5)
            mock_sleep.assert_not_called()

    def test_installed_mode_checks_display_manager(self):
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=_completed(0)) as mock_run_text:
            self.assertTrue(vm_acceptance.wait_for_desktop("installed", attempts=1, delay=0))
            mock_run_text.assert_called_once_with(
                ["systemctl", "is-active", "--quiet", "display-manager.service"], timeout=5
            )

    def test_times_out_when_never_ready(self):
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=_completed(1)), \
             mock.patch("kyth_shared.vm_acceptance.time.sleep"):
            self.assertFalse(vm_acceptance.wait_for_desktop("live", attempts=3, delay=0))

    def test_treats_a_missing_result_as_not_ready(self):
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=None), \
             mock.patch("kyth_shared.vm_acceptance.time.sleep"):
            self.assertFalse(vm_acceptance.wait_for_desktop("live", attempts=1, delay=0))


class BootedDigestAndDeploymentCountTests(unittest.TestCase):
    def test_booted_digest_falls_back_to_nested_image_digest(self):
        payload = '{"status":{"booted":{"image":{"image":{"imageDigest":"sha256:nested"}}}}}'
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=_completed(0, payload)):
            self.assertEqual(vm_acceptance.booted_digest(), "sha256:nested")

    def test_booted_digest_returns_empty_on_nonzero_exit(self):
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=_completed(1, "")):
            self.assertEqual(vm_acceptance.booted_digest(), "")

    def test_booted_digest_returns_empty_when_command_unavailable(self):
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=None):
            self.assertEqual(vm_acceptance.booted_digest(), "")

    def test_booted_digest_returns_empty_on_malformed_json(self):
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=_completed(0, "not json")):
            self.assertEqual(vm_acceptance.booted_digest(), "")

    def test_deployment_count_from_dict_payload(self):
        payload = '{"deployments":[{"a":1},{"b":2}]}'
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=_completed(0, payload)):
            self.assertEqual(vm_acceptance.deployment_count(), 2)

    def test_deployment_count_from_list_payload(self):
        payload = '[{"a":1}]'
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=_completed(0, payload)):
            self.assertEqual(vm_acceptance.deployment_count(), 1)

    def test_deployment_count_returns_zero_on_failure(self):
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=_completed(1, "")):
            self.assertEqual(vm_acceptance.deployment_count(), 0)

    def test_deployment_count_returns_zero_on_malformed_json(self):
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=_completed(0, "nope")):
            self.assertEqual(vm_acceptance.deployment_count(), 0)


class InstallerTargetRefAndStateTests(unittest.TestCase):
    def test_installer_target_ref_reads_env_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = pathlib.Path(tmp) / "kyth-installer.env"
            env_file.write_text("OTHER=1\nKYTH_TARGET_IMAGE='ghcr.io/example/kyth:custom'\n")
            with mock.patch("kyth_shared.vm_acceptance.INSTALLER_ENV_FILE", env_file):
                self.assertEqual(vm_acceptance._installer_target_ref(), "ghcr.io/example/kyth:custom")

    def test_installer_target_ref_defaults_when_file_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("kyth_shared.vm_acceptance.INSTALLER_ENV_FILE", pathlib.Path(tmp) / "absent"):
                self.assertEqual(
                    vm_acceptance._installer_target_ref(), "ghcr.io/mrtrickdotorg/kyth:testing"
                )

    def test_installer_target_ref_defaults_when_key_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = pathlib.Path(tmp) / "kyth-installer.env"
            env_file.write_text("OTHER=1\n")
            with mock.patch("kyth_shared.vm_acceptance.INSTALLER_ENV_FILE", env_file):
                self.assertEqual(
                    vm_acceptance._installer_target_ref(), "ghcr.io/mrtrickdotorg/kyth:testing"
                )

    def test_state_value_defaults_to_fresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("kyth_shared.vm_acceptance.STATE_FILE", pathlib.Path(tmp) / "absent"):
                self.assertEqual(vm_acceptance._state_value(), "fresh")

    def test_state_value_reads_existing_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = pathlib.Path(tmp) / "state"
            state_file.write_text("update-staged\n")
            with mock.patch("kyth_shared.vm_acceptance.STATE_FILE", state_file):
                self.assertEqual(vm_acceptance._state_value(), "update-staged")

    def test_initial_digest_returns_stored_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = pathlib.Path(tmp)
            (state_dir / "initial-digest").write_text("sha256:initial\n")
            with mock.patch("kyth_shared.vm_acceptance.STATE_DIR", state_dir):
                self.assertEqual(vm_acceptance._initial_digest(), "sha256:initial")

    def test_initial_digest_fails_loudly_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("kyth_shared.vm_acceptance.STATE_DIR", pathlib.Path(tmp)), \
                 mock.patch("kyth_shared.vm_acceptance.power"):
                with self.assertRaises(SystemExit):
                    vm_acceptance._initial_digest()


class InstalledTruthCheckTests(unittest.TestCase):
    def test_failed_units_parser_handles_bullets_and_empty_output(self):
        self.assertEqual(vm_acceptance._failed_units(""), [])
        self.assertEqual(vm_acceptance._failed_units("\n"), [])
        self.assertEqual(
            vm_acceptance._failed_units(
                "● foo.service loaded failed failed Foo Service\n"
                "bar.service loaded failed failed Bar Service\n"
            ),
            ["foo.service", "bar.service"],
        )

    def test_selinux_enforcing_accepts_enforcing(self):
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=_completed(0, "Enforcing\n")), \
             mock.patch("kyth_shared.vm_acceptance.emit") as emit:
            vm_acceptance._selinux_enforcing()
        emit.assert_called_once_with("INSTALLED_SELINUX_OK", "Enforcing")

    def test_selinux_enforcing_fails_when_permissive(self):
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=_completed(0, "Permissive\n")), \
             mock.patch("kyth_shared.vm_acceptance.emit"), \
             mock.patch("kyth_shared.vm_acceptance.power"):
            with self.assertRaises(SystemExit):
                vm_acceptance._selinux_enforcing()

    def test_first_boot_check_emits_ok_with_zero_failed(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text",
            side_effect=[_completed(0, ""), _completed(0, "success\n")],
        ), mock.patch("kyth_shared.vm_acceptance.emit") as emit:
            vm_acceptance._first_boot_check()
        emit.assert_called_once_with("FIRSTBOOT_OK", "0")

    def test_first_boot_check_fails_with_failed_units(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text",
            return_value=_completed(0, "● foo.service loaded failed failed Foo\n"),
        ), mock.patch("kyth_shared.vm_acceptance.emit"), \
             mock.patch("kyth_shared.vm_acceptance.power"):
            with self.assertRaises(SystemExit):
                vm_acceptance._first_boot_check()

    def test_first_boot_check_fails_when_hw_setup_did_not_succeed(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text",
            side_effect=[_completed(0, ""), _completed(0, "failed\n")],
        ), mock.patch("kyth_shared.vm_acceptance.emit"), \
             mock.patch("kyth_shared.vm_acceptance.power"):
            with self.assertRaises(SystemExit):
                vm_acceptance._first_boot_check()

    def test_network_check_emits_http_code(self):
        with mock.patch(
            "kyth_shared.vm_acceptance._installer_target_ref",
            return_value="ghcr.io/example/kyth:testing",
        ), mock.patch(
            "kyth_shared.vm_acceptance.run_text",
            side_effect=[_completed(0, "140.82.121.34 ghcr.io\n"), _completed(0, "401")],
        ), mock.patch("kyth_shared.vm_acceptance.emit") as emit:
            vm_acceptance._network_check()
        emit.assert_called_once_with("INSTALLED_NETWORK_OK", "401")

    def test_network_check_fails_when_registry_unreachable(self):
        with mock.patch(
            "kyth_shared.vm_acceptance._installer_target_ref",
            return_value="ghcr.io/example/kyth:testing",
        ), mock.patch(
            "kyth_shared.vm_acceptance.run_text",
            side_effect=[_completed(0, "140.82.121.34 ghcr.io\n"), _completed(0, "000")],
        ), mock.patch("kyth_shared.vm_acceptance.emit"), \
             mock.patch("kyth_shared.vm_acceptance.power"):
            with self.assertRaises(SystemExit):
                vm_acceptance._network_check()

    def test_registry_host_derivation(self):
        self.assertEqual(
            vm_acceptance._registry_host("ghcr.io/example/kyth:testing"), "ghcr.io"
        )
        self.assertEqual(vm_acceptance._registry_host("ghcr.io"), "ghcr.io")


def _complete_report() -> dict:
    return {
        "status": "complete",
        "checks": [
            {"name": name, "status": "pass", "detail": ""}
            for name in vm_acceptance.ASSURANCE_CHECK_NAMES
        ],
    }


class _FakeTarget:
    """Stand-in for the resolved acceptance disk path."""

    def is_block_device(self) -> bool:
        return True

    def resolve(self, strict: bool = True) -> "_FakeTarget":
        return self

    def __str__(self) -> str:
        return "/dev/vda"


class InstallerDaemonModeTests(unittest.TestCase):
    def test_installer_daemon_mode_reads_fw_cfg(self):
        with tempfile.TemporaryDirectory() as tmp:
            mode_file = pathlib.Path(tmp) / "mode"
            mode_file.write_bytes(b"daemon\x00")
            with mock.patch("kyth_shared.vm_acceptance.INSTALLER_MODE_FILE", mode_file):
                self.assertTrue(vm_acceptance.installer_daemon_mode())
            mode_file.write_bytes(b"raw")
            with mock.patch("kyth_shared.vm_acceptance.INSTALLER_MODE_FILE", mode_file):
                self.assertFalse(vm_acceptance.installer_daemon_mode())
            with mock.patch(
                "kyth_shared.vm_acceptance.INSTALLER_MODE_FILE",
                pathlib.Path(tmp) / "absent",
            ):
                self.assertFalse(vm_acceptance.installer_daemon_mode())

    def test_daemon_mode_contract_is_present_in_both_guests_and_host(self):
        python_text = pathlib.Path(vm_acceptance.__file__).read_text(encoding="utf-8")
        rust_text = (
            ROOT / "src/kyth-shared-rs/src/system/vm_acceptance.rs"
        ).read_text(encoding="utf-8")
        for text in (python_text, rust_text):
            for marker in (
                "/api/disks", "/api/start", "/api/report", "/api/stream",
                "X-Kyth-Session-Token", "installer-mode", "INSTALL_COMPLETE",
            ):
                self.assertIn(marker, text)
        host_text = HOST.read_text(encoding="utf-8")
        self.assertIn("--installer-daemon", host_text)
        self.assertIn("opt/com.kyth/installer-mode,string=daemon", host_text)

    def test_daemon_start_request_matches_the_native_contract(self):
        request = vm_acceptance._daemon_start_request(
            "/dev/vda", "kyth-acceptance", "kyth-acceptance", "kyth-acceptance"
        )
        self.assertEqual(
            set(request),
            {
                "acknowledged_irreversible", "confirm_backup", "confirm_current",
                "confirm_erase", "disk", "encryption", "flatpaks",
                "free_region_end", "free_region_start", "hostname",
                "install_mode", "kernel", "keymap", "locale", "mok_password",
                "password", "resize_gib", "resize_partition",
                "target_partition", "timezone", "tpm_recovery_ack", "username",
            },
        )
        self.assertEqual(request["disk"], "/dev/vda")
        self.assertEqual(request["install_mode"], "wipe")
        self.assertIs(request["confirm_backup"], True)
        self.assertIs(request["confirm_erase"], True)
        self.assertIs(request["acknowledged_irreversible"], True)
        self.assertEqual(request["encryption"], "none")
        self.assertEqual(request["hostname"], "kyth-acceptance")
        self.assertEqual(request["username"], "kyth-acceptance")
        self.assertEqual(request["password"], "kyth-acceptance")

    def test_acceptance_disk_selection_matches_the_raw_path_target(self):
        inventory = [
            {"name": "/dev/sda", "current": True},
            {"name": "/dev/vda", "current": False},
        ]
        target = pathlib.Path("/dev/vda")
        self.assertEqual(
            vm_acceptance._acceptance_disk_from_inventory(inventory, target),
            "/dev/vda",
        )
        # The disk hosting the live system is never eligible.
        self.assertIsNone(
            vm_acceptance._acceptance_disk_from_inventory(
                inventory, pathlib.Path("/dev/sda")
            )
        )
        self.assertIsNone(
            vm_acceptance._acceptance_disk_from_inventory(
                inventory, pathlib.Path("/dev/vdb")
            )
        )
        self.assertIsNone(
            vm_acceptance._acceptance_disk_from_inventory({}, target)
        )

    def test_report_evaluation_requires_completion_and_passing_assurance(self):
        self.assertEqual(vm_acceptance._report_failures(_complete_report()), [])

        # A warning progress check (the daemon records these on
        # successful installs, e.g. boot_entries) does not fail the run.
        report = _complete_report()
        report["checks"].append({"name": "boot_entries", "status": "warning"})
        self.assertEqual(vm_acceptance._report_failures(report), [])

        report = _complete_report()
        report["checks"] = [
            check for check in report["checks"] if check["name"] != "selinux"
        ]
        self.assertEqual(
            vm_acceptance._report_failures(report),
            ["assurance check selinux is missing"],
        )

        report = _complete_report()
        for check in report["checks"]:
            if check["name"] == "selinux":
                check["status"] = "fail"
        self.assertEqual(
            vm_acceptance._report_failures(report),
            ["assurance check selinux did not pass"],
        )

        report = _complete_report()
        report["checks"].append({"name": "power", "status": "fail"})
        self.assertEqual(
            vm_acceptance._report_failures(report),
            ["installer check power failed"],
        )

        report = _complete_report()
        report["status"] = "failed"
        self.assertEqual(
            vm_acceptance._report_failures(report),
            ['installer job status is "failed"'],
        )

        self.assertEqual(
            vm_acceptance._report_failures({"status": "complete", "checks": []}),
            ["installer report carries no checks"],
        )

    def test_daemon_error_message_extraction(self):
        self.assertEqual(
            vm_acceptance._daemon_error_message(
                '{"started": false, "message": "disk busy"}'
            ),
            "disk busy",
        )
        self.assertEqual(
            vm_acceptance._daemon_error_message('{"error": "nope"}'), "nope"
        )
        self.assertEqual(
            vm_acceptance._daemon_error_message("plain failure"), "plain failure"
        )

    def test_run_command_dispatches_to_daemon_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = pathlib.Path(tmp) / "kyth-installer.env"
            env_file.write_text("x=1")
            with mock.patch("kyth_shared.vm_acceptance.enabled", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance.INSTALLER_ENV_FILE", env_file), \
                 mock.patch("kyth_shared.vm_acceptance.installer_daemon_mode", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance.install_via_installer_daemon") as mock_daemon, \
                 mock.patch("kyth_shared.vm_acceptance.install_from_live_iso") as mock_live:
                self.assertEqual(vm_acceptance.main(["run"]), 0)
                mock_daemon.assert_called_once()
                mock_live.assert_not_called()

    def _daemon_flow_mocks(self, report: dict):
        requests: list[tuple] = []

        def fake_request(method, path, token, body=None):
            requests.append((method, path, token, body))
            if path == "/api/disks":
                return 200, json.dumps([
                    {"name": "/dev/sda", "current": True},
                    {"name": "/dev/vda", "current": False},
                ])
            if path == "/api/start":
                return 200, '{"started": true, "job_id": 1, "first_event_id": 1}'
            if path == "/api/report":
                return 200, json.dumps(report)
            raise AssertionError(f"unexpected daemon path {path}")

        return requests, fake_request

    def test_install_via_installer_daemon_runs_the_full_flow(self):
        requests, fake_request = self._daemon_flow_mocks(_complete_report())
        with mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=True), \
             mock.patch("kyth_shared.vm_acceptance.run_smoke_check"), \
             mock.patch("kyth_shared.vm_acceptance.TARGET_BY_ID", _FakeTarget()), \
             mock.patch(
                 "kyth_shared.vm_acceptance._installer_source_ref",
                 return_value="ghcr.io/mrtrickdotorg/kyth@sha256:abc",
             ), \
             mock.patch(
                 "kyth_shared.vm_acceptance._installer_target_ref",
                 return_value="ghcr.io/mrtrickdotorg/kyth:testing",
             ), \
             mock.patch(
                 "kyth_shared.vm_acceptance._prepare_installer_daemon",
                 return_value=("token-123", object()),
             ), \
             mock.patch("kyth_shared.vm_acceptance._daemon_request", side_effect=fake_request), \
             mock.patch(
                 "kyth_shared.vm_acceptance._daemon_stream_terminal_state",
                 return_value='{"id": 9, "type": "done"}',
             ) as mock_stream, \
             mock.patch("kyth_shared.vm_acceptance.emit") as emit, \
             mock.patch("kyth_shared.vm_acceptance.power") as power:
            vm_acceptance.install_via_installer_daemon()
        self.assertEqual(
            [(method, path) for method, path, _token, _body in requests],
            [("GET", "/api/disks"), ("POST", "/api/start"), ("GET", "/api/report")],
        )
        self.assertTrue(all(token == "token-123" for _m, _p, token, _b in requests))
        start_body = requests[1][3]
        self.assertEqual(start_body["disk"], "/dev/vda")
        self.assertEqual(start_body["install_mode"], "wipe")
        self.assertIs(start_body["confirm_erase"], True)
        self.assertIs(start_body["acknowledged_irreversible"], True)
        self.assertEqual(start_body["encryption"], "none")
        mock_stream.assert_called_once_with("token-123")
        emitted = [(call.args[0], call.args[1]) for call in emit.call_args_list]
        self.assertIn(("INSTALL_STARTED", "/dev/vda"), emitted)
        self.assertIn(
            ("INSTALL_COMPLETE", "ghcr.io/mrtrickdotorg/kyth:testing"), emitted
        )
        power.assert_called_once_with("reboot")

    def test_install_via_installer_daemon_fails_on_a_failed_assurance_check(self):
        report = _complete_report()
        for check in report["checks"]:
            if check["name"] == "selinux":
                check["status"] = "fail"
        _requests, fake_request = self._daemon_flow_mocks(report)
        with mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=True), \
             mock.patch("kyth_shared.vm_acceptance.run_smoke_check"), \
             mock.patch("kyth_shared.vm_acceptance.TARGET_BY_ID", _FakeTarget()), \
             mock.patch(
                 "kyth_shared.vm_acceptance._installer_source_ref",
                 return_value="ghcr.io/mrtrickdotorg/kyth@sha256:abc",
             ), \
             mock.patch(
                 "kyth_shared.vm_acceptance._installer_target_ref",
                 return_value="ghcr.io/mrtrickdotorg/kyth:testing",
             ), \
             mock.patch(
                 "kyth_shared.vm_acceptance._prepare_installer_daemon",
                 return_value=("token-123", object()),
             ), \
             mock.patch("kyth_shared.vm_acceptance._daemon_request", side_effect=fake_request), \
             mock.patch(
                 "kyth_shared.vm_acceptance._daemon_stream_terminal_state",
                 return_value='{"id": 9, "type": "done"}',
             ), \
             mock.patch("kyth_shared.vm_acceptance.emit") as emit, \
             mock.patch("kyth_shared.vm_acceptance.power"), \
             mock.patch(
                 "kyth_shared.vm_acceptance.fail", side_effect=SystemExit(1)
             ) as fail:
            with self.assertRaises(SystemExit):
                vm_acceptance.install_via_installer_daemon()
        self.assertIn("selinux", fail.call_args.args[0])
        self.assertFalse(
            any(call.args[0] == "INSTALL_COMPLETE" for call in emit.call_args_list)
        )

    def test_install_via_installer_daemon_propagates_stream_errors(self):
        _requests, fake_request = self._daemon_flow_mocks(_complete_report())
        with mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=True), \
             mock.patch("kyth_shared.vm_acceptance.run_smoke_check"), \
             mock.patch("kyth_shared.vm_acceptance.TARGET_BY_ID", _FakeTarget()), \
             mock.patch(
                 "kyth_shared.vm_acceptance._installer_source_ref",
                 return_value="ghcr.io/mrtrickdotorg/kyth@sha256:abc",
             ), \
             mock.patch(
                 "kyth_shared.vm_acceptance._installer_target_ref",
                 return_value="ghcr.io/mrtrickdotorg/kyth:testing",
             ), \
             mock.patch(
                 "kyth_shared.vm_acceptance._prepare_installer_daemon",
                 return_value=("token-123", object()),
             ), \
             mock.patch("kyth_shared.vm_acceptance._daemon_request", side_effect=fake_request), \
             mock.patch(
                 "kyth_shared.vm_acceptance._daemon_stream_terminal_state",
                 side_effect=RuntimeError("installer job failed: boom"),
             ), \
             mock.patch("kyth_shared.vm_acceptance.emit") as emit, \
             mock.patch("kyth_shared.vm_acceptance.power"):
            with self.assertRaises(RuntimeError):
                vm_acceptance.install_via_installer_daemon()
        self.assertFalse(
            any(call.args[0] == "INSTALL_COMPLETE" for call in emit.call_args_list)
        )


class VariantAcceptanceTests(unittest.TestCase):
    def test_variant_fw_cfg_readers(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb_file = pathlib.Path(tmp) / "secure-boot"
            win_file = pathlib.Path(tmp) / "windows"
            sb_file.write_bytes(b"1\x00")
            win_file.write_bytes(b"0")
            with mock.patch("kyth_shared.vm_acceptance.SECURE_BOOT_FILE", sb_file), \
                 mock.patch("kyth_shared.vm_acceptance.WINDOWS_FILE", win_file):
                self.assertTrue(vm_acceptance.secure_boot_mode())
                self.assertFalse(vm_acceptance.windows_mode())
            win_file.write_bytes(b"1")
            with mock.patch("kyth_shared.vm_acceptance.WINDOWS_FILE", win_file):
                self.assertTrue(vm_acceptance.windows_mode())
            with mock.patch(
                "kyth_shared.vm_acceptance.SECURE_BOOT_FILE",
                pathlib.Path(tmp) / "absent",
            ):
                self.assertFalse(vm_acceptance.secure_boot_mode())

    def test_variant_contract_is_present_in_both_guests_and_host(self):
        python_text = pathlib.Path(vm_acceptance.__file__).read_text(encoding="utf-8")
        rust_text = (
            ROOT / "src/kyth-shared-rs/src/system/vm_acceptance.rs"
        ).read_text(encoding="utf-8")
        for text in (python_text, rust_text):
            for marker in (
                "secure-boot", "windows", "INSTALLED_SECUREBOOT_OK",
                "WINDOWS_NTFS_BEFORE", "WINDOWS_NTFS_AFTER", "WINDOWS_NTFS_OK",
                "resize_ntfs", "ntfs_resize_candidate", "mokutil", "--sb-state",
            ):
                self.assertIn(marker, text)
        host_text = HOST.read_text(encoding="utf-8")
        for marker in (
            "--secure-boot", "--windows",
            "opt/com.kyth/secure-boot,string=1",
            "opt/com.kyth/windows,string=1",
            "virt-fw-vars", "--add-mok", "kyth-secureboot.cer",
            "OVMF_CODE_4M.secboot.fd", "OVMF_VARS_4M.ms.fd",
            "q35,smm=on", "cfi.pflash01,property=secure",
            "--secure-boot-required", "--windows-required",
            "vm-acceptance-prep-windows.sh", "128G",
            "--windows requires --installer-daemon",
            "INSTALLED_SECUREBOOT_OK", "WINDOWS_NTFS_OK",
        ):
            self.assertIn(marker, host_text)

    def test_windows_start_request_matches_the_native_contract(self):
        request = vm_acceptance._daemon_windows_start_request(
            "/dev/vda", "kyth-acceptance", "kyth-acceptance",
            "kyth-acceptance", "/dev/vda2", 63,
        )
        wipe = vm_acceptance._daemon_start_request(
            "/dev/vda", "kyth-acceptance", "kyth-acceptance", "kyth-acceptance"
        )
        self.assertEqual(set(request), set(wipe))
        self.assertEqual(request["install_mode"], "resize_ntfs")
        self.assertEqual(request["resize_partition"], "/dev/vda2")
        self.assertEqual(request["resize_gib"], 63)
        self.assertIs(request["confirm_erase"], True)
        self.assertEqual(request["encryption"], "none")

    def test_windows_resize_sizing_keeps_the_windows_floor(self):
        gib = 1024 * 1024 * 1024
        self.assertIsNone(vm_acceptance._windows_resize_gib(64 * gib))
        self.assertIsNone(vm_acceptance._windows_resize_gib(96 * gib - 1))
        self.assertEqual(vm_acceptance._windows_resize_gib(96 * gib), 32)
        self.assertEqual(vm_acceptance._windows_resize_gib(127 * gib), 63)

    def test_windows_target_requires_the_daemons_own_candidate_flag(self):
        partitions = [
            {"name": "/dev/vda1", "size_bytes": 512 * 1024 * 1024,
             "fstype": "vfat", "ntfs_resize_candidate": False},
            {"name": "/dev/vda2", "size_bytes": 127 * 1024 * 1024 * 1024,
             "fstype": "ntfs", "ntfs_resize_candidate": True},
        ]
        self.assertEqual(
            vm_acceptance._windows_resize_target_from_partitions(partitions),
            ("/dev/vda2", 63),
        )
        small = [
            {"name": "/dev/vda2", "size_bytes": 63 * 1024 * 1024 * 1024,
             "fstype": "ntfs", "ntfs_resize_candidate": False},
        ]
        self.assertIsNone(
            vm_acceptance._windows_resize_target_from_partitions(small)
        )
        self.assertIsNone(
            vm_acceptance._windows_resize_target_from_partitions({})
        )

    def test_ntfs_entries_parse_lsblk_output(self):
        output = (
            "/dev/vda\n"
            "/dev/vda1 vfat 8CA4-F0D2\n"
            "/dev/vda2 ntfs 5A8C4E2F12345678\n"
            "/dev/vda3 btrfs 9f1c-uuid\n"
            "/dev/vdb1 ntfs3 FEDCBA0987654321\n"
            "/dev/vdb2 ntfs\n"
        )
        self.assertEqual(
            vm_acceptance._ntfs_entries_from_lsblk(output),
            [
                ("/dev/vda2", "5A8C4E2F12345678"),
                ("/dev/vdb1", "FEDCBA0987654321"),
                ("/dev/vdb2", ""),
            ],
        )
        self.assertEqual(vm_acceptance._ntfs_entries_from_lsblk(""), [])

    def test_secure_boot_state_parsing(self):
        self.assertIs(
            vm_acceptance._secure_boot_state_from_output("SecureBoot enabled\n"),
            True,
        )
        self.assertIs(
            vm_acceptance._secure_boot_state_from_output("SecureBoot disabled\n"),
            False,
        )
        self.assertIsNone(vm_acceptance._secure_boot_state_from_output(""))
        self.assertIsNone(
            vm_acceptance._secure_boot_state_from_output(
                "mokutil: EFI variables are not supported\n"
            )
        )

    def _windows_flow_mocks(self, report: dict):
        requests: list[tuple] = []

        def fake_request(method, path, token, body=None):
            requests.append((method, path, token, body))
            if path == "/api/disks":
                return 200, json.dumps([
                    {"name": "/dev/sda", "current": True},
                    {"name": "/dev/vda", "current": False},
                ])
            if path == "/api/partitions?disk=%2Fdev%2Fvda":
                return 200, json.dumps([
                    {"name": "/dev/vda1", "size_bytes": 512 * 1024 * 1024,
                     "fstype": "vfat", "ntfs_resize_candidate": False},
                    {"name": "/dev/vda2",
                     "size_bytes": 127 * 1024 * 1024 * 1024,
                     "fstype": "ntfs", "ntfs_resize_candidate": True},
                ])
            if path == "/api/start":
                return 200, '{"started": true, "job_id": 1, "first_event_id": 1}'
            if path == "/api/report":
                return 200, json.dumps(report)
            raise AssertionError(f"unexpected daemon path {path}")

        return requests, fake_request

    def _windows_flow_patches(self, fake_request, ntfs_uuids):
        return (
            mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=True),
            mock.patch("kyth_shared.vm_acceptance.run_smoke_check"),
            mock.patch("kyth_shared.vm_acceptance.TARGET_BY_ID", _FakeTarget()),
            mock.patch(
                "kyth_shared.vm_acceptance._installer_source_ref",
                return_value="ghcr.io/mrtrickdotorg/kyth@sha256:abc",
            ),
            mock.patch(
                "kyth_shared.vm_acceptance._installer_target_ref",
                return_value="ghcr.io/mrtrickdotorg/kyth:testing",
            ),
            mock.patch(
                "kyth_shared.vm_acceptance._prepare_installer_daemon",
                return_value=("token-123", object()),
            ),
            mock.patch("kyth_shared.vm_acceptance.windows_mode", return_value=True),
            mock.patch("kyth_shared.vm_acceptance._daemon_request", side_effect=fake_request),
            mock.patch(
                "kyth_shared.vm_acceptance._daemon_stream_terminal_state",
                return_value='{"id": 9, "type": "done"}',
            ),
            mock.patch(
                "kyth_shared.vm_acceptance._ntfs_uuids",
                side_effect=ntfs_uuids,
            ),
        )

    def test_install_via_installer_daemon_windows_flow(self):
        requests, fake_request = self._windows_flow_mocks(_complete_report())
        patches = self._windows_flow_patches(
            fake_request, lambda device=None: [("/dev/vda2", "5A8C4E2F12345678")]
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7], patches[8], patches[9], \
             mock.patch("kyth_shared.vm_acceptance.emit") as emit, \
             mock.patch("kyth_shared.vm_acceptance.power") as power:
            vm_acceptance.install_via_installer_daemon()
        self.assertEqual(
            [(method, path) for method, path, _token, _body in requests],
            [
                ("GET", "/api/disks"),
                ("GET", "/api/partitions?disk=%2Fdev%2Fvda"),
                ("POST", "/api/start"),
                ("GET", "/api/report"),
            ],
        )
        start_body = requests[2][3]
        self.assertEqual(start_body["install_mode"], "resize_ntfs")
        self.assertEqual(start_body["resize_partition"], "/dev/vda2")
        self.assertEqual(start_body["resize_gib"], 63)
        emitted = [(call.args[0], call.args[1]) for call in emit.call_args_list]
        self.assertIn(
            ("WINDOWS_NTFS_BEFORE", "device=/dev/vda2 uuid=5A8C4E2F12345678"),
            emitted,
        )
        self.assertIn(
            ("WINDOWS_NTFS_AFTER", "device=/dev/vda2 uuid=5A8C4E2F12345678"),
            emitted,
        )
        self.assertIn(
            ("INSTALL_COMPLETE", "ghcr.io/mrtrickdotorg/kyth:testing"), emitted
        )
        power.assert_called_once_with("reboot")

    def test_windows_flow_fails_when_ntfs_identity_changes(self):
        _requests, fake_request = self._windows_flow_mocks(_complete_report())
        sightings = iter([
            [("/dev/vda2", "5A8C4E2F12345678")],
            [("/dev/vda2", "AAAA4E2F12345678")],
        ])
        patches = self._windows_flow_patches(
            fake_request, lambda device=None: next(sightings)
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7], patches[8], patches[9], \
             mock.patch("kyth_shared.vm_acceptance.emit") as emit, \
             mock.patch("kyth_shared.vm_acceptance.power"), \
             mock.patch(
                 "kyth_shared.vm_acceptance.fail", side_effect=SystemExit(1)
             ) as fail:
            with self.assertRaises(SystemExit):
                vm_acceptance.install_via_installer_daemon()
        self.assertIn("identity changed", fail.call_args.args[0])
        self.assertFalse(
            any(call.args[0] == "INSTALL_COMPLETE" for call in emit.call_args_list)
        )

    def test_secure_boot_check_emits_only_when_enabled(self):
        enabled = _completed(0, stdout="SecureBoot enabled\n")
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text", return_value=enabled
        ), mock.patch("kyth_shared.vm_acceptance.emit") as emit:
            vm_acceptance._secure_boot_check()
        emit.assert_called_once_with("INSTALLED_SECUREBOOT_OK", "enabled")

        disabled = _completed(0, stdout="SecureBoot disabled\n")
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text", return_value=disabled
        ), mock.patch(
            "kyth_shared.vm_acceptance.fail", side_effect=SystemExit(1)
        ) as fail:
            with self.assertRaises(SystemExit):
                vm_acceptance._secure_boot_check()
        self.assertIn("Secure Boot disabled", fail.call_args.args[0])

    def test_windows_ntfs_check_requires_a_surviving_volume(self):
        with mock.patch(
            "kyth_shared.vm_acceptance._ntfs_uuids",
            return_value=[("/dev/vda2", "5A8C4E2F12345678")],
        ), mock.patch("kyth_shared.vm_acceptance.emit") as emit:
            vm_acceptance._windows_ntfs_check()
        emit.assert_called_once_with(
            "WINDOWS_NTFS_OK", "device=/dev/vda2 uuid=5A8C4E2F12345678"
        )
        with mock.patch(
            "kyth_shared.vm_acceptance._ntfs_uuids", return_value=[]
        ), mock.patch(
            "kyth_shared.vm_acceptance.fail", side_effect=SystemExit(1)
        ) as fail:
            with self.assertRaises(SystemExit):
                vm_acceptance._windows_ntfs_check()
        self.assertIn("survived", fail.call_args.args[0])


class VariantPrepScriptTests(unittest.TestCase):
    def test_prep_script_shape(self):
        text = PREP.read_text(encoding="utf-8")
        for marker in (
            # GPT identities the installer's preflight keys on.
            "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
            "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
            # Both backends and their packages are named.
            "guestfish", "libguestfs-tools", "qemu-nbd", "mkntfs",
            "ntfs-3g", "mkfs.vfat", "dosfstools", "sfdisk",
            # The marker tree and the report contract.
            "Windows/System32", "NTFS_UUID=", "ntfs_resize_candidate",
            # The candidacy size floor is enforced, not assumed.
            "96 * 1024 * 1024 * 1024",
        ):
            self.assertIn(marker, text)

    @unittest.skipUnless(
        __import__("shutil").which("qemu-img"), "qemu-img is not installed"
    )
    def test_prep_refuses_a_disk_below_the_candidacy_floor(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk = pathlib.Path(tmp) / "small.qcow2"
            subprocess.run(
                ["qemu-img", "create", "-q", "-f", "qcow2", str(disk), "64G"],
                check=True,
            )
            result = subprocess.run(
                [str(PREP), "--disk", str(disk)],
                capture_output=True, text=True, timeout=120,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("96 GiB", result.stderr)


class RunSmokeCheckTests(unittest.TestCase):
    def test_ok_result_emits_smoke_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = pathlib.Path(tmp) / "log"
            serial = pathlib.Path(tmp) / "serial"
            with mock.patch("kyth_shared.vm_acceptance.LOG_FILE", log_file), \
                 mock.patch("kyth_shared.vm_acceptance.SERIAL_DEVICE", serial), \
                 mock.patch("kyth_shared.vm_acceptance.run", return_value=_completed(0)):
                vm_acceptance.run_smoke_check("LIVE")
            self.assertIn("LIVE_SMOKE_OK", log_file.read_text())

    def test_failed_invariants_calls_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = pathlib.Path(tmp) / "log"
            serial = pathlib.Path(tmp) / "serial"
            with mock.patch("kyth_shared.vm_acceptance.LOG_FILE", log_file), \
                 mock.patch("kyth_shared.vm_acceptance.SERIAL_DEVICE", serial), \
                 mock.patch("kyth_shared.vm_acceptance.run", return_value=_completed(2)), \
                 mock.patch("kyth_shared.vm_acceptance.power"):
                with self.assertRaises(SystemExit):
                    vm_acceptance.run_smoke_check("LIVE")

    def test_command_that_cannot_run_calls_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = pathlib.Path(tmp) / "log"
            serial = pathlib.Path(tmp) / "serial"
            with mock.patch("kyth_shared.vm_acceptance.LOG_FILE", log_file), \
                 mock.patch("kyth_shared.vm_acceptance.SERIAL_DEVICE", serial), \
                 mock.patch("kyth_shared.vm_acceptance.run", side_effect=OSError("no such binary")), \
                 mock.patch("kyth_shared.vm_acceptance.power"):
                with self.assertRaises(SystemExit):
                    vm_acceptance.run_smoke_check("LIVE")

    def test_smoke_check_tolerates_serial_copy_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = pathlib.Path(tmp) / "log"
            with mock.patch("kyth_shared.vm_acceptance.LOG_FILE", log_file), \
                 mock.patch("kyth_shared.vm_acceptance.SERIAL_DEVICE", pathlib.Path(tmp)), \
                 mock.patch("kyth_shared.vm_acceptance.run", return_value=_completed(1)), \
                 mock.patch("kyth_shared.vm_acceptance.emit"):
                vm_acceptance.run_smoke_check("LIVE")


class MainEntrypointTests(unittest.TestCase):
    def test_native_read_report_is_packaged_separately_from_run_executor(self):
        cargo = (ROOT / "src/kyth-shared-rs/Cargo.toml").read_text(encoding="utf-8")
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        branding = (ROOT / "build_files/scripts/branding/35-diagnostic-script-installs.sh").read_text(encoding="utf-8")
        self.assertIn('name = "kyth-vm-acceptance-guest"', cargo)
        rust = (ROOT / "src/kyth-shared-rs/src/system/vm_acceptance.rs").read_text(encoding="utf-8")
        for phase in ("LIVE_READY", "INSTALL_COMPLETE", "INSTALLED_READY", "UPDATE_STAGED", "UPDATE_BOOTED", "ROLLBACK_STAGED", "ROLLBACK_BOOTED", "COMPLETE", "FAILED"):
            self.assertIn(phase, rust)
        self.assertIn("/build/kyth-vm-acceptance-guest /usr/bin/kyth-vm-acceptance-guest", docker)
        self.assertIn("/ctx/kyth-vm-acceptance-guest /usr/libexec/kyth-vm-acceptance-guest", branding)
        self.assertNotIn("ExecCondition=", UNIT.read_text(encoding="utf-8"))
        unit = UNIT.read_text(encoding="utf-8")
        self.assertIn("ExecStart=/usr/libexec/kyth-vm-acceptance-guest run", unit)
        self.assertIn("WantedBy=multi-user.target", unit)
        self.assertIn("MemoryMax=4G", unit)
        installer = (ROOT / "installer/build.sh").read_text(encoding="utf-8")
        self.assertIn("livesys-late.service.d/kyth-vm-acceptance.conf", installer)
        self.assertIn("Wants=kyth-vm-acceptance.service", installer)

    def test_enabled_command_reflects_fw_cfg_state(self):
        with mock.patch("kyth_shared.vm_acceptance.enabled", return_value=True):
            self.assertEqual(vm_acceptance.main(["enabled"]), 0)
        with mock.patch("kyth_shared.vm_acceptance.enabled", return_value=False):
            self.assertEqual(vm_acceptance.main(["enabled"]), 1)

    def test_run_command_is_a_noop_when_not_enabled(self):
        with mock.patch("kyth_shared.vm_acceptance.enabled", return_value=False), \
             mock.patch("kyth_shared.vm_acceptance.install_from_live_iso") as mock_live, \
             mock.patch("kyth_shared.vm_acceptance.run_installed_lifecycle") as mock_installed:
            self.assertEqual(vm_acceptance.main(["run"]), 0)
            mock_live.assert_not_called()
            mock_installed.assert_not_called()

    def test_run_command_dispatches_to_live_iso_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = pathlib.Path(tmp) / "kyth-installer.env"
            env_file.write_text("x=1")
            with mock.patch("kyth_shared.vm_acceptance.enabled", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance.INSTALLER_ENV_FILE", env_file), \
                 mock.patch("kyth_shared.vm_acceptance.install_from_live_iso") as mock_live, \
                 mock.patch("kyth_shared.vm_acceptance.run_installed_lifecycle") as mock_installed:
                self.assertEqual(vm_acceptance.main(["run"]), 0)
                mock_live.assert_called_once()
                mock_installed.assert_not_called()

    def test_run_command_dispatches_to_installed_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("kyth_shared.vm_acceptance.enabled", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance.INSTALLER_ENV_FILE", pathlib.Path(tmp) / "absent"), \
                 mock.patch("kyth_shared.vm_acceptance.install_from_live_iso") as mock_live, \
                 mock.patch("kyth_shared.vm_acceptance.run_installed_lifecycle") as mock_installed:
                self.assertEqual(vm_acceptance.main(["run"]), 0)
                mock_installed.assert_called_once()
                mock_live.assert_not_called()

    def test_expected_errors_route_through_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("kyth_shared.vm_acceptance.enabled", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance.INSTALLER_ENV_FILE", pathlib.Path(tmp) / "absent"), \
                 mock.patch(
                     "kyth_shared.vm_acceptance.run_installed_lifecycle",
                     side_effect=RuntimeError("stage failed"),
                 ), \
                 mock.patch("kyth_shared.vm_acceptance.emit") as mock_emit, \
                 mock.patch("kyth_shared.vm_acceptance.power") as mock_power:
                with self.assertRaises(SystemExit) as cm:
                    vm_acceptance.main(["run"])
                self.assertEqual(cm.exception.code, 1)
                mock_emit.assert_called_once_with("FAILED", "stage failed")
                mock_power.assert_called_once_with("poweroff")


class RunInstalledLifecycleTests(unittest.TestCase):
    def _state_dir(self, tmp):
        state_dir = pathlib.Path(tmp) / "state-dir"
        return state_dir

    def test_invalid_update_ref_fails_before_anything_else(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = self._state_dir(tmp)
            with mock.patch("kyth_shared.vm_acceptance.STATE_DIR", state_dir), \
                 mock.patch("kyth_shared.vm_acceptance.STATE_FILE", state_dir / "state"), \
                 mock.patch("kyth_shared.vm_acceptance.read_update_ref", return_value="bad; poweroff"), \
                 mock.patch("kyth_shared.vm_acceptance.power") as mock_power:
                with self.assertRaises(SystemExit):
                    vm_acceptance.run_installed_lifecycle()
                mock_power.assert_called_once_with("poweroff")

    def test_fresh_state_without_update_ref_powers_off_after_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = self._state_dir(tmp)
            with mock.patch("kyth_shared.vm_acceptance.STATE_DIR", state_dir), \
                 mock.patch("kyth_shared.vm_acceptance.STATE_FILE", state_dir / "state"), \
                 mock.patch("kyth_shared.vm_acceptance.read_update_ref", return_value=""), \
                 mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance._selinux_enforcing"), \
                 mock.patch("kyth_shared.vm_acceptance._first_boot_check"), \
                 mock.patch("kyth_shared.vm_acceptance.network_check_enabled", return_value=False), \
                 mock.patch("kyth_shared.vm_acceptance.run_smoke_check") as mock_smoke, \
                 mock.patch("kyth_shared.vm_acceptance.run_hub_acceptance"), \
                 mock.patch("kyth_shared.vm_acceptance.booted_digest", return_value="sha256:aaa"), \
                 mock.patch("kyth_shared.vm_acceptance.power") as mock_power:
                vm_acceptance.run_installed_lifecycle()
                mock_smoke.assert_called_once_with("INSTALLED")
                mock_power.assert_called_once_with("poweroff")
                self.assertEqual(
                    (state_dir / "initial-digest").read_text().strip(), "sha256:aaa"
                )

    def test_fresh_state_with_update_ref_stages_update_and_reboots(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = self._state_dir(tmp)
            with mock.patch("kyth_shared.vm_acceptance.STATE_DIR", state_dir), \
                 mock.patch("kyth_shared.vm_acceptance.STATE_FILE", state_dir / "state"), \
                 mock.patch(
                     "kyth_shared.vm_acceptance.read_update_ref",
                     return_value="ghcr.io/example/kyth:testing",
                 ), \
                 mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance._selinux_enforcing"), \
                 mock.patch("kyth_shared.vm_acceptance._first_boot_check"), \
                 mock.patch("kyth_shared.vm_acceptance.network_check_enabled", return_value=False), \
                 mock.patch("kyth_shared.vm_acceptance.run_smoke_check"), \
                 mock.patch("kyth_shared.vm_acceptance.run_hub_acceptance"), \
                 mock.patch("kyth_shared.vm_acceptance.booted_digest", return_value="sha256:aaa"), \
                 mock.patch("kyth_shared.vm_acceptance._logged") as mock_logged, \
                 mock.patch("kyth_shared.vm_acceptance.power") as mock_power:
                vm_acceptance.run_installed_lifecycle()
                mock_logged.assert_called_once_with(
                    ["bootc", "switch", "ghcr.io/example/kyth:testing"], "bootc switch failed"
                )
                mock_power.assert_called_once_with("reboot")
                self.assertEqual((state_dir / "state").read_text().strip(), "update-staged")

    def test_fresh_state_fails_when_desktop_never_becomes_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = self._state_dir(tmp)
            with mock.patch("kyth_shared.vm_acceptance.STATE_DIR", state_dir), \
                 mock.patch("kyth_shared.vm_acceptance.STATE_FILE", state_dir / "state"), \
                 mock.patch("kyth_shared.vm_acceptance.read_update_ref", return_value=""), \
                 mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=False), \
                 mock.patch("kyth_shared.vm_acceptance.power") as mock_power:
                with self.assertRaises(SystemExit):
                    vm_acceptance.run_installed_lifecycle()
                mock_power.assert_called_once_with("poweroff")

    def test_update_staged_success_stages_rollback_and_reboots(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = self._state_dir(tmp)
            state_dir.mkdir(parents=True)
            (state_dir / "state").write_text("update-staged\n")
            (state_dir / "initial-digest").write_text("sha256:initial\n")
            with mock.patch("kyth_shared.vm_acceptance.STATE_DIR", state_dir), \
                 mock.patch("kyth_shared.vm_acceptance.STATE_FILE", state_dir / "state"), \
                 mock.patch("kyth_shared.vm_acceptance.read_update_ref", return_value=""), \
                 mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance.booted_digest", return_value="sha256:updated"), \
                 mock.patch("kyth_shared.vm_acceptance.deployment_count", return_value=2), \
                 mock.patch("kyth_shared.vm_acceptance.run_smoke_check") as mock_smoke, \
                 mock.patch("kyth_shared.vm_acceptance._logged") as mock_logged, \
                 mock.patch("kyth_shared.vm_acceptance.power") as mock_power:
                vm_acceptance.run_installed_lifecycle()
                mock_smoke.assert_called_once_with("UPDATE")
                mock_logged.assert_called_once_with(["bootc", "rollback"], "bootc rollback failed")
                mock_power.assert_called_once_with("reboot")
                self.assertEqual((state_dir / "state").read_text().strip(), "rollback-staged")

    def test_update_staged_fails_when_digest_did_not_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = self._state_dir(tmp)
            state_dir.mkdir(parents=True)
            (state_dir / "state").write_text("update-staged\n")
            (state_dir / "initial-digest").write_text("sha256:same\n")
            with mock.patch("kyth_shared.vm_acceptance.STATE_DIR", state_dir), \
                 mock.patch("kyth_shared.vm_acceptance.STATE_FILE", state_dir / "state"), \
                 mock.patch("kyth_shared.vm_acceptance.read_update_ref", return_value=""), \
                 mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance.booted_digest", return_value="sha256:same"), \
                 mock.patch("kyth_shared.vm_acceptance.power") as mock_power:
                with self.assertRaises(SystemExit):
                    vm_acceptance.run_installed_lifecycle()
                mock_power.assert_called_once_with("poweroff")

    def test_update_staged_fails_without_a_rollback_deployment(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = self._state_dir(tmp)
            state_dir.mkdir(parents=True)
            (state_dir / "state").write_text("update-staged\n")
            (state_dir / "initial-digest").write_text("sha256:initial\n")
            with mock.patch("kyth_shared.vm_acceptance.STATE_DIR", state_dir), \
                 mock.patch("kyth_shared.vm_acceptance.STATE_FILE", state_dir / "state"), \
                 mock.patch("kyth_shared.vm_acceptance.read_update_ref", return_value=""), \
                 mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance.booted_digest", return_value="sha256:updated"), \
                 mock.patch("kyth_shared.vm_acceptance.deployment_count", return_value=1), \
                 mock.patch("kyth_shared.vm_acceptance.power") as mock_power:
                with self.assertRaises(SystemExit):
                    vm_acceptance.run_installed_lifecycle()
                mock_power.assert_called_once_with("poweroff")

    def test_rollback_staged_success_completes_and_powers_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = self._state_dir(tmp)
            state_dir.mkdir(parents=True)
            (state_dir / "state").write_text("rollback-staged\n")
            (state_dir / "initial-digest").write_text("sha256:initial\n")
            with mock.patch("kyth_shared.vm_acceptance.STATE_DIR", state_dir), \
                 mock.patch("kyth_shared.vm_acceptance.STATE_FILE", state_dir / "state"), \
                 mock.patch("kyth_shared.vm_acceptance.read_update_ref", return_value=""), \
                 mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance.booted_digest", return_value="sha256:initial"), \
                 mock.patch("kyth_shared.vm_acceptance.run_smoke_check") as mock_smoke, \
                 mock.patch("kyth_shared.vm_acceptance.power") as mock_power:
                vm_acceptance.run_installed_lifecycle()
                mock_smoke.assert_called_once_with("ROLLBACK")
                mock_power.assert_called_once_with("poweroff")
                self.assertFalse((state_dir / "state").exists())

    def test_rollback_staged_fails_when_digest_does_not_match_initial(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = self._state_dir(tmp)
            state_dir.mkdir(parents=True)
            (state_dir / "state").write_text("rollback-staged\n")
            (state_dir / "initial-digest").write_text("sha256:initial\n")
            with mock.patch("kyth_shared.vm_acceptance.STATE_DIR", state_dir), \
                 mock.patch("kyth_shared.vm_acceptance.STATE_FILE", state_dir / "state"), \
                 mock.patch("kyth_shared.vm_acceptance.read_update_ref", return_value=""), \
                 mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance.booted_digest", return_value="sha256:not-initial"), \
                 mock.patch("kyth_shared.vm_acceptance.power") as mock_power:
                with self.assertRaises(SystemExit):
                    vm_acceptance.run_installed_lifecycle()
                mock_power.assert_called_once_with("poweroff")

    def test_unknown_state_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = self._state_dir(tmp)
            state_dir.mkdir(parents=True)
            (state_dir / "state").write_text("some-unknown-state\n")
            with mock.patch("kyth_shared.vm_acceptance.STATE_DIR", state_dir), \
                 mock.patch("kyth_shared.vm_acceptance.STATE_FILE", state_dir / "state"), \
                 mock.patch("kyth_shared.vm_acceptance.read_update_ref", return_value=""), \
                 mock.patch("kyth_shared.vm_acceptance.wait_for_desktop", return_value=True), \
                 mock.patch("kyth_shared.vm_acceptance.power") as mock_power:
                with self.assertRaises(SystemExit):
                    vm_acceptance.run_installed_lifecycle()
                mock_power.assert_called_once_with("poweroff")


class _FakeDaemonResponse:
    def __init__(self, status: int, payload: bytes):
        self.status = status
        self._payload = payload

    def read(self) -> bytes:
        return self._payload


def _daemon_connection_factory(outcomes):
    """A _UnixHTTPConnection stand-in whose request() consumes one
    outcome per connection: an exception instance is raised, anything
    else becomes the response returned by getresponse()."""
    created = []

    class FakeConnection:
        def __init__(self, socket_path, timeout):
            self.socket_path = socket_path
            self.timeout = timeout
            self.closed = False
            self.request_args = None
            self._response = None
            created.append(self)

        def request(self, method, path, body=None, headers=None):
            self.request_args = (method, path, body, headers)
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            self._response = outcome

        def getresponse(self):
            return self._response

        def close(self):
            self.closed = True

    return FakeConnection, created


class DaemonConnectionTests(unittest.TestCase):
    def test_unix_connection_connects_to_the_socket_path_with_timeout(self):
        fake_sock = mock.Mock()
        with mock.patch.object(socket, "socket", return_value=fake_sock) as factory:
            connection = vm_acceptance._UnixHTTPConnection(
                pathlib.Path("/run/kyth-installer/api.sock"), 7
            )
            connection.connect()
        factory.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
        fake_sock.settimeout.assert_called_once_with(7)
        fake_sock.connect.assert_called_once_with("/run/kyth-installer/api.sock")
        self.assertIs(connection.sock, fake_sock)

    def test_daemon_request_returns_status_and_decoded_body(self):
        factory, created = _daemon_connection_factory(
            [_FakeDaemonResponse(200, b'{"ok": true}')]
        )
        with mock.patch.object(vm_acceptance, "_UnixHTTPConnection", factory):
            status, body = vm_acceptance._daemon_request(
                "POST", "/api/start", "tok-1", {"disk": "/dev/vda"}
            )
        self.assertEqual((status, body), (200, '{"ok": true}'))
        self.assertEqual(len(created), 1)
        connection = created[0]
        self.assertEqual(connection.socket_path, vm_acceptance.INSTALLER_SOCKET)
        self.assertEqual(connection.timeout, 120)
        method, path, payload, headers = connection.request_args
        self.assertEqual((method, path), ("POST", "/api/start"))
        self.assertEqual(payload, '{"disk": "/dev/vda"}')
        self.assertEqual(headers["X-Kyth-Session-Token"], "tok-1")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertTrue(connection.closed)

    def test_daemon_request_without_body_sends_no_payload(self):
        factory, created = _daemon_connection_factory(
            [_FakeDaemonResponse(200, b"[]")]
        )
        with mock.patch.object(vm_acceptance, "_UnixHTTPConnection", factory):
            status, body = vm_acceptance._daemon_request(
                "GET", "/api/disks", "tok-1", timeout=5
            )
        self.assertEqual((status, body), (200, "[]"))
        self.assertIsNone(created[0].request_args[2])
        self.assertEqual(created[0].timeout, 5)

    def test_daemon_request_replaces_undecodable_bytes(self):
        factory, _created = _daemon_connection_factory(
            [_FakeDaemonResponse(200, b'{"a": "\xff"}')]
        )
        with mock.patch.object(vm_acceptance, "_UnixHTTPConnection", factory):
            _status, body = vm_acceptance._daemon_request("GET", "/api/x", "tok")
        self.assertEqual(body, '{"a": "\ufffd"}')

    def test_daemon_request_retries_after_a_transport_error(self):
        factory, created = _daemon_connection_factory(
            [OSError("daemon not up yet"), _FakeDaemonResponse(200, b"done")]
        )
        with mock.patch.object(vm_acceptance, "_UnixHTTPConnection", factory), \
             mock.patch("kyth_shared.vm_acceptance.time.sleep") as sleep:
            status, body = vm_acceptance._daemon_request("GET", "/api/disks", "tok")
        self.assertEqual((status, body), (200, "done"))
        self.assertEqual(len(created), 2)
        self.assertTrue(all(connection.closed for connection in created))
        sleep.assert_called_once_with(1)

    def test_daemon_request_gives_up_after_ten_transport_errors(self):
        factory, created = _daemon_connection_factory(
            [OSError("refused")] * 10
        )
        with mock.patch.object(vm_acceptance, "_UnixHTTPConnection", factory), \
             mock.patch("kyth_shared.vm_acceptance.time.sleep") as sleep:
            with self.assertRaises(RuntimeError) as caught:
                vm_acceptance._daemon_request("GET", "/api/disks", "tok")
        self.assertIn("installer daemon socket is unavailable", str(caught.exception))
        self.assertIn("refused", str(caught.exception))
        self.assertEqual(len(created), 10)
        self.assertTrue(all(connection.closed for connection in created))
        self.assertEqual(sleep.call_count, 10)


class _FakeStreamSocket:
    """Socket stand-in for _daemon_stream_terminal_state: readline()
    replays the script (bytes are returned, exception instances are
    raised, an exhausted script reads as EOF)."""

    def __init__(self, script=(), connect_error=None):
        self._script = list(script)
        self._connect_error = connect_error
        self.sent = bytearray()
        self.closed = False
        self.timeout = None
        self.address = None

    def settimeout(self, value):
        self.timeout = value

    def connect(self, address):
        if self._connect_error is not None:
            raise self._connect_error
        self.address = address

    def sendall(self, data):
        self.sent += data

    def makefile(self, mode):
        return self

    def readline(self, size=-1):
        if not self._script:
            return b""
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        self.closed = True


_STREAM_HEADERS = (
    b"HTTP/1.1 200 OK\r\n",
    b"Content-Type: text/event-stream\r\n",
    b"\r\n",
)


class DaemonStreamTests(unittest.TestCase):
    def test_stream_returns_the_done_event_payload(self):
        sock = _FakeStreamSocket([
            *_STREAM_HEADERS,
            b"event: message\r\n",
            b"data:\r\n",
            b"data: not-json\r\n",
            b'data: {"type": "progress", "percent": 10}\r\n',
            b'data: {"type": "done", "id": 3}\r\n',
        ])
        with mock.patch.object(socket, "socket", return_value=sock):
            result = vm_acceptance._daemon_stream_terminal_state("tok-9")
        self.assertEqual(result, '{"type": "done", "id": 3}')
        request = bytes(sock.sent).decode("utf-8")
        self.assertTrue(request.startswith("GET /api/stream HTTP/1.1\r\n"))
        self.assertIn("X-Kyth-Session-Token: tok-9\r\n", request)
        self.assertEqual(sock.timeout, 30)
        self.assertEqual(sock.address, str(vm_acceptance.INSTALLER_SOCKET))
        self.assertTrue(sock.closed)

    def test_stream_error_event_raises_with_the_daemon_message(self):
        sock = _FakeStreamSocket([
            *_STREAM_HEADERS,
            b'data: {"type": "error", "message": "disk exploded"}\r\n',
        ])
        with mock.patch.object(socket, "socket", return_value=sock):
            with self.assertRaises(RuntimeError) as caught:
                vm_acceptance._daemon_stream_terminal_state("tok")
        self.assertEqual(str(caught.exception), "installer job failed: disk exploded")
        self.assertTrue(sock.closed)

    def test_stream_error_event_without_a_message_uses_a_default(self):
        for payload in (
            b'data: {"type": "error"}\r\n',
            b'data: {"type": "error", "message": ""}\r\n',
            b'data: {"type": "error", "message": 42}\r\n',
        ):
            sock = _FakeStreamSocket([*_STREAM_HEADERS, payload])
            with mock.patch.object(socket, "socket", return_value=sock):
                with self.assertRaises(RuntimeError) as caught:
                    vm_acceptance._daemon_stream_terminal_state("tok")
            self.assertEqual(
                str(caught.exception),
                "installer job failed: installer reported an error",
            )

    def test_stream_rejects_a_non_200_status_line(self):
        sock = _FakeStreamSocket([b"HTTP/1.1 403 Forbidden\r\n", b"\r\n"])
        with mock.patch.object(socket, "socket", return_value=sock):
            with self.assertRaises(RuntimeError) as caught:
                vm_acceptance._daemon_stream_terminal_state("tok")
        self.assertEqual(
            str(caught.exception), "installer event stream answered HTTP 403"
        )

    def test_stream_rejects_an_unparseable_status_line(self):
        sock = _FakeStreamSocket([b"garbage\r\n", b"\r\n"])
        with mock.patch.object(socket, "socket", return_value=sock):
            with self.assertRaises(RuntimeError) as caught:
                vm_acceptance._daemon_stream_terminal_state("tok")
        self.assertEqual(
            str(caught.exception), "installer event stream answered HTTP 0"
        )

    def test_stream_returns_the_last_state_when_the_stream_ends(self):
        sock = _FakeStreamSocket([
            *_STREAM_HEADERS,
            b'data: {"type": "progress", "percent": 55}\r\n',
        ])
        with mock.patch.object(socket, "socket", return_value=sock):
            result = vm_acceptance._daemon_stream_terminal_state("tok")
        self.assertEqual(result, '{"type": "progress", "percent": 55}')

    def test_stream_survives_a_timeout_inside_the_budget(self):
        sock = _FakeStreamSocket([
            *_STREAM_HEADERS,
            TimeoutError("slow job"),
            b'data: {"type": "done"}\r\n',
        ])
        with mock.patch.object(socket, "socket", return_value=sock), \
             mock.patch(
                 "kyth_shared.vm_acceptance.time.monotonic",
                 side_effect=[1000.0, 1001.0],
             ):
            result = vm_acceptance._daemon_stream_terminal_state("tok")
        self.assertEqual(result, '{"type": "done"}')

    def test_stream_raises_once_the_budget_is_blown(self):
        sock = _FakeStreamSocket([
            *_STREAM_HEADERS,
            b'data: {"type": "progress"}\r\n',
            TimeoutError("slow job"),
        ])
        with mock.patch.object(socket, "socket", return_value=sock), \
             mock.patch(
                 "kyth_shared.vm_acceptance.time.monotonic",
                 side_effect=[1000.0, 5000.0],
             ):
            with self.assertRaises(RuntimeError) as caught:
                vm_acceptance._daemon_stream_terminal_state("tok")
        self.assertIn("did not finish within 1500s", str(caught.exception))
        self.assertIn('{"type": "progress"}', str(caught.exception))

    def test_stream_retries_a_failed_connect(self):
        refused = _FakeStreamSocket(connect_error=OSError("refused"))
        ready = _FakeStreamSocket([
            *_STREAM_HEADERS,
            b'data: {"type": "done"}\r\n',
        ])
        supply = iter([refused, ready])
        with mock.patch.object(socket, "socket", side_effect=lambda *a: next(supply)), \
             mock.patch("kyth_shared.vm_acceptance.time.sleep") as sleep:
            result = vm_acceptance._daemon_stream_terminal_state("tok")
        self.assertEqual(result, '{"type": "done"}')
        self.assertTrue(refused.closed)
        sleep.assert_called_once_with(1)

    def test_stream_gives_up_after_ten_failed_connects(self):
        created = []

        def factory(*args):
            sock = _FakeStreamSocket(connect_error=OSError("refused"))
            created.append(sock)
            return sock

        with mock.patch.object(socket, "socket", side_effect=factory), \
             mock.patch("kyth_shared.vm_acceptance.time.sleep"):
            with self.assertRaises(RuntimeError) as caught:
                vm_acceptance._daemon_stream_terminal_state("tok")
        self.assertIn("installer daemon socket is unavailable", str(caught.exception))
        self.assertEqual(len(created), 10)
        self.assertTrue(all(sock.closed for sock in created))


class PrepareInstallerDaemonTests(unittest.TestCase):
    TOKEN = "ab" * 32

    def _paths(self, tmp: str):
        base = pathlib.Path(tmp)
        run_dir = base / "run"
        run_dir.mkdir()
        socket_path = run_dir / "api.sock"
        socket_path.write_bytes(b"")
        return {
            "INSTALLER_LOCK_FILE": base / "installer.lock",
            "INSTALLER_RUN_DIR": run_dir,
            "INSTALLER_TOKEN_FILE": run_dir / "session-token",
            "INSTALLER_SOCKET": socket_path,
        }

    def _enter(self, paths, *, run_behavior=None, run_text_behavior=None):
        stack = contextlib.ExitStack()
        for name, value in paths.items():
            stack.enter_context(mock.patch.object(vm_acceptance, name, value))
        run = stack.enter_context(
            mock.patch(
                "kyth_shared.vm_acceptance.run",
                side_effect=run_behavior or (lambda command, **kw: _completed(0)),
            )
        )
        run_text = stack.enter_context(
            mock.patch(
                "kyth_shared.vm_acceptance.run_text",
                side_effect=run_text_behavior or self._default_run_text,
            )
        )
        stack.enter_context(mock.patch("kyth_shared.vm_acceptance.time.sleep"))
        return stack, run, run_text

    def _default_run_text(self, command, **kwargs):
        if command[0] == "openssl":
            return _completed(0, self.TOKEN + "\n")
        return _completed(0)

    def test_prepare_creates_a_root_only_token_and_returns_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(tmp)
            stack, run, _run_text = self._enter(paths)
            with stack:
                token, lock_handle = vm_acceptance._prepare_installer_daemon()
            try:
                self.assertEqual(token, self.TOKEN)
                token_file = paths["INSTALLER_TOKEN_FILE"]
                self.assertEqual(token_file.read_text(encoding="utf-8"), self.TOKEN)
                self.assertEqual(token_file.stat().st_mode & 0o777, 0o600)
            finally:
                lock_handle.close()
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(commands[0][:2], ["install", "-d"])
            self.assertIn("0750", commands[0])
            self.assertIn(str(paths["INSTALLER_RUN_DIR"]), commands[0])
            self.assertEqual(
                commands[1], ["systemctl", "restart", "kyth-installerd.service"]
            )

    def test_prepare_fails_when_the_lock_cannot_be_opened(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(tmp)
            paths["INSTALLER_LOCK_FILE"] = pathlib.Path(tmp) / "no-dir" / "lock"
            stack, _run, _run_text = self._enter(paths)
            with stack:
                with self.assertRaises(RuntimeError) as caught:
                    vm_acceptance._prepare_installer_daemon()
            self.assertIn("could not open installer session lock", str(caught.exception))

    def test_prepare_fails_when_another_session_holds_the_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(tmp)
            holder = paths["INSTALLER_LOCK_FILE"].open("a+")
            try:
                fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
                stack, _run, _run_text = self._enter(paths)
                with stack:
                    with self.assertRaises(RuntimeError) as caught:
                        vm_acceptance._prepare_installer_daemon()
                self.assertIn(
                    "another installer session is already in progress",
                    str(caught.exception),
                )
            finally:
                holder.close()

    def test_prepare_fails_when_the_runtime_directory_cannot_be_created(self):
        def run_behavior(command, **kwargs):
            if command[0] == "install":
                return _completed(1)
            return _completed(0)

        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(tmp)
            stack, _run, _run_text = self._enter(paths, run_behavior=run_behavior)
            with stack:
                with self.assertRaises(RuntimeError) as caught:
                    vm_acceptance._prepare_installer_daemon()
            self.assertIn(
                "could not create the installer runtime directory",
                str(caught.exception),
            )

    def test_prepare_fails_when_openssl_cannot_produce_a_token(self):
        def none_result(command, **kwargs):
            return None

        def failed_result(command, **kwargs):
            if command[0] == "openssl":
                return _completed(1)
            return _completed(0)

        def malformed_result(command, **kwargs):
            if command[0] == "openssl":
                return _completed(0, "not-a-hex-token\n")
            return _completed(0)

        for behavior in (none_result, failed_result, malformed_result):
            with tempfile.TemporaryDirectory() as tmp:
                paths = self._paths(tmp)
                stack, _run, _run_text = self._enter(
                    paths, run_text_behavior=behavior
                )
                with stack:
                    with self.assertRaises(RuntimeError) as caught:
                        vm_acceptance._prepare_installer_daemon()
                self.assertIn("session token", str(caught.exception))

    def test_prepare_fails_when_the_daemon_restart_fails(self):
        def run_behavior(command, **kwargs):
            if command[:2] == ["systemctl", "restart"]:
                return _completed(1)
            return _completed(0)

        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(tmp)
            stack, _run, _run_text = self._enter(paths, run_behavior=run_behavior)
            with stack:
                with self.assertRaises(RuntimeError) as caught:
                    vm_acceptance._prepare_installer_daemon()
            self.assertIn("could not restart the installer daemon", str(caught.exception))

    def test_prepare_waits_for_the_daemon_to_become_active(self):
        polls = []

        def run_text_behavior(command, **kwargs):
            if command[0] == "openssl":
                return _completed(0, self.TOKEN + "\n")
            polls.append(command)
            return _completed(0 if len(polls) > 1 else 1)

        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(tmp)
            stack, _run, _run_text = self._enter(
                paths, run_text_behavior=run_text_behavior
            )
            with stack:
                token, lock_handle = vm_acceptance._prepare_installer_daemon()
            lock_handle.close()
            self.assertEqual(token, self.TOKEN)
            self.assertEqual(len(polls), 2)

    def test_prepare_fails_when_the_daemon_never_becomes_ready(self):
        polls = []

        def run_text_behavior(command, **kwargs):
            if command[0] == "openssl":
                return _completed(0, self.TOKEN + "\n")
            polls.append(command)
            return _completed(1)

        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(tmp)
            stack, _run, _run_text = self._enter(
                paths, run_text_behavior=run_text_behavior
            )
            with stack:
                with self.assertRaises(RuntimeError) as caught:
                    vm_acceptance._prepare_installer_daemon()
            self.assertIn("did not become ready", str(caught.exception))
            self.assertEqual(len(polls), 30)


class _EventuallyBlockTarget(_FakeTarget):
    """Acceptance disk that appears after a few block-device probes."""

    def __init__(self, misses: int):
        self._misses = misses

    def is_block_device(self) -> bool:
        if self._misses:
            self._misses -= 1
            return False
        return True


class _UnresolvableTarget:
    def is_block_device(self) -> bool:
        return True

    def resolve(self, strict: bool = True):
        raise OSError("by-id symlink is gone")


class _NonBlockTarget:
    def is_block_device(self) -> bool:
        return False

    def resolve(self, strict: bool = True) -> "_NonBlockTarget":
        return self


class DaemonFlowFailureTests(unittest.TestCase):
    PARTITIONS_PATH = "/api/partitions?disk=%2Fdev%2Fvda"

    def _ok_responses(self, report: dict) -> dict:
        return {
            "/api/disks": (200, json.dumps([
                {"name": "/dev/sda", "current": True},
                {"name": "/dev/vda", "current": False},
            ])),
            self.PARTITIONS_PATH: (200, json.dumps([
                {"name": "/dev/vda1", "size_bytes": 512 * 1024 * 1024,
                 "fstype": "vfat", "ntfs_resize_candidate": False},
                {"name": "/dev/vda2",
                 "size_bytes": 127 * 1024 * 1024 * 1024,
                 "fstype": "ntfs", "ntfs_resize_candidate": True},
            ])),
            "/api/start": (200, '{"started": true, "job_id": 1, "first_event_id": 1}'),
            "/api/report": (200, json.dumps(report)),
        }

    def _request_fake(self, responses: dict):
        def fake(method, path, token, body=None):
            if path in responses:
                return responses[path]
            raise AssertionError(f"unexpected daemon path {path}")

        return fake

    def _enter_flow(self, fake_request, *, windows=False, ntfs_uuids=None,
                    target=None, source_ref="ghcr.io/mrtrickdotorg/kyth@sha256:abc"):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.wait_for_desktop", return_value=True))
        stack.enter_context(mock.patch("kyth_shared.vm_acceptance.run_smoke_check"))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.TARGET_BY_ID", target or _FakeTarget()))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._installer_source_ref",
            return_value=source_ref))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._installer_target_ref",
            return_value="ghcr.io/mrtrickdotorg/kyth:testing"))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._prepare_installer_daemon",
            return_value=("token-123", object())))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._daemon_request", side_effect=fake_request))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._daemon_stream_terminal_state",
            return_value='{"type": "done"}'))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.windows_mode", return_value=windows))
        if ntfs_uuids is not None:
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance._ntfs_uuids", side_effect=ntfs_uuids))
        emit = stack.enter_context(mock.patch("kyth_shared.vm_acceptance.emit"))
        power = stack.enter_context(mock.patch("kyth_shared.vm_acceptance.power"))
        fail = stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.fail", side_effect=SystemExit(1)))
        return stack, emit, power, fail

    def _assert_fails_with(self, responses, fragment, **flow_kwargs):
        fake = self._request_fake(responses)
        stack, _emit, _power, fail = self._enter_flow(fake, **flow_kwargs)
        with stack:
            with self.assertRaises(SystemExit):
                vm_acceptance.install_via_installer_daemon()
        self.assertIn(fragment, fail.call_args.args[0])

    def test_disk_inventory_http_error_fails(self):
        responses = self._ok_responses(_complete_report())
        responses["/api/disks"] = (503, '{"message": "busy"}')
        self._assert_fails_with(responses, "installer disk inventory answered HTTP 503: busy")

    def test_disk_inventory_invalid_json_fails(self):
        responses = self._ok_responses(_complete_report())
        responses["/api/disks"] = (200, "not json")
        self._assert_fails_with(responses, "installer disk inventory was not valid JSON")

    def test_disk_missing_from_inventory_fails(self):
        responses = self._ok_responses(_complete_report())
        responses["/api/disks"] = (200, json.dumps([
            {"name": "/dev/sda", "current": True},
        ]))
        self._assert_fails_with(responses, "missing from the installer inventory")

    def test_start_http_error_fails(self):
        responses = self._ok_responses(_complete_report())
        responses["/api/start"] = (500, '{"error": "disk gone"}')
        self._assert_fails_with(responses, "installer start answered HTTP 500: disk gone")

    def test_report_http_error_fails(self):
        responses = self._ok_responses(_complete_report())
        responses["/api/report"] = (503, '{"message": "busy"}')
        self._assert_fails_with(responses, "installer report answered HTTP 503: busy")

    def test_report_invalid_json_fails(self):
        responses = self._ok_responses(_complete_report())
        responses["/api/report"] = (200, "nope")
        self._assert_fails_with(responses, "installer report was not valid JSON")

    def test_report_with_only_a_warning_check_completes(self):
        report = _complete_report()
        report["checks"].append(
            {"name": "boot_entries", "status": "warning", "detail": ""}
        )
        fake = self._request_fake(self._ok_responses(report))
        stack, emit, power, fail = self._enter_flow(fake)
        with stack:
            vm_acceptance.install_via_installer_daemon()
        fail.assert_not_called()
        emitted = [(call.args[0], call.args[1]) for call in emit.call_args_list]
        self.assertIn(
            ("INSTALL_COMPLETE", "ghcr.io/mrtrickdotorg/kyth:testing"), emitted
        )
        power.assert_called_once_with("reboot")

    def test_desktop_never_ready_fails(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.wait_for_desktop", return_value=False
        ), mock.patch(
            "kyth_shared.vm_acceptance.fail", side_effect=SystemExit(1)
        ) as fail:
            with self.assertRaises(SystemExit):
                vm_acceptance.install_via_installer_daemon()
        self.assertEqual(
            fail.call_args.args[0], "live Plasma desktop did not become ready"
        )

    def test_target_appearing_after_a_wait_still_installs(self):
        fake = self._request_fake(self._ok_responses(_complete_report()))
        stack, emit, power, fail = self._enter_flow(
            fake, target=_EventuallyBlockTarget(2)
        )
        with stack, mock.patch("kyth_shared.vm_acceptance.time.sleep") as sleep:
            vm_acceptance.install_via_installer_daemon()
        self.assertEqual(sleep.call_count, 2)
        fail.assert_not_called()
        power.assert_called_once_with("reboot")

    def test_unresolvable_target_fails(self):
        fake = self._request_fake(self._ok_responses(_complete_report()))
        stack, _emit, _power, fail = self._enter_flow(
            fake, target=_UnresolvableTarget()
        )
        with stack:
            with self.assertRaises(SystemExit):
                vm_acceptance.install_via_installer_daemon()
        self.assertEqual(
            fail.call_args.args[0], "dedicated acceptance disk not found"
        )

    def test_non_block_target_fails(self):
        fake = self._request_fake(self._ok_responses(_complete_report()))
        stack, _emit, _power, fail = self._enter_flow(
            fake, target=_NonBlockTarget()
        )
        with stack, mock.patch("kyth_shared.vm_acceptance.time.sleep"):
            with self.assertRaises(SystemExit):
                vm_acceptance.install_via_installer_daemon()
        self.assertEqual(
            fail.call_args.args[0],
            "acceptance disk symlink did not resolve to a block device",
        )

    def test_invalid_source_ref_fails(self):
        fake = self._request_fake(self._ok_responses(_complete_report()))
        stack, _emit, _power, fail = self._enter_flow(fake, source_ref="bad ref!")
        with stack:
            with self.assertRaises(SystemExit):
                vm_acceptance.install_via_installer_daemon()
        self.assertEqual(
            fail.call_args.args[0],
            "installer source image reference contains unsupported characters",
        )

    def test_windows_partition_inventory_http_error_fails(self):
        responses = self._ok_responses(_complete_report())
        responses[self.PARTITIONS_PATH] = (500, '{"message": "udev busy"}')
        self._assert_fails_with(
            responses,
            "installer partition inventory answered HTTP 500: udev busy",
            windows=True,
        )

    def test_windows_partition_inventory_invalid_json_fails(self):
        responses = self._ok_responses(_complete_report())
        responses[self.PARTITIONS_PATH] = (200, "not json")
        self._assert_fails_with(
            responses,
            "installer partition inventory was not valid JSON",
            windows=True,
        )

    def test_windows_without_a_resize_candidate_fails(self):
        responses = self._ok_responses(_complete_report())
        responses[self.PARTITIONS_PATH] = (200, json.dumps([
            {"name": "/dev/vda2", "size_bytes": 127 * 1024 * 1024 * 1024,
             "fstype": "ntfs", "ntfs_resize_candidate": False},
        ]))
        self._assert_fails_with(
            responses, "no NTFS shrink candidate", windows=True
        )

    def test_windows_partition_without_a_uuid_fails(self):
        for sightings in ([[]], [[("/dev/vda2", "")]]):
            self._assert_fails_with(
                self._ok_responses(_complete_report()),
                "has no readable volume UUID",
                windows=True,
                ntfs_uuids=sightings,
            )

    def test_windows_partition_lost_during_install_fails(self):
        sightings = [
            [("/dev/vda2", "5A8C4E2F12345678")],
            [],
        ]
        self._assert_fails_with(
            self._ok_responses(_complete_report()),
            "missing or lost its volume identity",
            windows=True,
            ntfs_uuids=sightings,
        )


class RawInstallFailureTests(unittest.TestCase):
    def _enter(self, *, run_behavior=None, target=None, update_ref=""):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.wait_for_desktop", return_value=True))
        stack.enter_context(mock.patch("kyth_shared.vm_acceptance.run_smoke_check"))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.TARGET_BY_ID", target or _FakeTarget()))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._installer_source_ref",
            return_value="ghcr.io/kyth-os/kyth@sha256:abc123"))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._installer_target_ref",
            return_value="ghcr.io/example/kyth:testing"))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.read_update_ref", return_value=update_ref))
        stack.enter_context(mock.patch("kyth_shared.vm_acceptance.emit"))
        fail = stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.fail", side_effect=SystemExit(1)))
        return stack, fail

    def test_desktop_never_ready_fails(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.wait_for_desktop", return_value=False
        ), mock.patch(
            "kyth_shared.vm_acceptance.fail", side_effect=SystemExit(1)
        ) as fail:
            with self.assertRaises(SystemExit):
                vm_acceptance.install_from_live_iso()
        self.assertEqual(
            fail.call_args.args[0], "live Plasma desktop did not become ready"
        )

    def test_unresolvable_target_fails(self):
        stack, fail = self._enter(target=_UnresolvableTarget())
        with stack:
            with self.assertRaises(SystemExit):
                vm_acceptance.install_from_live_iso()
        self.assertEqual(
            fail.call_args.args[0], "dedicated acceptance disk not found"
        )

    def test_non_block_target_fails(self):
        stack, fail = self._enter(target=_NonBlockTarget())
        with stack, mock.patch("kyth_shared.vm_acceptance.time.sleep"):
            with self.assertRaises(SystemExit):
                vm_acceptance.install_from_live_iso()
        self.assertEqual(
            fail.call_args.args[0],
            "acceptance disk symlink did not resolve to a block device",
        )

    def test_bootc_spawn_failure_fails(self):
        stack, fail = self._enter()
        with tempfile.TemporaryDirectory() as tmp:
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.LOG_FILE", pathlib.Path(tmp) / "log"))
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.run",
                side_effect=OSError("bootc missing")))
            with stack:
                with self.assertRaises(SystemExit):
                    vm_acceptance.install_from_live_iso()
        self.assertEqual(fail.call_args.args[0], "bootc install to-disk failed")

    def test_bootc_nonzero_exit_fails(self):
        stack, fail = self._enter()
        with tempfile.TemporaryDirectory() as tmp:
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.LOG_FILE", pathlib.Path(tmp) / "log"))
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.run", return_value=_completed(1)))
            with stack:
                with self.assertRaises(SystemExit):
                    vm_acceptance.install_from_live_iso()
        self.assertEqual(fail.call_args.args[0], "bootc install to-disk failed")

    def test_invalid_update_ref_fails_after_install(self):
        stack, fail = self._enter(update_ref="bad; poweroff")
        with tempfile.TemporaryDirectory() as tmp:
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.LOG_FILE", pathlib.Path(tmp) / "log"))
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.run", return_value=_completed(0)))
            with stack:
                with self.assertRaises(SystemExit):
                    vm_acceptance.install_from_live_iso()
        self.assertEqual(
            fail.call_args.args[0],
            "update image reference contains unsupported characters",
        )


class GraphicalSessionTests(unittest.TestCase):
    def test_no_active_session_returns_none(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text", return_value=_completed(1, "")
        ):
            self.assertIsNone(vm_acceptance._active_graphical_session())
        with mock.patch("kyth_shared.vm_acceptance.run_text", return_value=None):
            self.assertIsNone(vm_acceptance._active_graphical_session())

    def test_session_without_an_owner_name_returns_none(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text",
            side_effect=[_completed(0, "c1\n"), _completed(0, "\n")],
        ):
            self.assertIsNone(vm_acceptance._active_graphical_session())

    def test_unknown_session_user_returns_none(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text",
            side_effect=[_completed(0, "c1\n"), _completed(0, "ghost\n")],
        ), mock.patch(
            "kyth_shared.vm_acceptance.pwd.getpwnam", side_effect=KeyError("ghost")
        ):
            self.assertIsNone(vm_acceptance._active_graphical_session())

    def test_wayland_x11_and_xauthority_reach_the_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            runtime = base / "run-user"
            runtime.mkdir()
            (runtime / "wayland-0").write_bytes(b"")
            x11_dir = base / "x11-unix"
            x11_dir.mkdir()
            (x11_dir / "X0").write_bytes(b"")
            home = base / "home"
            home.mkdir()
            (home / ".Xauthority").write_bytes(b"cookie")
            account = mock.Mock(pw_uid=4321, pw_dir=str(home))

            def path_factory(value):
                text = str(value)
                if text.startswith("/run/user/"):
                    return runtime
                if text == "/tmp/.X11-unix":
                    return x11_dir
                return pathlib.Path(value)

            with mock.patch(
                "kyth_shared.vm_acceptance.run_text",
                side_effect=[_completed(0, "c1\n"), _completed(0, "tester\n")],
            ), mock.patch(
                "kyth_shared.vm_acceptance.pwd.getpwnam", return_value=account
            ), mock.patch(
                "kyth_shared.vm_acceptance.Path", side_effect=path_factory
            ):
                result = vm_acceptance._active_graphical_session()
        username, environment = result
        self.assertEqual(username, "tester")
        self.assertEqual(environment["WAYLAND_DISPLAY"], "wayland-0")
        self.assertEqual(environment["DISPLAY"], ":0")
        self.assertEqual(environment["XAUTHORITY"], str(home / ".Xauthority"))
        self.assertEqual(environment["XDG_SESSION_TYPE"], "wayland")
        self.assertEqual(environment["XDG_RUNTIME_DIR"], str(runtime))


class _ExplodingPath:
    """Path stand-in whose write_text always fails (read-only /etc)."""

    def __init__(self, *args):
        pass

    def write_text(self, *args, **kwargs):
        raise OSError("read-only file system")


class EnsureGraphicalSessionTests(unittest.TestCase):
    def _enter(self, *, sessions, account_result, run_behavior=None):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._active_graphical_session",
            side_effect=sessions))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.run_text", return_value=account_result))
        run = stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.run",
            side_effect=run_behavior or (lambda command, **kw: _completed(0))))
        stack.enter_context(mock.patch("kyth_shared.vm_acceptance.time.sleep"))
        return stack, run

    def test_existing_display_session_is_returned_immediately(self):
        session = ("tester", {"WAYLAND_DISPLAY": "wayland-0", "HOME": "/home/tester"})
        stack, run = self._enter(sessions=[session], account_result=_completed(0))
        with stack:
            result = vm_acceptance._ensure_acceptance_graphical_session()
        self.assertEqual(result, session)
        run.assert_not_called()

    def test_bootstrap_creates_the_account_and_autologin_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / "90-kyth-vm-acceptance.conf"
            ready = ("kyth-acceptance", {"DISPLAY": ":0"})
            stack, run = self._enter(
                sessions=[("tester", {"HOME": "/x"}), ready],
                account_result=_completed(1),
            )
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.Path", return_value=config))
            with stack:
                result = vm_acceptance._ensure_acceptance_graphical_session()
            self.assertEqual(result, ready)
            contents = config.read_text(encoding="utf-8")
            self.assertIn("User=kyth-acceptance", contents)
            self.assertIn("Session=plasma.desktop", contents)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(commands[0][:1], ["useradd"])
            self.assertIn("kyth-acceptance", commands[0])
            self.assertEqual(
                commands[1],
                ["systemctl", "restart", "display-manager.service", "--no-block"],
            )

    def test_bootstrap_skips_useradd_when_the_account_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / "90-kyth-vm-acceptance.conf"
            ready = ("kyth-acceptance", {"WAYLAND_DISPLAY": "wayland-0"})
            stack, run = self._enter(
                sessions=[None, ready],
                account_result=_completed(0, "1001\n"),
            )
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.Path", return_value=config))
            with stack:
                result = vm_acceptance._ensure_acceptance_graphical_session()
            self.assertEqual(result, ready)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(len(commands), 1)
            self.assertEqual(commands[0][:2], ["systemctl", "restart"])

    def test_bootstrap_treats_a_missing_id_result_as_no_account(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / "90-kyth-vm-acceptance.conf"
            ready = ("kyth-acceptance", {"DISPLAY": ":0"})
            stack, run = self._enter(
                sessions=[None, ready],
                account_result=None,
            )
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.Path", return_value=config))
            with stack:
                result = vm_acceptance._ensure_acceptance_graphical_session()
            self.assertEqual(result, ready)
            self.assertEqual(run.call_args_list[0].args[0][:1], ["useradd"])

    def test_bootstrap_gives_up_when_useradd_fails(self):
        stack, _run = self._enter(
            sessions=[None],
            account_result=_completed(1),
            run_behavior=lambda command, **kw: _completed(1),
        )
        with stack:
            self.assertIsNone(vm_acceptance._ensure_acceptance_graphical_session())

    def test_bootstrap_gives_up_when_the_config_cannot_be_written(self):
        stack, _run = self._enter(
            sessions=[None],
            account_result=_completed(0, "1001\n"),
        )
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.Path", _ExplodingPath))
        with stack:
            self.assertIsNone(vm_acceptance._ensure_acceptance_graphical_session())

    def test_bootstrap_gives_up_when_the_login_manager_restart_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / "90-kyth-vm-acceptance.conf"
            stack, _run = self._enter(
                sessions=[None],
                account_result=_completed(0, "1001\n"),
                run_behavior=lambda command, **kw: _completed(1),
            )
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.Path", return_value=config))
            with stack:
                self.assertIsNone(
                    vm_acceptance._ensure_acceptance_graphical_session()
                )

    def test_bootstrap_gives_up_when_no_session_appears(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / "90-kyth-vm-acceptance.conf"
            stack, _run = self._enter(
                sessions=[None] * 61,
                account_result=_completed(0, "1001\n"),
            )
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.Path", return_value=config))
            with stack:
                self.assertIsNone(
                    vm_acceptance._ensure_acceptance_graphical_session()
                )


class HubHelperBranchTests(unittest.TestCase):
    def test_hub_pages_fails_when_the_manifest_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "kyth_shared.vm_acceptance.HUB_ROUTE_MANIFEST",
                pathlib.Path(tmp) / "absent.json",
            ), mock.patch("kyth_shared.vm_acceptance.power"):
                with self.assertRaises(SystemExit):
                    vm_acceptance._hub_pages()

    def test_hub_pages_fails_on_duplicate_page_keys(self):
        manifest = {
            "destinations": [
                {"key": "Updates", "route": "/updates", "sections": []},
                {"key": "Updates", "route": "/updates-2", "sections": []},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "hubRoutes.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with mock.patch(
                "kyth_shared.vm_acceptance.HUB_ROUTE_MANIFEST", path
            ), mock.patch("kyth_shared.vm_acceptance.power"):
                with self.assertRaises(SystemExit):
                    vm_acceptance._hub_pages()

    def test_hub_pages_fails_on_a_malformed_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "hubRoutes.json"
            path.write_text("{}", encoding="utf-8")
            with mock.patch(
                "kyth_shared.vm_acceptance.HUB_ROUTE_MANIFEST", path
            ), mock.patch("kyth_shared.vm_acceptance.power"):
                with self.assertRaises(SystemExit):
                    vm_acceptance._hub_pages()

    def test_hub_start_without_degraded_filters_empty_environment_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = pathlib.Path(tmp) / "hub.log"
            process = mock.Mock()
            with mock.patch(
                "kyth_shared.vm_acceptance.subprocess.Popen", return_value=process
            ) as popen:
                started = vm_acceptance._hub_start(
                    "tester",
                    {"HOME": "/tmp", "DISPLAY": ""},
                    "Welcome",
                    evidence,
                )
            self.assertIs(started, process)
            command = popen.call_args.args[0]
            self.assertIn("HOME=/tmp", command)
            self.assertNotIn("DISPLAY=", command)
            self.assertFalse(
                any("KYTH_HUB_ACCEPTANCE_DEGRADED" in part for part in command)
            )

    def test_hub_stop_escalates_to_sigkill_when_sigterm_is_ignored(self):
        process = mock.Mock()
        process.pid = 4321
        process.poll.return_value = None
        process.wait.side_effect = [
            subprocess.TimeoutExpired(["kyth-hub-shell"], 8),
            None,
        ]
        with mock.patch("kyth_shared.vm_acceptance.os.killpg") as killpg:
            vm_acceptance._hub_stop(process)
        self.assertEqual(
            [call.args for call in killpg.call_args_list],
            [(4321, signal.SIGTERM), (4321, signal.SIGKILL)],
        )

    def test_hub_launch_check_rejects_mismatched_or_missing_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = pathlib.Path(tmp) / "hub.log"
            with mock.patch(
                "kyth_shared.vm_acceptance._hub_start", return_value=mock.Mock()
            ), mock.patch("kyth_shared.vm_acceptance._hub_stop"), mock.patch(
                "kyth_shared.vm_acceptance._wait_hub_event",
                return_value={"page": "Updates", "route": "/wrong", "source": "initial"},
            ):
                self.assertFalse(
                    vm_acceptance._hub_launch_check(
                        "tester", {}, "Updates", "/updates", evidence
                    )
                )
            with mock.patch(
                "kyth_shared.vm_acceptance._hub_start", return_value=mock.Mock()
            ), mock.patch("kyth_shared.vm_acceptance._hub_stop"), mock.patch(
                "kyth_shared.vm_acceptance._wait_hub_event", return_value=None
            ):
                self.assertFalse(
                    vm_acceptance._hub_launch_check(
                        "tester", {}, "Updates", "/updates", evidence
                    )
                )
            with mock.patch(
                "kyth_shared.vm_acceptance._hub_start", return_value=mock.Mock()
            ), mock.patch("kyth_shared.vm_acceptance._hub_stop"), mock.patch(
                "kyth_shared.vm_acceptance._wait_hub_event",
                return_value={
                    "page": "Updates", "route": "/updates", "source": "single-instance",
                },
            ):
                self.assertFalse(
                    vm_acceptance._hub_launch_check(
                        "tester", {}, "Updates", "/updates", evidence
                    )
                )

    def test_hub_event_scans_past_newer_events_and_other_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = pathlib.Path(tmp) / "hub.log"
            evidence.write_text(
                'KYTH_HUB_ACCEPTANCE:deep-link:{"page":"Welcome"}\n'
                'KYTH_HUB_ACCEPTANCE:dashboard:{"state":"degraded"}\n'
                "an unrelated log line\n",
                encoding="utf-8",
            )
            self.assertEqual(
                vm_acceptance._hub_event(evidence, "deep-link"),
                {"page": "Welcome"},
            )
            self.assertIsNone(vm_acceptance._hub_event(evidence, "updates-probe"))

    def test_wait_hub_event_times_out_to_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = pathlib.Path(tmp) / "missing.log"
            with mock.patch(
                "kyth_shared.vm_acceptance.time.monotonic",
                side_effect=[0.0, 100.0],
            ):
                self.assertIsNone(
                    vm_acceptance._wait_hub_event(evidence, "deep-link", timeout=45)
                )
            # One empty poll inside the deadline, then the deadline passes.
            with mock.patch(
                "kyth_shared.vm_acceptance.time.monotonic",
                side_effect=[0.0, 0.0, 100.0],
            ), mock.patch("kyth_shared.vm_acceptance.time.sleep"):
                self.assertIsNone(
                    vm_acceptance._wait_hub_event(evidence, "deep-link", timeout=45)
                )

    def test_logged_runs_the_command_and_fails_on_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = pathlib.Path(tmp) / "log"
            with mock.patch(
                "kyth_shared.vm_acceptance.LOG_FILE", log_file
            ), mock.patch(
                "kyth_shared.vm_acceptance.run", return_value=_completed(0)
            ) as run:
                vm_acceptance._logged(["bootc", "rollback"], "rollback failed")
            self.assertEqual(run.call_args.args[0], ["bootc", "rollback"])
            with mock.patch(
                "kyth_shared.vm_acceptance.LOG_FILE", log_file
            ), mock.patch(
                "kyth_shared.vm_acceptance.run", return_value=_completed(3)
            ), mock.patch("kyth_shared.vm_acceptance.power"):
                with self.assertRaises(SystemExit):
                    vm_acceptance._logged(["bootc", "rollback"], "rollback failed")


class HubAcceptanceFailureTests(unittest.TestCase):
    def _enter(self, *, events, launch_check=True):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch("kyth_shared.vm_acceptance.emit"))
        stack.enter_context(mock.patch("kyth_shared.vm_acceptance.power"))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._ensure_acceptance_graphical_session",
            return_value=("tester", {"HOME": "/tmp", "DISPLAY": ":0"})))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._hub_pages",
            return_value=(("Welcome", "/"),)))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._hub_launch_check",
            return_value=launch_check))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._hub_start",
            side_effect=[mock.Mock() for _ in range(4)]))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._wait_hub_event", side_effect=events))
        stack.enter_context(mock.patch("kyth_shared.vm_acceptance._hub_stop"))
        return stack

    def _run_with_binary(self, stack):
        with tempfile.TemporaryDirectory() as tmp:
            binary = pathlib.Path(tmp) / "kyth-hub-shell"
            binary.write_bytes(b"hub")
            binary.chmod(0o755)
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.HUB_BINARY", binary))
            with stack:
                with self.assertRaises(SystemExit):
                    vm_acceptance.run_hub_acceptance()

    def test_missing_hub_binary_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "kyth_shared.vm_acceptance.HUB_BINARY",
                pathlib.Path(tmp) / "absent",
            ), mock.patch("kyth_shared.vm_acceptance.power"), mock.patch(
                "kyth_shared.vm_acceptance.emit"
            ):
                with self.assertRaises(SystemExit):
                    vm_acceptance.run_hub_acceptance()

    def test_missing_session_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = pathlib.Path(tmp) / "kyth-hub-shell"
            binary.write_bytes(b"hub")
            binary.chmod(0o755)
            with mock.patch(
                "kyth_shared.vm_acceptance.HUB_BINARY", binary
            ), mock.patch(
                "kyth_shared.vm_acceptance._ensure_acceptance_graphical_session",
                return_value=None,
            ), mock.patch("kyth_shared.vm_acceptance.power"), mock.patch(
                "kyth_shared.vm_acceptance.emit"
            ):
                with self.assertRaises(SystemExit):
                    vm_acceptance.run_hub_acceptance()

    def test_deep_link_failure_fails(self):
        self._run_with_binary(self._enter(events=[], launch_check=False))

    def test_first_launch_without_an_event_fails(self):
        self._run_with_binary(self._enter(events=[None]))

    def test_second_launch_with_the_wrong_page_fails(self):
        events = [
            {"page": "Welcome", "source": "initial"},
            {"page": "Welcome", "source": "single-instance"},
        ]
        self._run_with_binary(self._enter(events=events))

    def test_dashboard_not_degraded_fails(self):
        events = [
            {"page": "Welcome", "source": "initial"},
            {"page": "Updates", "source": "single-instance"},
            {"state": "ok", "label": "All good"},
        ]
        self._run_with_binary(self._enter(events=events))

    def test_updates_probe_with_an_unusable_state_fails(self):
        events = [
            {"page": "Welcome", "source": "initial"},
            {"page": "Updates", "source": "single-instance"},
            {"state": "degraded", "label": "Status unavailable"},
            {"state": "bogus"},
            {"state": "expected"},
        ]
        self._run_with_binary(self._enter(events=events))

    def test_privilege_probe_without_the_expected_state_fails(self):
        events = [
            {"page": "Welcome", "source": "initial"},
            {"page": "Updates", "source": "single-instance"},
            {"state": "degraded", "label": "Status unavailable"},
            {"state": "ok"},
            {"state": "unexpected"},
        ]
        self._run_with_binary(self._enter(events=events))


class InstalledLifecycleVariantTests(unittest.TestCase):
    def _enter_fresh(self, *, digest="sha256:aaa"):
        stack = contextlib.ExitStack()
        state_dir_holder = {}
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.read_update_ref", return_value=""))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.wait_for_desktop", return_value=True))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._selinux_enforcing"))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance._first_boot_check"))
        stack.enter_context(mock.patch("kyth_shared.vm_acceptance.run_smoke_check"))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.run_hub_acceptance"))
        stack.enter_context(mock.patch(
            "kyth_shared.vm_acceptance.booted_digest", return_value=digest))
        power = stack.enter_context(mock.patch("kyth_shared.vm_acceptance.power"))
        stack.enter_context(mock.patch("kyth_shared.vm_acceptance.emit"))
        return stack, power, state_dir_holder

    def test_fresh_state_runs_the_variant_truth_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = pathlib.Path(tmp) / "state-dir"
            stack, power, _holder = self._enter_fresh()
            secure = stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.secure_boot_mode", return_value=True))
            windows = stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.windows_mode", return_value=True))
            network = stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.network_check_enabled",
                return_value=True))
            secure_check = stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance._secure_boot_check"))
            windows_check = stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance._windows_ntfs_check"))
            network_check = stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance._network_check"))
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.STATE_DIR", state_dir))
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.STATE_FILE", state_dir / "state"))
            with stack:
                vm_acceptance.run_installed_lifecycle()
            secure_check.assert_called_once_with()
            windows_check.assert_called_once_with()
            network_check.assert_called_once_with()
            power.assert_called_once_with("poweroff")

    def test_fresh_state_fails_without_a_booted_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = pathlib.Path(tmp) / "state-dir"
            stack, _power, _holder = self._enter_fresh(digest="")
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.network_check_enabled",
                return_value=False))
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.STATE_DIR", state_dir))
            stack.enter_context(mock.patch(
                "kyth_shared.vm_acceptance.STATE_FILE", state_dir / "state"))
            with stack:
                with self.assertRaises(SystemExit):
                    vm_acceptance.run_installed_lifecycle()


class SmallBranchTests(unittest.TestCase):
    def test_network_check_enabled_reads_fw_cfg(self):
        with tempfile.TemporaryDirectory() as tmp:
            flag = pathlib.Path(tmp) / "network-check"
            flag.write_bytes(b"1")
            with mock.patch(
                "kyth_shared.vm_acceptance.NETWORK_CHECK_FILE", flag
            ):
                self.assertTrue(vm_acceptance.network_check_enabled())
            flag.write_bytes(b"0")
            with mock.patch(
                "kyth_shared.vm_acceptance.NETWORK_CHECK_FILE", flag
            ):
                self.assertFalse(vm_acceptance.network_check_enabled())

    def test_first_boot_check_fails_when_systemctl_failed_listing_breaks(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text", return_value=_completed(1, "")
        ), mock.patch("kyth_shared.vm_acceptance.power"):
            with self.assertRaises(SystemExit):
                vm_acceptance._first_boot_check()
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text", return_value=None
        ), mock.patch("kyth_shared.vm_acceptance.power"):
            with self.assertRaises(SystemExit):
                vm_acceptance._first_boot_check()

    def test_selinux_check_fails_when_getenforce_is_unavailable(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text", return_value=None
        ), mock.patch("kyth_shared.vm_acceptance.power"):
            with self.assertRaises(SystemExit):
                vm_acceptance._selinux_enforcing()

    def test_network_check_fails_when_the_registry_host_does_not_resolve(self):
        with mock.patch(
            "kyth_shared.vm_acceptance._installer_target_ref",
            return_value="ghcr.io/example/kyth:testing",
        ), mock.patch(
            "kyth_shared.vm_acceptance.run_text", return_value=_completed(1, "")
        ), mock.patch("kyth_shared.vm_acceptance.power"):
            with self.assertRaises(SystemExit):
                vm_acceptance._network_check()

    def test_network_check_fails_on_a_garbage_http_code(self):
        with mock.patch(
            "kyth_shared.vm_acceptance._installer_target_ref",
            return_value="ghcr.io/example/kyth:testing",
        ), mock.patch(
            "kyth_shared.vm_acceptance.run_text",
            side_effect=[
                _completed(0, "140.82.121.34 ghcr.io\n"),
                _completed(0, "garbage"),
            ],
        ), mock.patch("kyth_shared.vm_acceptance.power"):
            with self.assertRaises(SystemExit):
                vm_acceptance._network_check()

    def test_secure_boot_check_fails_when_mokutil_breaks(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text", return_value=None
        ), mock.patch("kyth_shared.vm_acceptance.power"):
            with self.assertRaises(SystemExit):
                vm_acceptance._secure_boot_check()
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text",
            return_value=_completed(1, ""),
        ), mock.patch("kyth_shared.vm_acceptance.power"):
            with self.assertRaises(SystemExit):
                vm_acceptance._secure_boot_check()

    def test_secure_boot_check_fails_on_undeterminable_output(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text",
            return_value=_completed(0, "mokutil: something unexpected\n"),
        ), mock.patch("kyth_shared.vm_acceptance.power"):
            with self.assertRaises(SystemExit):
                vm_acceptance._secure_boot_check()

    def test_ntfs_uuids_handles_failures_and_a_device_argument(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text", return_value=None
        ):
            self.assertEqual(vm_acceptance._ntfs_uuids(), [])
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text", return_value=_completed(1, "")
        ):
            self.assertEqual(vm_acceptance._ntfs_uuids(), [])
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text",
            return_value=_completed(0, "/dev/vda2 ntfs 5A8C4E2F12345678\n"),
        ) as run_text:
            self.assertEqual(
                vm_acceptance._ntfs_uuids("/dev/vda"),
                [("/dev/vda2", "5A8C4E2F12345678")],
            )
        run_text.assert_called_once_with(
            ["lsblk", "-npro", "NAME,FSTYPE,UUID", "/dev/vda"], timeout=30
        )

    def test_windows_ntfs_check_skips_uuid_less_volumes(self):
        with mock.patch(
            "kyth_shared.vm_acceptance._ntfs_uuids",
            return_value=[("/dev/vda1", ""), ("/dev/vda2", "UUID2")],
        ), mock.patch("kyth_shared.vm_acceptance.emit") as emit:
            vm_acceptance._windows_ntfs_check()
        emit.assert_called_once_with(
            "WINDOWS_NTFS_OK", "device=/dev/vda2 uuid=UUID2"
        )

    def test_report_failures_tolerates_malformed_check_entries(self):
        report = _complete_report()
        report["checks"].append("junk-entry")
        report["checks"].append({"name": 42, "status": "fail"})
        self.assertEqual(
            vm_acceptance._report_failures(report),
            ["installer check 42 failed"],
        )
        report = _complete_report()
        report["checks"].append({"status": "fail"})
        self.assertEqual(
            vm_acceptance._report_failures(report),
            ["installer check unknown failed"],
        )

    def test_daemon_error_message_falls_back_to_the_raw_body(self):
        self.assertEqual(
            vm_acceptance._daemon_error_message('{"message": 42}'),
            '{"message": 42}',
        )
        self.assertEqual(
            vm_acceptance._daemon_error_message('{"other": true}'),
            '{"other": true}',
        )
        self.assertEqual(vm_acceptance._daemon_error_message("[1, 2]"), "[1, 2]")
        self.assertEqual(
            vm_acceptance._daemon_error_message("x" * 600), "x" * 512
        )

    def test_installer_target_ref_defaults_on_an_empty_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = pathlib.Path(tmp) / "kyth-installer.env"
            env_file.write_text("KYTH_TARGET_IMAGE=\n")
            with mock.patch(
                "kyth_shared.vm_acceptance.INSTALLER_ENV_FILE", env_file
            ):
                self.assertEqual(
                    vm_acceptance._installer_target_ref(),
                    "ghcr.io/mrtrickdotorg/kyth:testing",
                )
            env_file.write_text("KYTH_TARGET_IMAGE=''\n")
            with mock.patch(
                "kyth_shared.vm_acceptance.INSTALLER_ENV_FILE", env_file
            ):
                self.assertEqual(
                    vm_acceptance._installer_target_ref(),
                    "ghcr.io/mrtrickdotorg/kyth:testing",
                )

    def test_booted_digest_returns_empty_for_a_list_payload(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text",
            return_value=_completed(0, "[1, 2]"),
        ):
            self.assertEqual(vm_acceptance.booted_digest(), "")

    def test_deployment_count_returns_zero_for_a_non_list_deployments(self):
        with mock.patch(
            "kyth_shared.vm_acceptance.run_text",
            return_value=_completed(0, '{"deployments": 5}'),
        ):
            self.assertEqual(vm_acceptance.deployment_count(), 0)

    def test_acceptance_disk_selection_skips_malformed_records(self):
        inventory = [
            "junk",
            42,
            {"name": "/dev/vda"},
            {"name": "/dev/vdb", "current": False},
        ]
        self.assertEqual(
            vm_acceptance._acceptance_disk_from_inventory(
                inventory, pathlib.Path("/dev/vda")
            ),
            "/dev/vda",
        )

    def test_windows_target_skips_malformed_candidates(self):
        gib = 1024 * 1024 * 1024
        partitions = [
            "junk",
            {"name": "/dev/vda9", "size_bytes": 127 * gib,
             "ntfs_resize_candidate": False},
            {"name": 42, "size_bytes": 127 * gib,
             "ntfs_resize_candidate": True},
            {"name": "/dev/vda8", "size_bytes": "big",
             "ntfs_resize_candidate": True},
            {"name": "/dev/vda7", "size_bytes": 64 * gib,
             "ntfs_resize_candidate": True},
            {"name": "/dev/vda2", "size_bytes": 127 * gib,
             "ntfs_resize_candidate": True},
        ]
        self.assertEqual(
            vm_acceptance._windows_resize_target_from_partitions(partitions),
            ("/dev/vda2", 63),
        )

    def test_installer_source_ref_returns_empty_when_fail_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "kyth_shared.vm_acceptance.INSTALLER_ENV_FILE",
                pathlib.Path(tmp) / "absent",
            ), mock.patch("kyth_shared.vm_acceptance.fail") as fail:
                self.assertEqual(vm_acceptance._installer_source_ref(), "")
            fail.assert_called_once_with(
                "pinned installer source is missing from live image"
            )

    def test_hub_pages_returns_empty_when_fail_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "kyth_shared.vm_acceptance.HUB_ROUTE_MANIFEST",
                pathlib.Path(tmp) / "absent.json",
            ), mock.patch("kyth_shared.vm_acceptance.fail") as fail:
                self.assertEqual(vm_acceptance._hub_pages(), ())
            self.assertIn(
                "Hub route manifest could not be read",
                fail.call_args.args[0],
            )

    def test_initial_digest_returns_empty_when_fail_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "kyth_shared.vm_acceptance.STATE_DIR", pathlib.Path(tmp)
            ), mock.patch("kyth_shared.vm_acceptance.fail") as fail:
                self.assertEqual(vm_acceptance._initial_digest(), "")
            fail.assert_called_once_with(
                "initial deployment digest is missing"
            )

    def test_module_entrypoint_reports_the_disabled_state(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "build_files" / "kyth_shared")
        result = subprocess.run(
            [sys.executable, "-m", "kyth_shared.vm_acceptance", "enabled"],
            capture_output=True, text=True, env=env, timeout=60,
        )
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
