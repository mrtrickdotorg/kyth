"""Scoped filtering for systemd host-unit compatibility warnings."""
import pathlib
import tempfile
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER = ROOT / "build_files/scripts/filter-systemd-verify.py"


class SystemdVerifyFilterTests(unittest.TestCase):
    def filter_output(self, output, owned=()):
        return subprocess.run(
            ["python3", str(HELPER), *owned], input=output, text=True,
            capture_output=True, check=False,
        )

    def test_cpuaccounting_host_warning_is_ignored_but_owned_and_other_warnings_fail(self):
        host = "/usr/lib/systemd/system/example.service:12: Support for option CPUAccounting= has been removed and it is ignored"
        owned = "build_files/kyth-example.service:12: Support for option CPUAccounting= has been removed and it is ignored"
        unrelated = "/usr/lib/systemd/system/example.service:13: Unknown key 'Typo' in section [Service], ignoring"
        result = self.filter_output("\n".join((host, owned, unrelated)) + "\n", ["build_files/kyth-example.service"])
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(host, result.stdout)
        self.assertIn(owned, result.stdout)
        self.assertIn(unrelated, result.stdout)

    def test_external_cpuaccounting_warning_alone_passes(self):
        host = "/usr/lib/systemd/system/example.service:12: Support for option CPUAccounting= has been removed and it is ignored\n"
        result = self.filter_output(host, ["build_files/kyth-example.service"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_absolute_project_owned_path_is_not_filtered(self):
        owned = "build_files/kyth-example.service"
        absolute = (ROOT / owned).resolve()
        warning = f"{absolute}:12: Support for option CPUAccounting= has been removed and it is ignored\n"
        result = self.filter_output(warning, [owned])
        self.assertIn(warning.strip(), result.stdout)

    def test_normalized_and_symlink_aliases_are_owned(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            target = pathlib.Path(temp_dir) / "unit.service"
            alias = pathlib.Path(temp_dir) / "alias.service"
            target.touch()
            alias.symlink_to(target)
            owned = target.relative_to(ROOT).as_posix()
            warning = f"{alias}:12: Support for option CPUAccounting= has been removed and it is ignored\n"
            result = self.filter_output(warning, [owned])
        self.assertIn(warning.strip(), result.stdout)

    def test_unknown_absolute_path_cpuaccounting_warning_is_not_filtered(self):
        warning = "/opt/vendor/unit.service:12: Support for option CPUAccounting= has been removed and it is ignored\n"
        result = self.filter_output(warning)
        self.assertIn(warning.strip(), result.stdout)

    def test_owned_path_inside_trusted_host_directory_is_not_filtered(self):
        owned = "/usr/lib/systemd/system/kyth-project-owned.service"
        warning = f"{owned}:12: Support for option CPUAccounting= has been removed and it is ignored\n"
        result = self.filter_output(warning, [owned])
        self.assertIn(warning.strip(), result.stdout)


if __name__ == "__main__":
    unittest.main()
