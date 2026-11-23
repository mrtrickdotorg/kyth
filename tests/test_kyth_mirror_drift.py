import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "build_files" / "scripts" / "check-kyth-mirror-drift.py"

SPEC = importlib.util.spec_from_file_location("check_kyth_mirror_drift", SCRIPT)
mirror_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mirror_gate)

SHARED = ("src/kyth_shared", "build_files/kyth_shared")
INSTALLER = ("src/kyth-installer", "build_files/kyth-installer")


class MirrorDriftGateTests(unittest.TestCase):
    def write(self, root, tree, name, content):
        path = Path(root) / tree / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def test_repository_pairs_mirror(self):
        for image_tree, tested_tree in mirror_gate.MIRROR_PAIRS:
            with self.subTest(pair=image_tree):
                self.assertEqual(
                    mirror_gate.compare_pair(ROOT, image_tree, tested_tree), []
                )

    def test_mirror_links_resolve_to_src(self):
        # The supported shape is a tracked symlink, so the image and the tests
        # read one copy of the bytes rather than two trees kept in sync by hand.
        for image_tree, tested_tree in mirror_gate.MIRROR_PAIRS:
            with self.subTest(pair=image_tree):
                tested = ROOT / tested_tree
                if not tested.is_symlink():
                    continue
                self.assertEqual(tested.resolve(), (ROOT / image_tree).resolve())

    def test_materialized_copy_with_changed_bytes_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write(tmp, "src/kyth_shared", "swappiness.py", b"VALUE = 100\n")
            self.write(tmp, "build_files/kyth_shared", "swappiness.py", b"VALUE = 10\n")
            problems = mirror_gate.compare_pair(Path(tmp), *SHARED)
        self.assertEqual(len(problems), 1)
        self.assertIn("swappiness.py differs", problems[0])

    def test_identical_materialized_copy_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write(tmp, "src/kyth-installer", "plan.py", b"# same\n")
            self.write(tmp, "build_files/kyth-installer", "plan.py", b"# same\n")
            self.assertEqual(mirror_gate.compare_pair(Path(tmp), *INSTALLER), [])

    def test_repointed_symlink_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write(tmp, "src/kyth_shared", "zram.py", b"# shipped\n")
            self.write(tmp, "stale/kyth_shared", "zram.py", b"# old\n")
            (Path(tmp) / "build_files").mkdir(parents=True, exist_ok=True)
            os.symlink("../stale/kyth_shared", Path(tmp) / "build_files/kyth_shared")
            problems = mirror_gate.compare_pair(Path(tmp), *SHARED)
        self.assertEqual(len(problems), 1)
        self.assertIn("must resolve to src/kyth_shared", problems[0])
        self.assertIn("'../stale/kyth_shared'", problems[0])

    def test_one_sided_files_name_the_side_they_are_missing_from(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write(tmp, "src/kyth-installer", "plan_commit.py", b"# ship\n")
            self.write(tmp, "build_files/kyth-installer", "only_tested.py", b"# test\n")
            problems = mirror_gate.compare_pair(Path(tmp), *INSTALLER)
        self.assertIn(
            "build_files/kyth-installer/only_tested.py has no copy in "
            "src/kyth-installer/only_tested.py",
            problems,
        )
        self.assertTrue(
            any(
                "src/kyth-installer/plan_commit.py has no copy in "
                "build_files/kyth-installer/plan_commit.py" in problem
                for problem in problems
            ),
            problems,
        )

    def test_build_artifacts_do_not_count_as_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write(tmp, "src/kyth_shared", "zram.py", b"# same\n")
            self.write(tmp, "build_files/kyth_shared", "zram.py", b"# same\n")
            self.write(tmp, "src/kyth-installer", "plan.py", b"# same\n")
            self.write(tmp, "build_files/kyth-installer", "plan.py", b"# same\n")
            self.write(
                tmp, "build_files/kyth_shared", "__pycache__/zram.cpython-313.pyc", b"x",
            )
            self.write(tmp, "src/kyth-installer", "kyth_installer.egg-info/PKG-INFO", b"x")
            self.assertEqual(mirror_gate.compare_pair(Path(tmp), *SHARED), [])
            self.assertEqual(mirror_gate.compare_pair(Path(tmp), *INSTALLER), [])

    def test_missing_tree_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "src/kyth_shared").mkdir(parents=True)
            problems = mirror_gate.compare_pair(Path(tmp), *SHARED)
        self.assertEqual(len(problems), 1)
        self.assertIn("missing tree: build_files/kyth_shared", problems[0])
        self.assertIn("core.symlinks", problems[0])

    def test_main_exits_nonzero_on_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            for image_tree, tested_tree in mirror_gate.MIRROR_PAIRS:
                self.write(tmp, image_tree, "module.py", b"same\n")
                self.write(tmp, tested_tree, "module.py", b"same\n")
            self.assertEqual(mirror_gate.main(["--root", tmp]), 0)

            self.write(tmp, "build_files/kyth-installer", "module.py", b"drifted\n")
            self.assertEqual(mirror_gate.main(["--root", tmp]), 1)

    def test_validation_runs_the_gate(self):
        validation = (ROOT / "build_files/scripts/validate.sh").read_text()
        self.assertIn("check-kyth-mirror-drift.py", validation)


if __name__ == "__main__":
    unittest.main()
