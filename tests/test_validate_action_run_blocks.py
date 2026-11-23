from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "build_files/scripts/validate-action-run-blocks.py"
ACTIONS = ROOT / ".github/actions"
SPEC = importlib.util.spec_from_file_location("validate_action_run_blocks", SCRIPT)
assert SPEC and SPEC.loader
run_blocks = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_blocks
SPEC.loader.exec_module(run_blocks)

HAS_SHELLCHECK = shutil.which("shellcheck") is not None

FIXTURE = """\
name: Fixture
runs:
  using: composite
  steps:
    - name: Block body
      shell: bash
      run: |
        set -euo pipefail
        echo "${HOME}"

    - name: Inline body
      shell: bash
      run: rm -f "${HOME}/.docker/config.json"

    - name: Quoted inline
      shell: bash
      run: "echo inline"

    - name: Folded body
      shell: bash
      run: >
        set -euo pipefail
        echo folded

    - name: Node step
      shell: node
      run: console.log('skipped')

    - name: Block payload
      uses: actions/example@v1
      with:
        body: |
          run: this is payload text, not a step
"""

FLOW = """\
name: Flow
runs:
  using: composite
  steps:
    - {name: Flow body, shell: bash, run: "echo flow"}
    - name: Anchored body
      shell: bash
      run: &body |
        set -euo pipefail
        echo "${HOME}"
    - name: Aliased body
      shell: bash
      run: *body
"""

BROKEN = """\
name: Broken
runs:
  using: composite
  steps:
    - name: Unclosed quote
      shell: bash
      run: |
        set -euo pipefail
        rm -f "${HOME}/config.json
"""


def write_action(root: Path, text: str, action: str = "fixture") -> Path:
    path = root / action / "action.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class ParseActionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def test_reads_block_inline_quoted_and_folded_bodies(self):
        steps = run_blocks.parse_action(write_action(self.root, FIXTURE))
        self.assertEqual(
            [step.name for step in steps],
            ["Block body", "Inline body", "Quoted inline", "Folded body", "Node step"],
        )
        self.assertEqual(steps[0].run, 'set -euo pipefail\necho "${HOME}"\n')
        # A plain scalar keeps its real quotes: stripping both ends truncated
        # this very body when the parser was first written.
        self.assertEqual(steps[1].run, 'rm -f "${HOME}/.docker/config.json"\n')
        self.assertEqual(steps[2].run, "echo inline\n")
        # `>` folds lines into one shell line, which is what actually runs.
        self.assertEqual(steps[3].run, "set -euo pipefail echo folded\n")
        self.assertEqual(steps[4].shell, "node")

    def test_a_block_payload_is_not_mistaken_for_a_step(self):
        steps = run_blocks.parse_action(write_action(self.root, FIXTURE))
        self.assertNotIn("this is payload text, not a step", " ".join(step.run for step in steps))

    def test_find_step_names_the_steps_it_does_have(self):
        path = write_action(self.root, FIXTURE)
        self.assertEqual(run_blocks.find_step(path, "Folded body").run, "set -euo pipefail echo folded\n")
        with self.assertRaises(KeyError):
            run_blocks.find_step(path, "Absent step")

    def test_flow_mappings_and_anchors_are_read_like_any_other_shape(self):
        steps = run_blocks.parse_action(write_action(self.root, FLOW))
        self.assertEqual([step.name for step in steps], ["Flow body", "Anchored body", "Aliased body"])
        self.assertEqual(steps[0].run, "echo flow\n")
        self.assertEqual(steps[2].run, steps[1].run)

    def test_an_action_without_steps_is_an_error_not_a_skip(self):
        path = write_action(self.root, "name: Empty\nruns:\n  using: composite\n  steps: []\n")
        with self.assertRaises(ValueError):
            run_blocks.parse_action(path)

    def test_invalid_yaml_is_an_error_not_a_skip(self):
        path = write_action(
            self.root,
            'name: Broken\nruns:\n  using: composite\n  steps: [{name: x, shell: bash, run: "echo hi"}\n',
        )
        with self.assertRaises(ValueError):
            run_blocks.parse_action(path)


class LintTests(unittest.TestCase):
    def run_script(self, actions_dir: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--actions-dir", str(actions_dir)],
            capture_output=True,
            text=True,
            check=False,
        )

    @unittest.skipUnless(HAS_SHELLCHECK, "shellcheck comes from install-validation-tools.sh")
    def test_a_broken_run_block_fails_the_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_action(Path(tmp), BROKEN, "broken")
            proc = self.run_script(Path(tmp))
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("bash -n failed", proc.stderr)

    @unittest.skipUnless(HAS_SHELLCHECK, "shellcheck comes from install-validation-tools.sh")
    def test_an_empty_actions_dir_fails_rather_than_passing_vacuously(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_script(Path(tmp))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("No composite actions found", proc.stderr)

    @unittest.skipUnless(HAS_SHELLCHECK, "shellcheck comes from install-validation-tools.sh")
    def test_every_run_block_this_repository_ships_is_clean(self):
        proc = self.run_script(ACTIONS)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        actions = len(list(ACTIONS.glob("*/action.yml")))
        self.assertIn(f"in {actions} composite actions", proc.stdout)


if __name__ == "__main__":
    unittest.main()
