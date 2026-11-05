import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/build.yml").read_text()

import sys  # noqa: E402

sys.path.insert(0, str(ROOT / "build_files/scripts"))

import destination_testing_policy  # noqa: E402


class DestinationBuildGateContracts(unittest.TestCase):
    def test_boolean_and_string_true_inputs_select_destination_mode(self):
        self.assertIn("destinationValue === true", WORKFLOW)
        self.assertIn("destinationValue === 'true'", WORKFLOW)


    def test_destination_opt_in_is_legacy_off_and_gate_cannot_unlock_plan(self):
        self.assertIn("destination_testing:\n        description:", WORKFLOW)
        self.assertIn("default: false", WORKFLOW)
        self.assertIn(
            "if: github.event_name == 'workflow_dispatch' && "
            "inputs.destination_testing",
            WORKFLOW,
        )
        self.assertIn("core.setOutput('ok', 'false')", WORKFLOW)
        self.assertIn("if: needs.gate.outputs.ok == 'true'", WORKFLOW)

    def test_destination_gate_binds_runs_to_validation_workflow_path(self):
        self.assertEqual(WORKFLOW.count("github.paginate("), 2)
        self.assertIn("github.rest.actions.listRepoWorkflows", WORKFLOW)
        self.assertIn(
            "workflow.path === '.github/workflows/validation.yml'", WORKFLOW
        )
        self.assertIn("workflow_id: validationWorkflow.id", WORKFLOW)

    def test_destination_gate_selects_only_successful_validation_runs(self):
        for condition in (
            "r.name === 'Validation' &&",
            "r.status === 'completed' &&",
            "r.conclusion === 'success'",
        ):
            with self.subTest(condition=condition):
                self.assertIn(condition, WORKFLOW)

    def test_destination_gate_is_read_only_and_explicitly_fails(self):
        gate = WORKFLOW.split("  destination_gate:", 1)[1].split("\n  plan:", 1)[0]
        self.assertIn("actions: read", gate)
        self.assertIn("contents: read", gate)
        self.assertNotIn("packages: write", gate)
        self.assertIn("exit 1", gate)
        forbidden = (
            "docker/login-action",
            "docker/build-push-action",
            "packages: write",
            "secrets.",
            "GITHUB_TOKEN",
            "attest",
            "cosign",
            "tag promotion",
            "gh release",
            "upload-release-asset",
            "ISO dispatch",
            "CVE dispatch",
            "actions: write",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token.lower(), gate.lower())
        self.assertIn("needs.gate.outputs.ok == 'true'", WORKFLOW)
        self.assertIn("core.setOutput('ok', 'false')", WORKFLOW)

    def test_destination_preflight_executes_only_two_fixed_context_plans(self):
        gate = WORKFLOW.split("  destination_gate:", 1)[1].split("\n  plan:", 1)[0]
        for token in (
            "source_tag: 'testing'", "kernel_flavor: 'fedora'",
            "source_tag: 'testing-cachy'", "kernel_flavor: 'cachy'",
            "repository: `${owner}/${repo}`", "ref: context.ref",
            "source_sha: context.sha", "build_workflow_sha: context.sha",
            "process.env.DESTINATION_RUN_ID",
            "process.env.DESTINATION_RUN_ATTEMPT", "'plan-build'",
            "Keep destination publication disabled", "exit 1", "actions: read",
        ):
            self.assertIn(token, gate)
        plan_code = gate.split("const plans =", 1)[1]
        self.assertNotIn("inputs.", plan_code)

    def test_gate_source_repository_matches_the_policy_identity(self):
        # The gate feeds the policy `repository: \`${owner}/${repo}\``, which is
        # the repository this workflow runs in. The policy must authorize that
        # same repository, so the destination image it publishes lives under the
        # source repository's owner.
        self.assertIn("repository: `${owner}/${repo}`", WORKFLOW)
        self.assertEqual(
            f"ghcr.io/{destination_testing_policy.SOURCE_REPOSITORY}",
            destination_testing_policy.DESTINATION_IMAGE,
        )
        identity = destination_testing_policy.validate_destination_dispatch(
            event_name="workflow_dispatch",
            repository=destination_testing_policy.SOURCE_REPOSITORY,
            ref="refs/heads/testing",
            skip_validation="false",
            source_sha="1" * 40,
            testing_tip_sha="1" * 40,
            validation_sha="1" * 40,
            validation_branch="testing",
            validation_workflow_name="Validation",
            validation_workflow_path=".github/workflows/validation.yml",
            validation_event="push",
            validation_status="completed",
            validation_conclusion="success",
        )
        self.assertEqual(
            identity["image"], destination_testing_policy.DESTINATION_IMAGE
        )
        with self.assertRaises(ValueError):
            destination_testing_policy.validate_destination_dispatch(
                event_name="workflow_dispatch",
                repository="kyth-os/kyth",
                ref="refs/heads/testing",
                skip_validation="false",
                source_sha="1" * 40,
                testing_tip_sha="1" * 40,
                validation_sha="1" * 40,
                validation_branch="testing",
                validation_workflow_name="Validation",
                validation_workflow_path=".github/workflows/validation.yml",
                validation_event="push",
                validation_status="completed",
                validation_conclusion="success",
            )


if __name__ == "__main__":
    unittest.main()
