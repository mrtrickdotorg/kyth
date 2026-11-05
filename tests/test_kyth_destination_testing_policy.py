from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "build_files/scripts/destination_testing_policy.py"
sys.path.insert(0, str(ROOT / "build_files/scripts"))

from destination_testing_policy import (  # noqa: E402
    DESTINATION_IMAGE,
    destination_build_plan,
    validate_destination_dispatch,
    validate_destination_metadata,
)


SOURCE_SHA = "1" * 40
WORKFLOW_SHA = SOURCE_SHA
DIGEST = "sha256:" + "a" * 64
BASE_DIGEST = "sha256:" + "b" * 64


class DestinationBuildPlanTests(unittest.TestCase):
    def plan(self, **overrides):
        values = {
            "repository": "mrtrickdotorg/kyth", "ref": "refs/heads/testing",
            "source_sha": SOURCE_SHA, "build_workflow_sha": SOURCE_SHA,
            "source_tag": "testing", "kernel_flavor": "fedora",
            "run_id": "12345", "run_attempt": "2",
        }
        values.update(overrides)
        return destination_build_plan(**values)

    def test_returns_fixed_candidate_identity_and_source_provenance(self):
        plan = self.plan()
        self.assertEqual(plan["image"], DESTINATION_IMAGE)
        self.assertEqual(plan["image_owner"], "mrtrickdotorg")
        self.assertEqual(plan["source_repository"], "mrtrickdotorg/kyth")
        self.assertEqual(plan["source_ref"], "refs/heads/testing")
        self.assertEqual(plan["source_sha"], SOURCE_SHA)
        self.assertEqual(
            plan["source_url"],
            f"https://github.com/mrtrickdotorg/kyth/tree/{SOURCE_SHA}",
        )
        self.assertEqual(
            plan["documentation_url"],
            f"https://github.com/mrtrickdotorg/kyth/blob/{SOURCE_SHA}/README.md",
        )
        self.assertEqual(
            plan["candidate_tag"], "destination-candidate-testing-12345-2-fedora"
        )
        self.assertEqual(
            plan["candidate_ref"],
            f"{DESTINATION_IMAGE}:destination-candidate-testing-12345-2-fedora",
        )
        self.assertEqual(
            plan["artifact_name"], "destination-testing-testing-12345-2-fedora"
        )
        self.assertEqual(plan["floating_tag"], "testing")
        self.assertEqual(plan, self.plan())

    def test_rejects_untrusted_source_workflow_channel_and_run_values(self):
        invalid = (
            {"repository": "kyth-os/kyth"}, {"repository": "other/repo"},
            {"ref": "refs/heads/main"}, {"source_sha": "bad"},
            {"source_sha": "3" * 40}, {"build_workflow_sha": "bad"},
            {"build_workflow_sha": "2" * 40}, {"source_tag": "latest"},
            {"source_tag": "testing-cachy", "kernel_flavor": "fedora"},
            {"kernel_flavor": "cachy"}, {"run_id": "0"},
            {"run_id": "01"}, {"run_id": "1.0"},
            {"run_attempt": "0"}, {"run_attempt": "-1"},
            {"run_attempt": "02"},
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.plan(**values)

    def test_rejects_run_values_that_exceed_registry_tag_length(self):
        for field in ("run_id", "run_attempt"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.plan(**{field: "9" * 200})

    def test_channel_plans_use_unique_refs_separate_from_floating_tags(self):
        plans = [
            self.plan(source_tag="testing", kernel_flavor="fedora"),
            self.plan(source_tag="testing-cachy", kernel_flavor="cachy"),
        ]
        for plan in plans:
            for ref_field in ("base_ref", "raw_ref", "candidate_ref"):
                self.assertIn(plan["source_tag"], plan[ref_field])
                self.assertNotEqual(
                    plan[ref_field].rsplit(":", 1)[-1], plan["floating_tag"]
                )
        for field in ("base_ref", "raw_ref", "candidate_ref"):
            self.assertEqual(len({plan[field] for plan in plans}), 2)
        self.assertEqual(plans[0]["floating_tag"], "testing")
        self.assertEqual(plans[1]["floating_tag"], "testing-cachy")

    def test_plan_build_cli_emits_both_fixed_plans_and_rejects_invalid_identity(self):
        for channel, flavor in (("testing", "fedora"), ("testing-cachy", "cachy")):
            payload = {
                "repository": "mrtrickdotorg/kyth", "ref": "refs/heads/testing",
                "source_sha": SOURCE_SHA, "build_workflow_sha": SOURCE_SHA,
                "source_tag": channel, "kernel_flavor": flavor,
                "run_id": "12345", "run_attempt": "2",
            }
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as handle:
                json.dump(payload, handle)
                handle.flush()
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "plan-build", handle.name],
                    text=True, capture_output=True, check=False,
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["source_tag"], channel)
            for field, invalid in (("repository", "other/repo"),
                                   ("ref", "refs/heads/main"),
                                   ("source_tag", "latest"),
                                   ("run_id", "0")):
                bad = dict(payload, **{field: invalid})
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as handle:
                    json.dump(bad, handle)
                    handle.flush()
                    rejected = subprocess.run(
                        [sys.executable, str(SCRIPT), "plan-build", handle.name],
                        text=True, capture_output=True, check=False,
                    )
                self.assertEqual(rejected.returncode, 2)
                self.assertEqual(rejected.stdout, "")


class DestinationDispatchPolicyTests(unittest.TestCase):
    def valid_dispatch(self) -> dict[str, object]:
        return {
            "event_name": "workflow_dispatch",
            "repository": "mrtrickdotorg/kyth",
            "ref": "refs/heads/testing",
            "skip_validation": "false",
            "source_sha": SOURCE_SHA,
            "testing_tip_sha": SOURCE_SHA,
            "validation_sha": SOURCE_SHA,
            "validation_branch": "testing",
            "validation_workflow_name": "Validation",
            "validation_workflow_path": ".github/workflows/validation.yml",
            "validation_event": "push",
            "validation_status": "completed",
            "validation_conclusion": "success",
        }

    def test_valid_testing_dispatch_resolves_only_fixed_destination(self):
        identity = validate_destination_dispatch(**self.valid_dispatch())

        self.assertEqual(identity["image"], DESTINATION_IMAGE)
        self.assertEqual(identity["source_sha"], SOURCE_SHA)
        self.assertEqual(identity["branch"], "testing")

    def test_dispatch_rejects_invalid_event_repository_ref_or_skip(self):
        invalid_fields = (
            ("event_name", "push"),
            ("event_name", "schedule"),
            ("repository", "kyth-os/kyth"),
            ("ref", "refs/heads/main"),
            ("ref", "refs/tags/testing"),
            ("skip_validation", "true"),
            ("skip_validation", True),
            ("skip_validation", 0),
            ("skip_validation", None),
        )
        for field, value in invalid_fields:
            with self.subTest(field=field, value=value):
                args = self.valid_dispatch()
                args[field] = value
                with self.assertRaises(ValueError):
                    validate_destination_dispatch(**args)

    def test_boolean_false_skip_flag_is_allowed(self):
        args = self.valid_dispatch()
        args["skip_validation"] = False
        identity = validate_destination_dispatch(**args)
        self.assertEqual(identity["image"], DESTINATION_IMAGE)

    def test_dispatch_rejects_sha_or_validation_mismatches(self):
        invalid_fields = (
            ("source_sha", "not-a-sha"),
            ("testing_tip_sha", "3" * 40),
            ("validation_sha", "3" * 40),
            ("validation_sha", "not-a-sha"),
            ("validation_branch", "main"),
            ("validation_workflow_name", "CodeQL"),
            ("validation_workflow_path", ".github/workflows/other.yml"),
            ("validation_event", "workflow_dispatch"),
            ("validation_status", "in_progress"),
            ("validation_conclusion", "failure"),
            ("validation_conclusion", "cancelled"),
        )
        for field, value in invalid_fields:
            with self.subTest(field=field, value=value):
                args = self.valid_dispatch()
                args[field] = value
                with self.assertRaises(ValueError):
                    validate_destination_dispatch(**args)


class DestinationMetadataPolicyTests(unittest.TestCase):
    def valid_metadata(self) -> dict[str, object]:
        return {
            "mode": "destination_testing",
            "image": DESTINATION_IMAGE,
            "source_tag": "testing",
            "source_sha": SOURCE_SHA,
            "build_workflow_sha": WORKFLOW_SHA,
            "kernel_flavor": "fedora",
            "run_id": "12345",
            "run_attempt": "2",
            "candidate_tag": "destination-candidate-testing-12345-2-fedora",
            "digest": DIGEST,
            "base_image": (
                f"{DESTINATION_IMAGE}:"
                "destination-base-testing-12345-2-fedora"
            ),
            "base_digest": BASE_DIGEST,
            "artifact_name": "destination-testing-testing-12345-2-fedora",
        }

    def expected_identity(self) -> dict[str, str]:
        return {
            "source_sha": SOURCE_SHA,
            "build_workflow_sha": WORKFLOW_SHA,
            "source_tag": "testing",
            "kernel_flavor": "fedora",
            "run_id": "12345",
            "run_attempt": "2",
        }

    def test_valid_metadata_returns_exact_candidate_and_promotion_identity(self):
        identity = validate_destination_metadata(
            self.valid_metadata(), self.expected_identity()
        )

        self.assertEqual(identity["image"], DESTINATION_IMAGE)
        self.assertEqual(
            identity["candidate_tag"], "destination-candidate-testing-12345-2-fedora"
        )
        self.assertEqual(
            identity["candidate_ref"],
            f"{DESTINATION_IMAGE}:destination-candidate-testing-12345-2-fedora",
        )
        self.assertEqual(identity["digest_ref"], f"{DESTINATION_IMAGE}@{DIGEST}")
        self.assertEqual(identity["floating_tag"], "testing")

    def test_metadata_rejects_workflow_sha_different_from_source_sha(self):
        metadata = self.valid_metadata()
        expected = self.expected_identity()
        metadata["build_workflow_sha"] = "3" * 40
        expected["build_workflow_sha"] = "3" * 40

        with self.assertRaises(ValueError):
            validate_destination_metadata(metadata, expected)

    def test_metadata_rejects_run_values_that_exceed_registry_tag_length(self):
        for field in ("run_id", "run_attempt"):
            metadata = self.valid_metadata()
            expected = self.expected_identity()
            metadata[field] = "9" * 200
            expected[field] = "9" * 200
            run_id = str(metadata["run_id"])
            run_attempt = str(metadata["run_attempt"])
            metadata.update(
                candidate_tag=(
                    f"destination-candidate-testing-{run_id}-{run_attempt}-fedora"
                ),
                base_image=(
                    f"{DESTINATION_IMAGE}:destination-base-testing-"
                    f"{run_id}-{run_attempt}-fedora"
                ),
                artifact_name=(
                    f"destination-testing-testing-{run_id}-{run_attempt}-fedora"
                ),
            )
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_destination_metadata(metadata, expected)

    def test_metadata_rejects_destination_or_identity_mismatch(self):
        invalid_fields = (
            ("mode", "legacy"),
            ("mode", None),
            ("image", "ghcr.io/kyth-os/kyth"),
            ("image", None),
            ("source_tag", "latest"),
            ("source_tag", None),
            ("source_sha", "3" * 40),
            ("source_sha", None),
            ("build_workflow_sha", "3" * 40),
            ("build_workflow_sha", None),
            ("kernel_flavor", "cachy"),
            ("kernel_flavor", None),
            ("run_id", "12346"),
            ("run_id", 12345),
            ("run_attempt", "3"),
            ("run_attempt", 2),
            ("candidate_tag", "testing"),
            ("candidate_tag", None),
            ("digest", "sha256:ABC"),
            ("digest", None),
            ("base_image", "ghcr.io/kyth-os/kyth:base-testing"),
            ("base_image", None),
            ("base_digest", "latest"),
            ("base_digest", None),
            ("artifact_name", "supply-chain-input-testing"),
            ("artifact_name", None),
        )
        for field, value in invalid_fields:
            with self.subTest(field=field, value=value):
                metadata = self.valid_metadata()
                metadata[field] = value
                with self.assertRaises(ValueError):
                    validate_destination_metadata(metadata, self.expected_identity())

    def test_metadata_rejects_malformed_run_identity(self):
        metadata = self.valid_metadata()
        metadata.update(
            run_id="01",
            candidate_tag="destination-candidate-01-2-fedora",
            artifact_name="destination-testing-testing-01-2-fedora",
        )
        expected = self.expected_identity()
        expected["run_id"] = "01"
        with self.assertRaises(ValueError):
            validate_destination_metadata(metadata, expected)

    def test_metadata_rejects_unexpected_destination_identity_fields(self):
        metadata = self.valid_metadata()
        metadata["arbitrary_effective_tag"] = "latest"
        with self.assertRaises(ValueError):
            validate_destination_metadata(metadata, self.expected_identity())

    def test_metadata_rejects_missing_destination_identity_fields(self):
        metadata = self.valid_metadata()
        del metadata["base_digest"]
        with self.assertRaises(ValueError):
            validate_destination_metadata(metadata, self.expected_identity())

    def test_metadata_rejects_non_mapping_inputs(self):
        with self.assertRaises(ValueError):
            validate_destination_metadata([], self.expected_identity())
        with self.assertRaises(ValueError):
            validate_destination_metadata(self.valid_metadata(), None)

    def test_metadata_rejects_tag_and_kernel_flavor_mismatch(self):
        metadata = self.valid_metadata()
        metadata.update(
            source_tag="testing-cachy",
            kernel_flavor="cachy",
            candidate_tag="destination-candidate-testing-cachy-12345-2-cachy",
            base_image=(
                f"{DESTINATION_IMAGE}:"
                "destination-base-testing-cachy-12345-2-cachy"
            ),
            artifact_name="destination-testing-testing-cachy-12345-2-cachy",
        )
        identity = validate_destination_metadata(
            metadata,
            {
                **self.expected_identity(),
                "source_tag": "testing-cachy",
                "kernel_flavor": "cachy",
            },
        )
        self.assertEqual(identity["floating_tag"], "testing-cachy")
        self.assertEqual(identity["kernel_flavor"], "cachy")
        self.assertEqual(
            identity["candidate_tag"],
            "destination-candidate-testing-cachy-12345-2-cachy",
        )
        self.assertEqual(
            identity["candidate_ref"],
            f"{DESTINATION_IMAGE}:destination-candidate-testing-cachy-12345-2-cachy",
        )
        self.assertEqual(identity["digest_ref"], f"{DESTINATION_IMAGE}@{DIGEST}")
        self.assertEqual(identity["base_digest"], BASE_DIGEST)


class DestinationPolicyCliTests(unittest.TestCase):
    def run_cli(
        self,
        command: str,
        payload: object,
        expected: object | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            payload_path = Path(temp_dir) / "metadata.json"
            payload_path.write_text(json.dumps(payload), encoding="utf-8")
            argv = [sys.executable, str(SCRIPT), command]
            if command == "validate-metadata":
                expected_path = Path(temp_dir) / "expected.json"
                expected_path.write_text(json.dumps(expected), encoding="utf-8")
                argv.extend(
                    ["--metadata", str(payload_path), "--expected", str(expected_path)]
                )
            else:
                argv.append(str(payload_path))
            return subprocess.run(
                argv,
                capture_output=True,
                check=False,
                text=True,
            )

    def test_cli_emits_validated_dispatch_identity_as_json(self):
        payload = DestinationDispatchPolicyTests().valid_dispatch()

        result = self.run_cli("validate-dispatch", payload)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["image"], DESTINATION_IMAGE)

    def test_cli_rejects_invalid_dispatch_without_identity_output(self):
        payload = DestinationDispatchPolicyTests().valid_dispatch()
        payload["skip_validation"] = "true"

        result = self.run_cli("validate-dispatch", payload)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_cli_emits_validated_metadata_identity_as_json(self):
        fixture = DestinationMetadataPolicyTests()

        result = self.run_cli(
            "validate-metadata",
            fixture.valid_metadata(),
            fixture.expected_identity(),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        identity = json.loads(result.stdout)
        self.assertEqual(identity["image"], DESTINATION_IMAGE)
        self.assertEqual(identity["floating_tag"], "testing")

    def test_cli_rejects_same_file_as_metadata_and_expected(self):
        fixture = DestinationMetadataPolicyTests()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "metadata.json"
            path.write_text(json.dumps(fixture.valid_metadata()), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "validate-metadata",
                    "--metadata",
                    str(path),
                    "--expected",
                    str(path),
                ],
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("separate files", result.stderr)

    def test_cli_rejects_inconsistent_metadata_without_identity_output(self):
        fixture = DestinationMetadataPolicyTests()
        metadata = fixture.valid_metadata()
        metadata["digest"] = "sha256:ABC"

        result = self.run_cli(
            "validate-metadata", metadata, fixture.expected_identity()
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
