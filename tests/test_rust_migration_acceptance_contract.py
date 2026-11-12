import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = ROOT / "build_files/scripts/run-rust-migration-acceptance.sh"
GATES = ROOT / "docs/rust-migration-acceptance-gates.md"
JUSTFILE = ROOT / "Justfile"
ARTIFACT_WORKFLOW = ROOT / ".github/workflows/rust-migration-acceptance.yml"


class RustMigrationAcceptanceContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = ACCEPTANCE.read_text(encoding="utf-8")
        cls.gates = GATES.read_text(encoding="utf-8")
        cls.justfile = JUSTFILE.read_text(encoding="utf-8")
        cls.artifact_workflow = ARTIFACT_WORKFLOW.read_text(encoding="utf-8")

    def test_wrapper_requires_exact_iso_and_image_and_preserves_artifacts(self):
        for token in (
            "--iso",
            "--image-ref",
            "--update-ref",
            "--artifacts",
            "--timeout-minutes",
            "vm-acceptance.sh",
            "--update-ref",
            "run-metadata.txt",
            "evidence-status.txt",
        ):
            self.assertIn(token, self.script)
        self.assertIn("intentionally leaves its artifact directory", self.script)
        self.assertNotIn("rm -rf", self.script)

    def test_gate_document_separates_source_and_promoted_image_evidence(self):
        self.assertIn("Static owner gate", self.gates)
        self.assertIn("Exact-image gate", self.gates)
        self.assertIn("Observation window", self.gates)
        self.assertIn("disposable disks/images", self.gates)
        self.assertIn("cleanup-vm-acceptance.sh", self.gates)

    def test_just_exposes_reproducible_acceptance_entrypoint(self):
        self.assertIn("rust-migration-acceptance iso image_ref", self.justfile)
        self.assertIn("run-rust-migration-acceptance.sh", self.justfile)

    def test_kvm_grant_loads_module_before_usability_check(self):
        """Regression (2026-11-12): the Ubuntu 26.04 runner image no
        longer loads the kvm module out of the box, so the old
        udev-rule-only grant step conjured no /dev/kvm and every
        nightly acceptance run died at the usability check from
        2026-11-09 on. Every copy of the grant step (both jobs here,
        plus the ISO workflow's acceptance job) must load the host
        module and set permissions before it checks usability."""
        iso_workflow = (ROOT / ".github/workflows/build-live-iso.yml").read_text(
            encoding="utf-8"
        )
        for name, workflow in (
            ("rust-migration-acceptance", self.artifact_workflow),
            ("build-live-iso", iso_workflow),
        ):
            blocks = workflow.split("- name: Grant runner access to /dev/kvm")[1:]
            self.assertTrue(blocks, f"{name}: no KVM grant step found")
            for block in blocks:
                step = block.split("- name:", 1)[0]
                self.assertIn("for module in kvm_intel kvm_amd", step, name)
                self.assertIn('modprobe "${module}"', step, name)
                self.assertIn("chmod 0666 /dev/kvm", step, name)
                self.assertLess(
                    step.index("modprobe"),
                    step.index("! -r /dev/kvm"),
                    name,
                )

    def test_artifact_workflow_reuses_exact_iso_without_rebuilding(self):
        for token in (
            "artifact_run_id",
            "artifact_name",
            "source_sha",
            "image_ref",
            "actions/download-artifact",
            "run-id:",
            "sha256sum --check --strict",
            "run-rust-migration-acceptance.sh",
            "actions/upload-artifact",
            "IMAGE_REF:",
            "ARTIFACT_RUN_ID:",
            "TIMEOUT_MINUTES:",
            "UPDATE_REF:",
        ):
            self.assertIn(token, self.artifact_workflow)
        self.assertNotIn("podman build", self.artifact_workflow)
        self.assertNotIn("Build ISO with Titanoboa", self.artifact_workflow)

    def test_artifact_workflow_is_callable_and_runs_nightly(self):
        self.assertIn("workflow_call:", self.artifact_workflow)
        self.assertIn("schedule:", self.artifact_workflow)
        self.assertIn("cron:", self.artifact_workflow)
        # Nightly runs the promoted testing image, not a dispatch artifact.
        self.assertIn("ghcr.io/mrtrickdotorg/kyth:testing", self.artifact_workflow)
        self.assertNotIn("ghcr.io/kyth-os/kyth", self.artifact_workflow)
        self.assertIn("iso-testing", self.artifact_workflow)
        # The nightly run must fail on a nonzero acceptance exit: it gates
        # nothing, so silence would hide regressions.
        self.assertNotIn("continue-on-error", self.artifact_workflow)
        self.assertNotIn("|| true", self.artifact_workflow)


if __name__ == "__main__":
    unittest.main()
