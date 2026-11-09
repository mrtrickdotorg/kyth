from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUPPLY_CHAIN = ROOT / ".github/workflows/supply-chain.yml"
BUILD_LIVE_ISO = ROOT / ".github/workflows/build-live-iso.yml"
UPLOAD_R2 = ROOT / ".github/actions/upload-r2/action.yml"


def _job_section(workflow: str, job: str, next_job: str) -> str:
    return workflow.split(f"\n  {job}:", 1)[1].split(f"\n  {next_job}:", 1)[0]


class SupplyChainAcceptanceDispatchTests(unittest.TestCase):
    def test_iso_dispatch_pays_for_acceptance_only_on_stable(self):
        """Stable (latest) ISO dispatches run acceptance; testing stays cheap.

        The hardcoded "false" meant no supply-chain-dispatched ISO ever ran
        the VM acceptance gate, so stable ISOs published unproven.
        """
        workflow = SUPPLY_CHAIN.read_text(encoding="utf-8")
        dispatch = workflow.split(
            "- name: Dispatch Live ISO after image verification", 1
        )[1]
        self.assertNotIn('"run_acceptance": "false"', dispatch)
        self.assertIn(
            "\"run_acceptance\": "
            "${{ inputs.source_tag == 'latest' && '\"true\"' || '\"false\"' }}",
            dispatch,
        )


class SupplyChainVerifiedEventTests(unittest.TestCase):
    def test_prepare_derives_the_build_event_from_the_api(self):
        """verified_event comes from the build run itself, not dispatch text."""
        workflow = SUPPLY_CHAIN.read_text(encoding="utf-8")
        prepare = _job_section(workflow, "prepare", "publish")
        self.assertIn(
            "verified_event: ${{ steps.verify_event.outputs.verified_event }}",
            prepare,
        )
        verify = prepare.split("- name: Verify originating build event", 1)[1]
        self.assertIn("actions/github-script@", verify)
        self.assertIn("listRepoWorkflows", verify)
        self.assertIn("'.github/workflows/build.yml'", verify)
        self.assertIn("listWorkflowRuns", verify)
        self.assertIn("r.status === 'completed'", verify)
        self.assertIn("core.setOutput('verified_event', verifiedEvent)", verify)

    def test_publish_environment_uses_verified_event_only(self):
        """H12: free-text original_event must not select stable-release-auto.

        original_event is a workflow_dispatch input checked by regex alone;
        trusting it let any dispatcher claim 'schedule' and skip the manual
        approval environment. The API-verified event from prepare selects.
        """
        workflow = SUPPLY_CHAIN.read_text(encoding="utf-8")
        publish = _job_section(workflow, "publish", "migrate_stable")
        environment = next(
            line
            for line in publish.splitlines()
            if line.strip().startswith("environment:")
        )
        self.assertIn(
            "needs.prepare.outputs.verified_event == 'schedule'", environment
        )
        self.assertIn("stable-release-auto", environment)
        self.assertNotIn("inputs.original_event", environment)

    def test_preflight_is_digest_addressed(self):
        """Prepare pins the exact digest it was dispatched with."""
        workflow = SUPPLY_CHAIN.read_text(encoding="utf-8")
        preflight = workflow.split("- name: Preflight source image", 1)[1].split(
            "- name:", 1
        )[0]
        self.assertIn("image-tag: ${{ inputs.source_tag }}", preflight)
        self.assertIn("source-digest: ${{ inputs.source_digest }}", preflight)


class IsoPublishAcceptanceGateTests(unittest.TestCase):
    def test_skipped_acceptance_publishes_for_testing_only(self):
        """Stable requires this run's acceptance success; skipped is not enough.

        The ISO is built from the pinned digest, so an acceptance success is
        digest-exact proof. Tolerating 'skipped' for stable let an emergency
        dispatch publish an unproven stable ISO.
        """
        workflow = BUILD_LIVE_ISO.read_text(encoding="utf-8")
        publish_header = workflow.split("\n  publish:", 1)[1].split(
            "    runs-on:", 1
        )[0]
        self.assertIn("needs.acceptance.result == 'success'", publish_header)
        self.assertRegex(
            publish_header,
            r"needs\.acceptance\.result == 'skipped'\s*&&\s*"
            r"\(inputs\.source_tag \|\| needs\.build\.outputs\.effective_tag\)"
            r" == 'testing'",
        )
        # Failure still never publishes: no negated-failure formulation.
        self.assertNotIn("needs.acceptance.result != 'failure'", publish_header)


class PublishOrderingTests(unittest.TestCase):
    def test_github_releases_publish_before_the_r2_upload(self):
        """The R2 channel pointer moves only once the GitHub releases exist."""
        workflow = BUILD_LIVE_ISO.read_text(encoding="utf-8")
        publish = workflow.split("\n  publish:", 1)[1]
        releases_at = publish.index("- name: Publish GitHub releases")
        upload_at = publish.index("- name: Upload ISO to Cloudflare R2")
        self.assertLess(releases_at, upload_at)

    def test_r2_uploads_land_the_iso_after_its_sidecars(self):
        """Neither R2 set may expose an ISO before its checksum/signature."""
        action = UPLOAD_R2.read_text(encoding="utf-8")
        immutable_loop = next(
            line for line in action.splitlines() if "for artifact in" in line
        )
        self.assertLess(
            immutable_loop.index('"${ISO}.json"'),
            immutable_loop.index('"${ISO}"'),
        )
        channel_iso_cp = 'aws s3 cp "${ISO}" "s3://${BUCKET}/$(basename "${CHANNEL}")"'
        self.assertIn(channel_iso_cp, action)
        self.assertLess(
            action.index('aws s3 cp "${CHANNEL}${suffix}"'),
            action.index(channel_iso_cp),
        )


if __name__ == "__main__":
    unittest.main()
