"""Pure policy checks for Kyth's opt-in destination-testing publication path.

The validation functions have no I/O or network side effects. The CLI reads
local JSON files only; callers must independently obtain GitHub API context and
construct the expected identity from trusted workflow values before relying on
any output. This module never authenticates those input sources itself.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

SOURCE_REPOSITORY = "mrtrickdotorg/kyth"
SOURCE_BRANCH = "testing"
SOURCE_REF = f"refs/heads/{SOURCE_BRANCH}"
VALIDATION_WORKFLOW_PATH = ".github/workflows/validation.yml"
DESTINATION_IMAGE = "ghcr.io/mrtrickdotorg/kyth"

_CHANNEL_FLAVORS = {"testing": "fedora", "testing-cachy": "cachy"}
_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RUN_NUMBER_RE = re.compile(r"[1-9][0-9]*\Z")
_MAX_OCI_TAG_LENGTH = 128


def _require_match(pattern: re.Pattern[str], value: object, field: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def _require_equal(actual: object, expected: object, field: str) -> None:
    if actual != expected:
        raise ValueError(f"{field} does not match the authorized destination identity")


def _require_oci_tags(*tags: str) -> None:
    if any(len(tag) > _MAX_OCI_TAG_LENGTH for tag in tags):
        raise ValueError("destination OCI tag exceeds the 128-character limit")


def destination_build_plan(
    *,
    repository: str,
    ref: str,
    source_sha: str,
    build_workflow_sha: str,
    source_tag: str,
    kernel_flavor: str,
    run_id: str,
    run_attempt: str,
) -> dict[str, str]:
    """Return a deterministic, non-publishing destination candidate plan."""
    _require_equal(repository, SOURCE_REPOSITORY, "source repository")
    _require_equal(ref, SOURCE_REF, "source ref")
    source_sha = _require_match(_SHA_RE, source_sha, "source SHA")
    build_workflow_sha = _require_match(
        _SHA_RE, build_workflow_sha, "build workflow SHA"
    )
    _require_equal(build_workflow_sha, source_sha, "build workflow SHA")
    if not isinstance(source_tag, str) or source_tag not in _CHANNEL_FLAVORS:
        raise ValueError("unsupported destination testing channel")
    expected_flavor = _CHANNEL_FLAVORS[source_tag]
    _require_equal(kernel_flavor, expected_flavor, "kernel flavor")
    kernel_flavor = expected_flavor
    run_id = _require_match(_RUN_NUMBER_RE, run_id, "run ID")
    run_attempt = _require_match(_RUN_NUMBER_RE, run_attempt, "run attempt")

    base_tag = f"destination-base-{source_tag}-{run_id}-{run_attempt}-{kernel_flavor}"
    raw_tag = f"destination-raw-{source_tag}-{run_id}-{run_attempt}-{kernel_flavor}"
    candidate_tag = (
        f"destination-candidate-{source_tag}-{run_id}-{run_attempt}-{kernel_flavor}"
    )
    _require_oci_tags(base_tag, raw_tag, candidate_tag)
    return {
        "image": DESTINATION_IMAGE,
        "image_owner": "mrtrickdotorg",
        "source_repository": SOURCE_REPOSITORY,
        "source_ref": SOURCE_REF,
        "source_sha": source_sha,
        "source_url": f"https://github.com/{SOURCE_REPOSITORY}/tree/{source_sha}",
        "documentation_url": (
            f"https://github.com/{SOURCE_REPOSITORY}/blob/{source_sha}/README.md"
        ),
        "source_tag": source_tag,
        "kernel_flavor": kernel_flavor,
        "base_tag": base_tag,
        "base_ref": f"{DESTINATION_IMAGE}:{base_tag}",
        "raw_tag": raw_tag,
        "raw_ref": f"{DESTINATION_IMAGE}:{raw_tag}",
        "candidate_tag": candidate_tag,
        "candidate_ref": f"{DESTINATION_IMAGE}:{candidate_tag}",
        "artifact_name": (
            f"destination-testing-{source_tag}-{run_id}-{run_attempt}-{kernel_flavor}"
        ),
        "floating_tag": source_tag,
    }


def validate_destination_dispatch(
    *,
    event_name: str,
    repository: str,
    ref: str,
    skip_validation: str | bool,
    source_sha: str,
    testing_tip_sha: str,
    validation_sha: str,
    validation_branch: str,
    validation_workflow_name: str,
    validation_workflow_path: str,
    validation_event: str,
    validation_status: str,
    validation_conclusion: str,
) -> dict[str, str]:
    """Validate the exact manual testing dispatch and return fixed identity.

    Callers must obtain ``testing_tip_sha`` and the Validation fields from the
    GitHub API, not from workflow inputs. Any missing, malformed, or mismatched
    value is rejected.
    """
    _require_equal(event_name, "workflow_dispatch", "event")
    _require_equal(repository, SOURCE_REPOSITORY, "source repository")
    _require_equal(ref, SOURCE_REF, "source ref")
    if not (
        (isinstance(skip_validation, str) and skip_validation == "false")
        or (type(skip_validation) is bool and skip_validation is False)
    ):
        raise ValueError("destination mode cannot skip Validation")

    source_sha = _require_match(_SHA_RE, source_sha, "source SHA")
    testing_tip_sha = _require_match(_SHA_RE, testing_tip_sha, "testing tip SHA")
    validation_sha = _require_match(_SHA_RE, validation_sha, "Validation SHA")
    _require_equal(testing_tip_sha, source_sha, "current testing tip")
    _require_equal(validation_sha, source_sha, "Validation SHA")
    _require_equal(validation_branch, SOURCE_BRANCH, "Validation branch")
    _require_equal(validation_workflow_name, "Validation", "Validation workflow")
    _require_equal(
        validation_workflow_path,
        VALIDATION_WORKFLOW_PATH,
        "Validation workflow path",
    )
    _require_equal(validation_event, "push", "Validation event")
    _require_equal(validation_status, "completed", "Validation status")
    _require_equal(validation_conclusion, "success", "Validation conclusion")

    return {
        "image": DESTINATION_IMAGE,
        "branch": SOURCE_BRANCH,
        "source_sha": source_sha,
    }


def validate_destination_metadata(
    metadata: Mapping[str, object], expected: Mapping[str, object]
) -> dict[str, str]:
    """Validate the destination-testing metadata namespace against trusted run context.

    Callers pass only the namespaced destination object plus an expected
    identity assembled from workflow/API context. Unknown fields are rejected,
    and no caller-selected destination or channel is accepted.
    """
    if not isinstance(metadata, Mapping) or not isinstance(expected, Mapping):
        raise ValueError("metadata and expected identity must be mappings")

    required_metadata = {
        "mode",
        "image",
        "source_tag",
        "source_sha",
        "build_workflow_sha",
        "kernel_flavor",
        "run_id",
        "run_attempt",
        "candidate_tag",
        "digest",
        "base_image",
        "base_digest",
        "artifact_name",
    }
    if set(metadata) != required_metadata:
        raise ValueError("destination metadata has missing or unexpected fields")

    required_expected = {
        "source_sha",
        "build_workflow_sha",
        "source_tag",
        "kernel_flavor",
        "run_id",
        "run_attempt",
    }
    if set(expected) != required_expected:
        raise ValueError("expected identity has missing or unexpected fields")

    for key in required_expected:
        _require_equal(metadata.get(key), expected[key], key)

    _require_equal(metadata.get("mode"), "destination_testing", "mode")
    _require_equal(metadata.get("image"), DESTINATION_IMAGE, "image")

    source_tag = metadata.get("source_tag")
    if not isinstance(source_tag, str) or source_tag not in _CHANNEL_FLAVORS:
        raise ValueError("unsupported destination testing channel")
    kernel_flavor = metadata.get("kernel_flavor")
    _require_equal(kernel_flavor, _CHANNEL_FLAVORS[source_tag], "kernel flavor")

    source_sha = _require_match(_SHA_RE, metadata.get("source_sha"), "source SHA")
    build_workflow_sha = _require_match(
        _SHA_RE, metadata.get("build_workflow_sha"), "build workflow SHA"
    )
    _require_equal(build_workflow_sha, source_sha, "build workflow SHA")
    run_id = _require_match(_RUN_NUMBER_RE, metadata.get("run_id"), "run ID")
    run_attempt = _require_match(
        _RUN_NUMBER_RE, metadata.get("run_attempt"), "run attempt"
    )
    digest = _require_match(_DIGEST_RE, metadata.get("digest"), "candidate digest")
    base_digest = _require_match(_DIGEST_RE, metadata.get("base_digest"), "base digest")

    base_tag = f"destination-base-{source_tag}-{run_id}-{run_attempt}-{kernel_flavor}"
    raw_tag = f"destination-raw-{source_tag}-{run_id}-{run_attempt}-{kernel_flavor}"
    candidate_tag = (
        f"destination-candidate-{source_tag}-{run_id}-{run_attempt}-{kernel_flavor}"
    )
    _require_oci_tags(base_tag, raw_tag, candidate_tag)
    _require_equal(metadata.get("candidate_tag"), candidate_tag, "candidate tag")
    _require_equal(
        metadata.get("base_image"),
        f"{DESTINATION_IMAGE}:{base_tag}",
        "base image",
    )
    artifact_name = (
        f"destination-testing-{source_tag}-{run_id}-{run_attempt}-{kernel_flavor}"
    )
    _require_equal(metadata.get("artifact_name"), artifact_name, "artifact name")

    return {
        "image": DESTINATION_IMAGE,
        "source_sha": source_sha,
        "build_workflow_sha": build_workflow_sha,
        "source_tag": source_tag,
        "kernel_flavor": str(kernel_flavor),
        "run_id": run_id,
        "run_attempt": run_attempt,
        "base_tag": base_tag,
        "base_ref": f"{DESTINATION_IMAGE}:{base_tag}",
        "raw_tag": raw_tag,
        "raw_ref": f"{DESTINATION_IMAGE}:{raw_tag}",
        "candidate_tag": candidate_tag,
        "candidate_ref": f"{DESTINATION_IMAGE}:{candidate_tag}",
        "digest": digest,
        "digest_ref": f"{DESTINATION_IMAGE}@{digest}",
        "base_digest": base_digest,
        "floating_tag": source_tag,
    }


def _read_json_object(path: str) -> dict[str, object]:
    import json

    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("input JSON must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    dispatch_parser = subparsers.add_parser("validate-dispatch")
    dispatch_parser.add_argument("input_json", help="API-derived dispatch context JSON")
    plan_parser = subparsers.add_parser("plan-build")
    plan_parser.add_argument("input_json", help="trusted fixed build-plan JSON")
    metadata_parser = subparsers.add_parser("validate-metadata")
    metadata_parser.add_argument(
        "--metadata", required=True, help="artifact metadata JSON"
    )
    metadata_parser.add_argument(
        "--expected", required=True, help="workflow-context identity JSON"
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "plan-build":
            payload = _read_json_object(args.input_json)
            identity = destination_build_plan(**cast(Any, payload))
        elif args.command == "validate-dispatch":
            payload = _read_json_object(args.input_json)
            identity = validate_destination_dispatch(**cast(Any, payload))
        else:
            metadata_path = Path(args.metadata)
            expected_path = Path(args.expected)
            if metadata_path.resolve() == expected_path.resolve():
                raise ValueError(
                    "metadata and expected identity must use separate files"
                )
            metadata = _read_json_object(str(metadata_path))
            expected = _read_json_object(str(expected_path))
            identity = validate_destination_metadata(
                cast(Mapping[str, object], metadata),
                cast(Mapping[str, object], expected),
            )
    except (OSError, ValueError, TypeError) as exc:
        print(f"destination policy validation failed: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(identity, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
