"""Fail-closed context guard for copying existing stable images unchanged.

This validates consistency only. The workflow must obtain main_sha and
legacy_digest independently from GitHub and the source registry, and verify
cryptographic provenance before any copy or signature is produced.
"""

import json
import os
import re
import sys


def validate(context):
    """Accept only the authorized maintenance context and exact source identity."""
    required = {
        "enabled", "repository", "event", "ref", "original_event", "tag",
        "source_sha", "main_sha", "source_digest", "legacy_digest",
    }
    if not isinstance(context, dict) or set(context) != required:
        return False
    if not (
        context["enabled"] is True
        and context["repository"] == "mrtrickdotorg/kyth"
        and context["event"] == "workflow_dispatch"
        and context["ref"] == "refs/heads/testing"
        and context["original_event"] == ""
        and context["tag"] in ("latest", "latest-cachy")
    ):
        return False
    for name in ("source_sha", "main_sha"):
        value = context[name]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
            return False
    for name in ("source_digest", "legacy_digest"):
        value = context[name]
        if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            return False
    return (
        context["source_sha"] == context["main_sha"]
        and context["source_digest"] == context["legacy_digest"]
    )


def main():
    try:
        context = {
            "enabled": json.loads(os.environ["MIGRATE_LEGACY_STABLE"]),
            "repository": os.environ["GITHUB_REPOSITORY"],
            "event": os.environ["GITHUB_EVENT_NAME"],
            "ref": os.environ["GITHUB_REF"],
            "original_event": os.environ["ORIGINAL_EVENT"],
            "tag": os.environ["SOURCE_TAG"],
            "source_sha": os.environ["SOURCE_SHA"],
            "main_sha": os.environ["MAIN_SHA"],
            "source_digest": os.environ["SOURCE_DIGEST"],
            "legacy_digest": os.environ["LEGACY_DIGEST"],
        }
    except (KeyError, ValueError) as exc:
        print(f"Invalid migration context: {exc}", file=sys.stderr)
        return 1
    if not validate(context):
        print("Stable migration context rejected", file=sys.stderr)
        return 1
    print(json.dumps(context, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
