#!/usr/bin/env bash
# check-base-pin-drift.sh — report whether the Fedora base digest pinned
# in-tree still matches the digest the registry serves for the floating tag.
#
# Why this exists: CI does NOT build from the pinned digest. build.yml's
# "Resolve upstream base image digest" step reads the image ref (repo:tag)
# from build_base/Dockerfile, resolves the tag's CURRENT digest, and builds
# from that — CI floats. Local builds do the opposite on purpose:
# build.just's build-base fails closed on anything that is not a
# digest-pinned ref, and _vars.just records the pin as the reproducible,
# cosign-verified reference. So the pin rots silently: Quay supersedes the
# :45 digest, CI moves on, and local builds keep testing the old base (or
# fail outright once Quay garbage-collects the superseded digest, which
# happened within about a day during the F45 beta). This check makes the
# rot loud in both places instead of silent.
#
# The pin itself is deliberate and stays. This script never rewrites it;
# on drift it reports the exact ref a human re-pins to when they decide to.
#
# Usage:
#   build_files/scripts/check-base-pin-drift.sh [--strict]
#
# Exit codes: 0 when in sync, when the registry digest cannot be resolved
# (unknown is not drift — an offline builder keeps the pin), and on drift
# or split in the default warn-only mode. --strict exits 1 on drift or on
# a split pin so a caller may gate on it explicitly.
#
# Environment:
#   KYTH_BASE_CURRENT_DIGEST  Pre-resolved current digest for the floating
#                             tag; skips registry resolution. CI sets this
#                             (build.yml already resolved the digest with
#                             buildx) and tests use it for fixtures.
#   KYTH_BASE_RESOLVER        auto|skopeo|docker|none (default auto:
#                             skopeo, then docker buildx imagetools).
#                             "none" forces the unknown path (tests).
#   KYTH_BASE_DOCKERFILE      Pin source 1 (default build_base/Dockerfile).
#   KYTH_BASE_VARS_JUST       Pin source 2 (default _vars.just).
#
# In GitHub Actions (GITHUB_ACTIONS=true) drift and split reports are also
# emitted as ::warning:: annotations.
#
# No `set -e`: this is a reporter invoked from builds that must not fail
# because the advice channel broke. Errors are handled explicitly.

set -uo pipefail

strict=0
for arg in "$@"; do
	case "${arg}" in
	--strict) strict=1 ;;
	*)
		echo "check-base-pin-drift: unknown argument: ${arg}" >&2
		exit 2
		;;
	esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
dockerfile="${KYTH_BASE_DOCKERFILE:-${repo_root}/build_base/Dockerfile}"
vars_just="${KYTH_BASE_VARS_JUST:-${repo_root}/_vars.just}"

digest_re='^sha256:[0-9a-f]{64}$'

fail_read() {
	echo "base-pin: ERROR: $1" >&2
	exit 2
}

# Pin source 1: CI's own parse of build_base/Dockerfile.
[[ -f "${dockerfile}" ]] || fail_read "pin source not found: ${dockerfile}"
pinned_ref="$(sed -n 's/^ARG BASE_IMAGE=//p' "${dockerfile}" | head -n1)"
[[ -n "${pinned_ref}" ]] || fail_read "no 'ARG BASE_IMAGE=' line in ${dockerfile}"
image="${pinned_ref%%@*}"
pin_digest="${pinned_ref##*@}"
[[ "${pin_digest}" =~ ${digest_re} ]] ||
	fail_read "pinned digest in ${dockerfile} is not a sha256 digest: '${pin_digest}'"

# Pin source 2: the default_base_image fallback in _vars.just. The two
# in-tree copies must agree (also hard-gated by
# test_base_digest_pin_is_identical_in_dockerfile_and_vars); a split is
# reported here too because this is the tool a human runs first.
[[ -f "${vars_just}" ]] || fail_read "pin source not found: ${vars_just}"
vars_digest="$(grep -F 'default_base_image' "${vars_just}" |
	grep -F 'fedora-kinoite' |
	head -n1 |
	sed -n 's/.*@\(sha256:[0-9a-f]\{64\}\).*/\1/p')"
[[ -n "${vars_digest}" ]] ||
	fail_read "no digest-pinned default_base_image fallback in ${vars_just}"

annotate() {
	if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
		echo "::warning::$1"
	fi
}

if [[ "${vars_digest}" != "${pin_digest}" ]]; then
	echo "base-pin: SPLIT: the in-tree pin copies disagree — build_base/Dockerfile has ${pin_digest}, _vars.just has ${vars_digest}. Reconcile them to one digest."
	annotate "base-pin split: build_base/Dockerfile pins ${pin_digest} but _vars.just pins ${vars_digest}"
	[[ "${strict}" == "1" ]] && exit 1
	exit 0
fi

# Resolve the registry's current digest for the floating tag, unless the
# caller already resolved it (CI) or pinned the resolver off (tests).
current="${KYTH_BASE_CURRENT_DIGEST:-}"
if [[ -z "${current}" ]]; then
	resolver="${KYTH_BASE_RESOLVER:-auto}"
	if [[ "${resolver}" != "none" ]]; then
		if [[ "${resolver}" == "skopeo" || "${resolver}" == "auto" ]] &&
			command -v skopeo >/dev/null 2>&1; then
			current="$(skopeo inspect --format '{{.Digest}}' "docker://${image}" 2>/dev/null || true)"
		fi
		if [[ -z "${current}" && "${resolver}" != "skopeo" ]] &&
			command -v docker >/dev/null 2>&1; then
			current="$(docker buildx imagetools inspect "${image}" --format '{{ .Manifest.Digest }}' 2>/dev/null || true)"
		fi
	fi
fi

if [[ ! "${current}" =~ ${digest_re} ]]; then
	echo "base-pin: UNKNOWN: could not resolve the current digest of ${image}; the in-tree pin is ${pin_digest}. Local builds keep the pin; CI resolves the tag itself, so this says nothing about CI."
	exit 0
fi

if [[ "${current}" == "${pin_digest}" ]]; then
	echo "base-pin: in sync: ${image} is pinned at ${pin_digest}, which is what the registry currently serves."
	exit 0
fi

echo "base-pin: DRIFT: ${image} is pinned in-tree at ${pin_digest}, but the registry now serves ${current}."
echo "base-pin: CI builds float to the registry digest, so CI and local builds are testing different bases."
echo "base-pin: to re-pin, set both build_base/Dockerfile (ARG BASE_IMAGE) and _vars.just (default_base_image) to ${image}@${current}."
annotate "base-pin drift: in-tree pin ${pin_digest} != current ${image} digest ${current}; CI builds the new base, local builds the pinned one"
[[ "${strict}" == "1" ]] && exit 1
exit 0
