#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "${ROOT}"' EXIT

CERT="${ROOT}/kyth-secureboot.der"
FLAG="${ROOT}/mok-enrolled"
LOG="${ROOT}/mokutil.log"
MOKUTIL="${ROOT}/mokutil"

touch "${CERT}"

cat >"${MOKUTIL}" <<'MOKEOF'
#!/usr/bin/env bash
set -euo pipefail

case "$1" in
    --sb-state)
        if [[ "${MOCK_SB_ENABLED:-0}" == "1" ]]; then
            echo "SecureBoot enabled"
        else
            echo "SecureBoot disabled"
        fi
        ;;
    --test-key)
        if [[ "${MOCK_ENROLLED:-0}" == "1" ]]; then
            echo "$2 is already enrolled"
        else
            echo "$2 is not enrolled" >&2
            exit 1
        fi
        ;;
    --list-enrolled)
        if [[ "${MOCK_ENROLLED:-0}" == "1" ]]; then
            echo "CN=KythOS Secure Boot"
        fi
        ;;
    --list-new)
        if [[ "${MOCK_PENDING:-0}" == "1" ]]; then
            echo "CN=KythOS Secure Boot"
        fi
        ;;
    --import)
        # Tripwire only: the enroller must never import unattended, so
        # any call lands in the log and fails the case asserting on it.
        cat >/dev/null
        echo "import $2" >> "${MOCK_LOG}"
        ;;
    *)
        echo "unexpected mokutil args: $*" >&2
        exit 2
        ;;
esac
MOKEOF
chmod +x "${MOKUTIL}"

run_enroller() {
	MOCK_LOG="${LOG}" \
		KYTH_ENROLL_MOK_FORCE_SHELL="1" \
		MOCK_SB_ENABLED="${1}" \
		MOCK_ENROLLED="${2}" \
		MOCK_PENDING="${3:-0}" \
		KYTH_MOK_CERT_DER="${CERT}" \
		KYTH_MOK_FLAG="${FLAG}" \
		KYTH_MOKUTIL="${MOKUTIL}" \
		"$(dirname "${BASH_SOURCE[0]}")/../kyth-enroll-mok" >"${ROOT}/out" 2>"${ROOT}/err"
}

run_enroller 0 0
if [[ -f "${FLAG}" ]]; then
	echo "disabled Secure Boot path should not create enrollment marker" >&2
	exit 1
fi
if [[ -s "${LOG}" ]]; then
	echo "disabled Secure Boot path should not import automatically" >&2
	exit 1
fi

run_enroller 1 0
if [[ -f "${FLAG}" ]]; then
	echo "unenrolled Secure Boot path should not create enrollment marker" >&2
	exit 1
fi
if [[ -s "${LOG}" ]]; then
	echo "unenrolled Secure Boot path should not import automatically" >&2
	exit 1
fi

run_enroller 1 0 1
if [[ -f "${FLAG}" ]]; then
	echo "staged Secure Boot path should not create enrollment marker before confirmation" >&2
	exit 1
fi
if [[ -s "${LOG}" ]]; then
	echo "staged Secure Boot path should not import again" >&2
	exit 1
fi

rm -f "${FLAG}" "${LOG}"
run_enroller 1 1
if [[ ! -f "${FLAG}" ]]; then
	echo "already-enrolled path should create enrollment marker" >&2
	exit 1
fi
if [[ -s "${LOG}" ]]; then
	echo "already-enrolled path should not import again" >&2
	exit 1
fi

echo "secureboot enrollment tests passed"
