"""Contracts for Secure Boot signing of the first-boot NVIDIA akmod build.

Under Secure Boot lockdown the kernel refuses unsigned modules, so the
deferred `akmods --force` build in kyth-hardware-policy must be gated on
the akmods signing keypair: generate it once per machine, defer until its
certificate is enrolled, and verify the built module's signature before
flipping the persisted status to `proprietary-ready`. These tests pin the
source shape of that flow; the decision table itself is unit-tested in
Rust (nvidia_signing_gate_decision_table).
"""
from __future__ import annotations

import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build_files" / "kyth_shared"))
sys.path.insert(0, str(ROOT / "build_files" / "kyth-installer"))

HARDWARE_POLICY_BIN = ROOT / "src/kyth-shared-rs/src/hardware_policy_bin.rs"
NVIDIA_AKMODS_UNIT = ROOT / "build_files/kyth-nvidia-akmods.service"
GPU_NVIDIA_FRAGMENT = ROOT / "build_files/scripts/packages/16-gpu-nvidia.sh"


def _rust_fn_body(source: str, name: str) -> str:
    start = source.index(f"fn {name}")
    end = source.index("\nfn ", start)
    return source[start:end]


class NvidiaSigningContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bin_source = HARDWARE_POLICY_BIN.read_text(encoding="utf-8")

    def test_signing_prep_precedes_the_akmods_build_inside_the_lock(self) -> None:
        """The gate must run before `akmods --force`, and under the lock:
        prepping outside the lock would let a second build race the
        one-time keypair generation, and prepping after the build would
        sign nothing at all."""
        body = _rust_fn_body(self.bin_source, "build_nvidia_akmods")
        lock_at = body.index("acquire(DEFAULT_LOCK_PATH")
        prep_at = body.index("ensure_nvidia_module_signing()")
        build_at = body.index('"--force"')
        self.assertLess(lock_at, prep_at)
        self.assertLess(prep_at, build_at)

    def test_deferred_and_unsigned_states_are_persisted(self) -> None:
        """A deferral must be visible to the Hub (not a silent skip), and a
        build that comes out unsigned despite an enrolled certificate must
        surface as its own state instead of flipping to ready."""
        self.assertIn('"secureboot-enrollment-required"', self.bin_source)
        self.assertIn('"proprietary-unsigned"', self.bin_source)
        body = _rust_fn_body(self.bin_source, "build_nvidia_akmods")
        # The unsigned check runs only on the signed path, after the build.
        self.assertIn("NvidiaSigningGate::BuildSigned", body)
        self.assertIn("nvidia_module_signed()", body)

    def test_enrollment_probe_tests_the_akmods_cert_itself(self) -> None:
        """The akmods certificate is generated per machine, so its subject
        is not "KythOS Secure Boot": enrollment must be probed with
        `mokutil --test-key` on the certificate file, never by subject
        matching over --list-enrolled (this binary must not invoke
        --list-enrolled at all)."""
        self.assertIn('"--test-key"', self.bin_source)
        self.assertIn("AKMODS_CERT_PATH", self.bin_source)
        self.assertNotIn('"--list-enrolled"', self.bin_source)

    def test_kmodgenca_is_guarded_by_an_existence_check(self) -> None:
        """Regenerating the keypair would orphan the enrolled certificate,
        so kmodgenca may only run behind an existence check on the pair —
        never unconditionally."""
        body = _rust_fn_body(self.bin_source, "generate_akmods_keypair_once")
        guard_at = body.index(".exists()")
        generate_at = body.index("kmodgenca")
        self.assertLess(guard_at, generate_at)
        self.assertIn("AKMODS_CERT_PATH", body)
        self.assertIn("AKMODS_KEY_PATH", body)

    def test_unit_can_write_the_akmods_pki_tree(self) -> None:
        """ProtectSystem=strict makes /etc read-only unless named in
        ReadWritePaths; the keypair generation and akmods' own writes need
        /etc/pki/akmods there. The directories always exist in the image,
        so the path must not carry the ignore-missing `-` prefix."""
        unit = NVIDIA_AKMODS_UNIT.read_text(encoding="utf-8")
        read_write = next(
            line for line in unit.splitlines() if line.startswith("ReadWritePaths=")
        )
        paths = read_write.split("=", 1)[1].split()
        self.assertIn("/etc/pki/akmods", paths)
        self.assertNotIn("-/etc/pki/akmods", paths)

    def test_image_precreates_pki_dirs_without_key_material(self) -> None:
        """The image ships the (empty) akmods PKI directories with the
        right modes — the private half locked down — but never key
        material: keys are per-machine and generated at first boot."""
        fragment = GPU_NVIDIA_FRAGMENT.read_text(encoding="utf-8")
        self.assertIn("install -d -m 0755 /etc/pki/akmods/certs", fragment)
        self.assertIn("install -d -m 0700 /etc/pki/akmods/private", fragment)
        # Comments may name the runtime generator; no executable line may
        # run it or create/copy a keypair file at image build time.
        executable = "\n".join(
            line
            for line in fragment.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        self.assertNotIn("kmodgenca", executable)
        self.assertIsNone(
            re.search(r"public_key\.(der|priv)|private_key", executable),
            "no keypair file may be created or copied at image build time",
        )


if __name__ == "__main__":
    unittest.main()
