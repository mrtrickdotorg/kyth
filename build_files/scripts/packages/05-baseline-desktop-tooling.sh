#!/bin/bash
# shellcheck shell=bash
set -euo pipefail

# Install baseline tooling in a single transaction to reduce solver and
# metadata overhead before the gaming repos are enabled.
# pam-kwallet is required (not --skip-unavailable): script 26 wires its PAM
# module into the login stack, and a silently-missing package would break
# wallet unlock while the build looks green.
dnf5 install -y \
	plasma-login-manager \
	pam-kwallet
dnf5 install -y --skip-unavailable \
	kcm-plasmalogin \
	fprintd \
	fprintd-pam \
	pcsc-lite \
	opensc \
	krdc \
	bubblewrap \
	irqbalance \
	plocate \
	ntfs-3g \
	os-prober \
	rsync \
	fuse \
	fuse-libs \
	fuse3 \
	mtools \
	dosfstools \
	sbsigntools \
	util-linux-script \
	openssl \
	fwupd

# The Guardian's local-LLM runtime is deliberately NOT installed here.
# Fedora's llama-cpp package links the ROCm/HIP backend into the main
# binary, so it hard-requires rocblas/hipblas/libamdhip64 and drags in
# the whole ROCm tree (rocsolver alone is ~1 GiB; the closure measured
# 2.32 GiB — 30% of the image) for a feature that is optional and
# CPU-only by design. The Guardian already treats a missing llama-cli
# as an explicit degraded state and its model is user-downloaded, so
# the runtime is fetched on first use instead of taxing every install.
# Do not re-add llama-cpp (or any rocm* package) to the image; the
# build contracts pin this.
