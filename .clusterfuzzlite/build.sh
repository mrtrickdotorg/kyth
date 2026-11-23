#!/bin/bash -eu

# fuzz/ currently carries only its pinned atheris requirement: the Hub fuzzer
# and the retired Hub page package it bundled are gone. Glob with nullglob so
# an empty fuzz/ reports that instead of handing pyinstaller a nonexistent
# literal path.
shopt -s nullglob
fuzzers=("$SRC"/kyth/fuzz/*_fuzzer.py)
if ((${#fuzzers[@]} == 0)); then
	echo "clusterfuzzlite: fuzz/ has no *_fuzzer.py — nothing to build" >&2
	exit 1
fi

for fuzzer in "${fuzzers[@]}"; do
	fuzzer_basename="$(basename -s .py "$fuzzer")"
	fuzzer_package="${fuzzer_basename}.pkg"
	pyinstaller \
		--distpath "$OUT" \
		--onefile \
		--name "$fuzzer_package" \
		"$fuzzer"
	cat >"$OUT/$fuzzer_basename" <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
PYTHONUTF8=1 "\$this_dir/$fuzzer_package" "\$@"
EOF
	chmod +x "$OUT/$fuzzer_basename"
done
