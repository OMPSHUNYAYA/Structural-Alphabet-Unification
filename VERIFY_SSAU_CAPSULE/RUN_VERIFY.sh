#!/usr/bin/env sh
set -eu

rm -rf CAPSULE_OUT
mkdir -p CAPSULE_OUT

python3 ../ssau_master_verify_v1.py --verify_replay --out_root VERIFY_SSAU_CAPSULE/CAPSULE_OUT

cat VERIFY_SSAU_CAPSULE/CAPSULE_OUT/MANIFEST.sha256
echo ""
cat EXPECTED_SHA256.txt
