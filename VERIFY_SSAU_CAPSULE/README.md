# SSAU Independent Verification Capsule

This capsule exists to enable blind verification of SSAU by exact replay.

## Verification Ritual (60 seconds)

1) Run the verifier:

- Windows: `RUN_VERIFY.bat`
- Linux/macOS: `bash RUN_VERIFY.sh`

2) Confirm replay PASS:

- The runlog must show replay PASS across components.

3) Confirm the pinned fingerprint matches:

- Compare the ACTUAL fingerprint printed by the script
- Against `EXPECTED_SHA256.txt`

If the fingerprint matches, SSAU verification is confirmed by byte-identity.
If it does not match, the run is NOT VERIFIED.

No tolerance. No statistical testing. No manual review required.

---

## Capsule Fingerprint Policy

The capsule fingerprint is defined over:

- `runlog.txt`
- `summary.txt`
- `verification_index.csv`

These files represent deterministic replay evidence.

`verification_index.json` is included for inspection and tooling support but is not part of the fingerprint due to potential environment-dependent metadata ordering.

Verification succeeds when the ACTUAL fingerprint matches the EXPECTED fingerprint exactly.

