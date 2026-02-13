@echo off
setlocal

cd /d "%~dp0"
cd ..

if exist VERIFY_SSAU_CAPSULE\CAPSULE_OUT rmdir /s /q VERIFY_SSAU_CAPSULE\CAPSULE_OUT
mkdir VERIFY_SSAU_CAPSULE\CAPSULE_OUT

python scripts\ssau_master_verify_v1.py --verify_replay --out_root VERIFY_SSAU_CAPSULE\CAPSULE_OUT

set "RUNDIR="
for /d %%D in (VERIFY_SSAU_CAPSULE\CAPSULE_OUT\*) do set "RUNDIR=%%D"

if "%RUNDIR%"=="" (
  echo ERROR: No capsule run directory found.
  exit /b 1
)

echo ===== ACTUAL (capsule fingerprint) =====
cd /d "%RUNDIR%"
certutil -hashfile runlog.txt SHA256 | findstr /R /V "hash CertUtil"
certutil -hashfile summary.txt SHA256 | findstr /R /V "hash CertUtil"
certutil -hashfile verification_index.csv SHA256 | findstr /R /V "hash CertUtil"
cd /d "%~dp0"
cd ..

echo.
echo ===== EXPECTED (pinned) =====
type VERIFY_SSAU_CAPSULE\EXPECTED_SHA256.txt

endlocal
