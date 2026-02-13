#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, UTC

def _abspath(p):
    return os.path.abspath(p)

def _ensure_dir(p):
    os.makedirs(p, exist_ok=True)

def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def _read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()

def _write_text(path, s):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)

def _write_json(path, obj):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=False, sort_keys=True, indent=2)

def _find_dirs(root):
    if not os.path.isdir(root):
        return []
    out = []
    for name in os.listdir(root):
        p = os.path.join(root, name)
        if os.path.isdir(p):
            out.append(p)
    out.sort()
    return out

def _pick_run_dir(out_root, prefer_contains=None):
    cands = _find_dirs(out_root)
    if not cands:
        return ""
    if prefer_contains:
        for p in reversed(cands):
            if prefer_contains in os.path.basename(p):
                return p
    return cands[-1]

def _read_manifest_sha(out_dir):
    m = os.path.join(out_dir, "MANIFEST.sha256")
    if not os.path.isfile(m):
        return ""
    return _sha256_file(m)

def _parse_lattice_summary(summary_txt_path):
    txt = _read_text(summary_txt_path)
    blocks = []
    cur = None
    for line in txt.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("INPUT:"):
            if cur:
                blocks.append(cur)
            cur = {"input": s.split("INPUT:", 1)[1].strip()}
        elif cur is not None:
            if "=" in s:
                k, v = s.split("=", 1)
                cur[k.strip()] = v.strip()
    if cur:
        blocks.append(cur)
    return blocks

def _run(cmd, cwd, log_lines):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = p.stdout or ""
    log_lines.append("CMD: " + " ".join(cmd))
    log_lines.append(out.rstrip("\n"))
    if p.returncode != 0:
        log_lines.append("RETURN_CODE=" + str(p.returncode))
    return p.returncode

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="V01_SSAU_MASTER_VERIFY", help="Run tag.")
    ap.add_argument("--verify_replay", action="store_true")
    ap.add_argument("--out_root", default=os.path.join("outputs", "ssau_verify_out"), help="Output root for master verifier artifacts.")
    ap.add_argument("--python", default=sys.executable, help="Python executable.")
    args = ap.parse_args()

    cwd_root = os.getcwd()
    out_root = _abspath(args.out_root)
    _ensure_dir(out_root)

    master_tag = args.tag
    stamp = "20000101_000000"
    run_dir = os.path.join(out_root, f"{stamp}__SSAU_MASTER_VERIFY__{master_tag}")
    _ensure_dir(run_dir)

    log_lines = []
    ok = True

    p_master = _abspath(os.path.join("outputs", "ssau_master_alphabet", "alphabet.json"))
    p_ssw = _abspath(os.path.join("outputs", "ssw_extract_out", "alphabet.json"))
    p_csv = _abspath(os.path.join("outputs", "ssau_csv_extract_out", "alphabet.json"))

    required = [p_master, p_ssw, p_csv]
    missing = [p for p in required if not os.path.isfile(p)]
    if missing:
        _write_text(os.path.join(run_dir, "summary.txt"), "FAIL: missing required inputs\n" + "\n".join(missing) + "\n")
        return 2

    inject_root = _abspath(os.path.join("outputs", "ssau_inject_out"))
    unify_root = _abspath(os.path.join("outputs", "ssau_unify_out"))
    srs_root = _abspath(os.path.join("outputs", "ssau_srs_out"))
    rit_root = _abspath(os.path.join("outputs", "ssau_rit_out"))
    scm_root = _abspath(os.path.join("outputs", "ssau_scm_out"))
    lattice_root = _abspath(os.path.join("outputs", "ssau_lattice_compress_out"))

    scripts_dir = _abspath(os.path.join("scripts"))
    s_inject = os.path.join(scripts_dir, "ssau_domain_injection_stress_v0_1.py")
    s_unify = os.path.join(scripts_dir, "ssau_unify_v0_2.py")
    s_srs = os.path.join(scripts_dir, "ssau_srs_growth_curve_v0_1.py")
    s_rit = os.path.join(scripts_dir, "ssau_refusal_invariance_v0_4.py")
    s_scm = os.path.join(scripts_dir, "ssau_structural_collapse_mapping_v0_1.py")
    s_lattice = os.path.join(scripts_dir, "ssau_lattice_compress_v0_1.py")

    for sp in [s_inject, s_unify, s_srs, s_rit, s_scm, s_lattice]:
        if not os.path.isfile(sp):
            missing.append(sp)
    if missing:
        _write_text(os.path.join(run_dir, "summary.txt"), "FAIL: missing required scripts\n" + "\n".join(sorted(set(missing))) + "\n")
        return 2

    vr = ["--verify_replay"] if args.verify_replay else []

    rc = _run([args.python, s_inject,
               "--base", p_master,
               "--tag", "V01_INJECT_SSAU_MASTER",
               "--out_root", inject_root,
               "--inject_counts", "0", "5", "10", "25", "50"] + vr, cwd_root, log_lines)
    ok = ok and (rc == 0)

    p_inj0  = _abspath(os.path.join(inject_root, f"{stamp}__SSAU_INJECT__V01__V01_INJECT_SSAU_MASTER", "INJECT_000000", "alphabet.json"))
    p_inj5  = _abspath(os.path.join(inject_root, f"{stamp}__SSAU_INJECT__V01__V01_INJECT_SSAU_MASTER", "INJECT_000005", "alphabet.json"))
    p_inj10 = _abspath(os.path.join(inject_root, f"{stamp}__SSAU_INJECT__V01__V01_INJECT_SSAU_MASTER", "INJECT_000010", "alphabet.json"))
    p_inj25 = _abspath(os.path.join(inject_root, f"{stamp}__SSAU_INJECT__V01__V01_INJECT_SSAU_MASTER", "INJECT_000025", "alphabet.json"))
    p_inj50 = _abspath(os.path.join(inject_root, f"{stamp}__SSAU_INJECT__V01__V01_INJECT_SSAU_MASTER", "INJECT_000050", "alphabet.json"))

    inj_missing = [p for p in [p_inj0, p_inj5, p_inj10, p_inj25, p_inj50] if not os.path.isfile(p)]
    if inj_missing:
        ok = False
        log_lines.append("MISSING_INJECTION_OUTPUTS:\n" + "\n".join(inj_missing))

    rc = _run([args.python, s_unify,
               "--tag", "V02_UNIFY_MASTER_SSW_CSV",
               "--out_root", unify_root,
               "--inputs", p_master, p_ssw, p_csv,
               "--transitions", "", "", _abspath(os.path.join("outputs", "ssau_csv_extract_out", "transitions.csv"))] + vr, cwd_root, log_lines)
    ok = ok and (rc == 0)

    rc = _run([args.python, s_unify,
               "--tag", "V02_UNIFY_MASTER_PLUS_INJECT50",
               "--out_root", unify_root,
               "--inputs", p_master, p_inj50,
               "--transitions", "", ""] + vr, cwd_root, log_lines)
    ok = ok and (rc == 0)

    d_unify_msc = _pick_run_dir(unify_root, "V02_UNIFY_MASTER_SSW_CSV")
    d_unify_inj = _pick_run_dir(unify_root, "V02_UNIFY_MASTER_PLUS_INJECT50")

    p_unified_msc = os.path.join(d_unify_msc, "ssau_unified_alphabet.json") if d_unify_msc else ""
    p_unified_inj = os.path.join(d_unify_inj, "ssau_unified_alphabet.json") if d_unify_inj else ""

    if not (p_unified_msc and os.path.isfile(p_unified_msc)):
        ok = False
        log_lines.append("MISSING_UNIFIED_ALPHABET: MASTER_SSW_CSV")
    if not (p_unified_inj and os.path.isfile(p_unified_inj)):
        ok = False
        log_lines.append("MISSING_UNIFIED_ALPHABET: MASTER_PLUS_INJECT50")

    rc = _run([args.python, s_srs,
               "--tag", "V01_SRS_CURVE_MASTER_PLUS_SSW_PLUS_CSV",
               "--out_root", srs_root,
               "--inputs", p_master, p_ssw, p_csv, p_unified_msc] + vr, cwd_root, log_lines)
    ok = ok and (rc == 0)

    rc = _run([args.python, s_srs,
               "--tag", "V01_SRS_CURVE_MASTER_PLUS_INJECT50_UNIFIED",
               "--out_root", srs_root,
               "--inputs", p_master, p_inj50, p_unified_inj] + vr, cwd_root, log_lines)
    ok = ok and (rc == 0)

    rc = _run([args.python, s_rit,
               "--tag", "V04_RIT_MASTER_SSW_CSV_TERMINAL",
               "--out_root", rit_root,
               "--unified", p_unified_msc,
               "--inputs", p_master, p_ssw, p_csv] + vr, cwd_root, log_lines)
    ok = ok and (rc == 0)

    rc = _run([args.python, s_rit,
               "--tag", "V04_RIT_MASTER_PLUS_INJECT50_TERMINAL",
               "--out_root", rit_root,
               "--unified", p_unified_inj,
               "--inputs", p_master, p_inj50] + vr, cwd_root, log_lines)
    ok = ok and (rc == 0)

    rc = _run([args.python, s_scm,
               "--tag", "V01_SCM_FROM_TEST_SERIES",
               "--out_root", scm_root] + vr, cwd_root, log_lines)
    ok = ok and (rc == 0)

    rc = _run([args.python, s_lattice,
               "--tag", "V01_CORE_CROSS_DOMAIN",
               "--out_root", lattice_root,
               "--alphabet", p_master,
               "--alphabet", p_ssw,
               "--alphabet", p_csv] + vr, cwd_root, log_lines)
    ok = ok and (rc == 0)

    rc = _run([args.python, s_lattice,
               "--tag", "V01_INJECTION_CURVE",
               "--out_root", lattice_root,
               "--alphabet", p_inj0,
               "--alphabet", p_inj5,
               "--alphabet", p_inj10,
               "--alphabet", p_inj25,
               "--alphabet", p_inj50] + vr, cwd_root, log_lines)
    ok = ok and (rc == 0)

    idx = {
        "run_tag": master_tag,
        "run_dir": run_dir,
        "created_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verify_replay": bool(args.verify_replay),
        "components": []
    }

    def add_component(name, out_dir, extra=None):
        item = {
            "component": name,
            "out_dir": out_dir,
            "manifest_sha256": _read_manifest_sha(out_dir) if out_dir else "",
            "sha256_of_manifest_file": _read_manifest_sha(out_dir) if out_dir else "",
        }
        if extra:
            item.update(extra)
        idx["components"].append(item)

    d_lattice_core_a = os.path.join(lattice_root, "REPLAY_A__SSAU_LATTICE_COMPRESS__V01__V01_CORE_CROSS_DOMAIN")
    d_lattice_inj_a  = os.path.join(lattice_root, "REPLAY_A__SSAU_LATTICE_COMPRESS__V01__V01_INJECTION_CURVE")

    lattice_metrics = []
    for d in [d_lattice_core_a, d_lattice_inj_a]:
        s = os.path.join(d, "summary.txt")
        if os.path.isfile(s):
            lattice_metrics.append({"out_dir": d, "inputs": _parse_lattice_summary(s)})

    add_component("INJECT", _pick_run_dir(inject_root, "__SSAU_INJECT__V01__V01_INJECT_SSAU_MASTER"))
    add_component("UNIFY_MASTER_SSW_CSV", d_unify_msc)
    add_component("UNIFY_MASTER_PLUS_INJECT50", d_unify_inj)
    add_component("SRS_CURVE_MSC", _pick_run_dir(srs_root, "V01_SRS_CURVE_MASTER_PLUS_SSW_PLUS_CSV"))
    add_component("SRS_CURVE_INJ50", _pick_run_dir(srs_root, "V01_SRS_CURVE_MASTER_PLUS_INJECT50_UNIFIED"))
    add_component("RIT_MSC", _pick_run_dir(rit_root, "V04_RIT_MASTER_SSW_CSV_TERMINAL"))
    add_component("RIT_INJ50", _pick_run_dir(rit_root, "V04_RIT_MASTER_PLUS_INJECT50_TERMINAL"))
    add_component("SCM", _pick_run_dir(scm_root, "V01_SCM_FROM_TEST_SERIES"))
    add_component("LATTICE_CORE_CROSS_DOMAIN", d_lattice_core_a, {"metrics": lattice_metrics[0]["inputs"] if lattice_metrics else []})
    add_component("LATTICE_INJECTION_CURVE", d_lattice_inj_a, {"metrics": lattice_metrics[1]["inputs"] if len(lattice_metrics) > 1 else []})

    idx["components"].sort(key=lambda x: x["component"])

    _write_json(os.path.join(run_dir, "verification_index.json"), idx)

    csv_path = os.path.join(run_dir, "verification_index.csv")
    with open(csv_path, "w", encoding="utf-8", newline="\n") as f:
        w = csv.writer(f)
        w.writerow(["component", "out_dir", "sha256_of_manifest_file"])
        for c in idx["components"]:
            w.writerow([c["component"], c["out_dir"], c["sha256_of_manifest_file"]])

    status = "PASS" if ok else "FAIL"
    _write_text(os.path.join(run_dir, "summary.txt"), status + "\n")

    _write_text(os.path.join(run_dir, "runlog.txt"), "\n\n".join(log_lines).strip() + "\n")

    mf_items = []
    for fn in ["summary.txt", "runlog.txt", "verification_index.json", "verification_index.csv"]:
        p = os.path.join(run_dir, fn)
        if os.path.isfile(p):
            mf_items.append((fn, _sha256_file(p)))
    mf_items.sort()
    mf_path = os.path.join(run_dir, "MANIFEST.sha256")
    with open(mf_path, "w", encoding="utf-8", newline="\n") as f:
        for rel, h in mf_items:
            f.write(h + "  " + rel + "\n")

    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
