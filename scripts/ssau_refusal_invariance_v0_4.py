#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Tuple


VERSION = "v0.4"
ENGINE_TAG = "SSAU_RIT__V04"

TERMINALS = {"DENY", "ABSTAIN"}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def write_csv(path: str, header: List[str], rows: List[List[Any]]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        for r in rows:
            w.writerow(r)


def write_json(path: str, obj: Any) -> None:
    s = json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2)
    write_text(path, s + "\n")


def write_manifest(run_dir: str, files: List[str]) -> None:
    lines: List[str] = []
    lines.append("MANIFEST_SHA256")
    for fn in files:
        p = os.path.join(run_dir, fn)
        lines.append(f"{fn}  {sha256_file(p)}")
    write_text(os.path.join(run_dir, "MANIFEST.sha256"), "\n".join(lines) + "\n")


def compare_trees(a_dir: str, b_dir: str) -> Tuple[bool, str]:
    def list_files(root: str) -> List[str]:
        out: List[str] = []
        for base, _, files in os.walk(root):
            rel_base = os.path.relpath(base, root)
            for fn in files:
                rel = fn if rel_base == "." else os.path.join(rel_base, fn)
                out.append(rel.replace("\\", "/"))
        out.sort()
        return out

    a_files = list_files(a_dir)
    b_files = list_files(b_dir)
    if a_files != b_files:
        return False, "file list mismatch"

    for rel in a_files:
        ap = os.path.join(a_dir, rel.replace("/", os.sep))
        bp = os.path.join(b_dir, rel.replace("/", os.sep))
        with open(ap, "rb") as fa:
            ab = fa.read()
        with open(bp, "rb") as fb:
            bb = fb.read()
        if ab != bb:
            return False, f"bytes mismatch: {rel}"
    return True, "ok"


def safe_run_dir(out_root: str, tag: str) -> str:
    ensure_dir(out_root)
    ts = os.environ.get("SSAU_FIXED_TS", "").strip()
    if not ts:
        import datetime
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"{ts}__SSAU_RIT__V04__{tag}"
    run_dir = os.path.join(out_root, name)
    ensure_dir(run_dir)
    return run_dir


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise ValueError("invalid json root")
    return obj


def _parts(s: str) -> List[str]:
    return [p.strip() for p in (s or "").split(":") if p.strip()]


def canonical_refusal_key(key: str) -> str:
    """
    Canonical key for refusal invariance:
    - If the *terminal token* is DENY/ABSTAIN, collapse to ROLE:TERMINAL.
    - Else, fall back to a conservative uppercase normalization.
    Examples:
      N:U:N:DENY -> N:DENY
      A:U:A:ABSTAIN -> A:ABSTAIN
      N:N:DENY -> N:DENY
    """
    s = (key or "").strip()
    if not s:
        return ""
    parts = _parts(s)
    if len(parts) == 0:
        return ""
    if len(parts) == 1:
        return parts[0].upper()

    role = parts[0].upper()
    tail = parts[-1].upper()

    if tail in TERMINALS:
        return f"{role}:{tail}"

    return ":".join([p.upper() for p in parts])


def input_key(role: str, sigma: str) -> str:
    role_u = (role or "").strip().upper()
    sigma_s = (sigma or "").strip()
    if not sigma_s:
        return ""
    sigma_u = sigma_s.upper()
    if role_u and sigma_u.startswith(role_u + ":"):
        return sigma_u
    if role_u:
        return (role_u + ":" + sigma_u)
    return sigma_u


def extract_refusals_from_unified(unified_obj: Dict[str, Any]) -> Dict[str, str]:
    refusals: Dict[str, str] = {}
    ua = unified_obj.get("unified_alphabet", None)
    if not isinstance(ua, list):
        raise ValueError("expected unified_alphabet[] in unified json")

    for ent in ua:
        if not isinstance(ent, dict):
            continue
        u_sigma = (ent.get("u_sigma", "") or "").strip()
        decision = (ent.get("decision", "") or "").strip().upper()
        if not u_sigma:
            continue
        if decision in TERMINALS:
            refusals[canonical_refusal_key(u_sigma)] = decision
    return refusals


def extract_refusals_from_alphabet(alpha_obj: Dict[str, Any]) -> Dict[str, str]:
    refusals: Dict[str, str] = {}
    a = alpha_obj.get("alphabet", None)
    if not isinstance(a, list):
        raise ValueError("expected alphabet[] in alphabet.json")

    for ent in a:
        if not isinstance(ent, dict):
            continue
        sigma = (ent.get("sigma", "") or "").strip()
        role = (ent.get("role", "") or "").strip()
        decision = (ent.get("decision", "") or "").strip().upper()

        k_raw = input_key(role, sigma)
        if not k_raw:
            continue
        if decision in TERMINALS:
            refusals[canonical_refusal_key(k_raw)] = decision
    return refusals


def check_invariance(input_refusals: Dict[str, str], unified_refusals: Dict[str, str]) -> Tuple[bool, List[str]]:
    missing: List[str] = []
    for k, dec in input_refusals.items():
        if k not in unified_refusals:
            missing.append(f"{k} ({dec})")
    return (len(missing) == 0), missing


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--unified", required=True, help="Path to ssau_unified_alphabet.json")
    ap.add_argument("--inputs", nargs="*", default=[], help="Optional input alphabet.json paths.")
    ap.add_argument("--names", nargs="*", default=[], help="Optional names for inputs; must match length of --inputs if provided.")
    ap.add_argument("--tag", type=str, default="V04_RIT", help="Run tag.")
    ap.add_argument("--out_root", type=str, default=os.path.join("outputs", "ssau_rit_out"), help="Output root.")
    ap.add_argument("--verify_replay", action="store_true")
    args = ap.parse_args()

    tag = (args.tag or "").strip()
    if not tag:
        print("ERROR: empty --tag", file=sys.stderr)
        return 2

    if args.names and (len(args.names) != len(args.inputs)):
        print("ERROR: --names length must match --inputs length", file=sys.stderr)
        return 2

    unified_path = args.unified

    def run_once(replay_label: str, fixed_ts: str) -> str:
        if fixed_ts:
            os.environ["SSAU_FIXED_TS"] = fixed_ts
        else:
            os.environ.pop("SSAU_FIXED_TS", None)

        run_dir = safe_run_dir(args.out_root, tag)

        if fixed_ts:
            os.environ.pop("SSAU_FIXED_TS", None)

        unified_obj = load_json(unified_path)
        unified_ref = extract_refusals_from_unified(unified_obj)

        rows: List[List[Any]] = []
        checks: List[Dict[str, Any]] = []

        for k in sorted(unified_ref.keys()):
            rows.append(["UNIFIED", k, unified_ref[k], "present_in_unified", "YES"])

        for i, p in enumerate(args.inputs):
            nm = args.names[i] if args.names else f"INPUT_{i+1}"
            alpha_obj = load_json(p)
            in_ref = extract_refusals_from_alphabet(alpha_obj)

            ok, missing = check_invariance(in_ref, unified_ref)
            checks.append({
                "name": nm,
                "path": os.path.normpath(p).replace("\\", "/"),
                "refusals_in_input": len(in_ref),
                "missing_in_unified_canonical": missing,
                "pass_canonical_invariance": bool(ok),
                "canonical_rule": "ROLE:TERMINAL for terminal in {DENY,ABSTAIN}",
            })

            for k in sorted(in_ref.keys()):
                rows.append([nm, k, in_ref[k], "present_in_unified_canonical", "YES" if k in unified_ref else "NO"])

        out_obj = {
            "engine": ENGINE_TAG,
            "version": VERSION,
            "contract": "refusal_invariance_test",
            "invariant": "phi((m,a,s)) = m",
            "rule": "R(Ai) subseteq R(U) using canonical ROLE:TERMINAL for terminal refusals",
            "unified_refusal_count": len(unified_ref),
            "input_checks": checks,
        }

        header = ["source", "sigma_key_canonical", "decision", "check", "result"]
        write_csv(os.path.join(run_dir, "rit_refusal_checks.csv"), header, rows)
        write_json(os.path.join(run_dir, "rit_summary.json"), out_obj)

        summary_lines: List[str] = []
        summary_lines.append(f"SSAU Refusal Invariance Test {VERSION}")
        summary_lines.append(f"engine={ENGINE_TAG}")
        summary_lines.append(f"tag={tag}")
        summary_lines.append(f"replay={replay_label}")
        summary_lines.append(f"unified_refusal_count={len(unified_ref)}")
        if checks:
            for c in checks:
                summary_lines.append(f"input={c['name']} pass_canonical_invariance={c['pass_canonical_invariance']} refusals_in_input={c['refusals_in_input']}")
                if c["missing_in_unified_canonical"]:
                    summary_lines.append(f"missing={c['missing_in_unified_canonical']}")
        else:
            summary_lines.append("inputs=NONE (unified refusal inventory only)")
        write_text(os.path.join(run_dir, "summary.txt"), "\n".join(summary_lines) + "\n")

        manifest_files = ["rit_refusal_checks.csv", "rit_summary.json", "summary.txt"]
        write_manifest(run_dir, manifest_files)
        return run_dir

    if args.verify_replay:
        a_dir = run_once("REPLAY_A", "20000101_000000")
        b_dir = run_once("REPLAY_B", "20000101_000000")
        ok, why = compare_trees(a_dir, b_dir)
        if not ok:
            print(f"VERIFY_REPLAY: FAIL ({why})", file=sys.stderr)
            return 1
        print("VERIFY_REPLAY: PASS (all artifacts byte-identical across REPLAY_A and REPLAY_B)")
        print("OK: SSAU refusal invariance test v0.4 complete")
        print(f"Output folder: {os.path.dirname(a_dir)}")
        return 0

    run_dir = run_once("RUN", "")
    print("OK: SSAU refusal invariance test v0.4 complete")
    print(f"Output folder: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
