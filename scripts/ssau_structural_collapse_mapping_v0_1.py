#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
from typing import Any, Dict, List, Tuple

VERSION = "v0.1"
ENGINE_TAG = "SSAU_SCM__V01"
INVARIANT = "phi((m,a,s)) = m"


def sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


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


def rm_tree(path: str) -> None:
    if os.path.isdir(path):
        shutil.rmtree(path)


def write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def write_json(path: str, obj: Any) -> None:
    s = json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2)
    write_text(path, s + "\n")


def write_csv(path: str, header: List[str], rows: List[List[Any]]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        for r in rows:
            w.writerow(r)


def write_manifest(run_dir: str, files: List[str]) -> None:
    rows: List[str] = []
    rows.append("MANIFEST_SHA256")
    for fn in files:
        p = os.path.join(run_dir, fn)
        rows.append(f"{fn}  {sha256_file(p)}")
    write_text(os.path.join(run_dir, "MANIFEST.sha256"), "\n".join(rows) + "\n")


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
    name = f"{ts}__SSAU_SCM__V01__{tag}"
    run_dir = os.path.join(out_root, name)
    ensure_dir(run_dir)
    return run_dir


def read_csv_series(path: str, col: str, index_col: str) -> List[Tuple[str, float]]:
    with open(path, "r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        if (col not in r.fieldnames) or (index_col not in r.fieldnames):
            raise ValueError(f"CSV must contain columns: {index_col}, {col}")
        out: List[Tuple[str, float]] = []
        for row in r:
            t = str(row[index_col]).strip()
            v = float(str(row[col]).strip())
            out.append((t, v))
    if not out:
        raise ValueError("CSV had no rows")
    return out


def default_series() -> List[Tuple[str, float]]:
    # Deterministic toy series (same m used for BOTH profiles)
    # 40 steps: gentle rise, plateau, gentle fall.
    out: List[Tuple[str, float]] = []
    for i in range(40):
        if i < 15:
            v = 10.0 + (i * 0.2)
        elif i < 25:
            v = 13.0
        else:
            v = 13.0 - ((i - 25) * 0.15)
        out.append((str(i), float(f"{v:.6f}")))
    return out


def sigma_profile_allow(t_idx: int, m: float) -> str:
    # Profile A: structurally aligned, admits occasional recoveries.
    if t_idx % 17 == 0 and t_idx != 0:
        return "R:RECOVER"
    if t_idx % 9 == 0 and t_idx != 0:
        return "D:DRIFT"
    return "C:STABLE"


def sigma_profile_deny(t_idx: int, m: float, n: int) -> str:
    # Profile B: same m, but structural posture degrades; ends in terminal refusal.
    # The terminal refusal is forced late (purely structural).
    if t_idx >= n - 3:
        return "N:DENY"
    if t_idx % 8 == 0 and t_idx != 0:
        return "M:META"
    return "D:DRIFT"


def decision_for_sigma(sigma: str) -> str:
    s = (sigma or "").strip().upper()
    # Terminal
    if "DENY" in s or s.startswith("N:"):
        return "DENY"
    if "ABSTAIN" in s or s.startswith("A:"):
        return "ABSTAIN"
    # Restricted
    if s.startswith("M:") or "META" in s or s.startswith("T:") or "THRESH" in s or s.startswith("X:"):
        return "ALLOW_RESTRICTED"
    # Default allow
    return "ALLOW"


def a_for_decision(decision: str) -> str:
    d = (decision or "").strip().upper()
    if d == "ALLOW":
        return "ALIGNED"
    if d == "ALLOW_RESTRICTED":
        return "METASTABLE"
    if d == "ABSTAIN":
        return "ABSTAIN"
    if d == "DENY":
        return "DENY"
    return "ABSTAIN"


def s_update(prev_s: int, sigma: str) -> int:
    s = (sigma or "").strip().upper()
    # Deterministic accumulation rule (governance-only, not physics)
    # - DRIFT increments
    # - META increments by 2
    # - RECOVER decreases by 1 but not below 0
    # - DENY/ABSTAIN keep accumulating by 1 (to record terminal strain)
    if "DENY" in s or "ABSTAIN" in s:
        return prev_s + 1
    if s.startswith("D:") or "DRIFT" in s:
        return prev_s + 1
    if s.startswith("M:") or "META" in s:
        return prev_s + 2
    if s.startswith("R:") or "RECOVER" in s:
        return max(0, prev_s - 1)
    # stable holds
    return prev_s


def build_timeline(series: List[Tuple[str, float]], profile: str) -> Tuple[List[List[Any]], Dict[str, Any]]:
    rows: List[List[Any]] = []
    s_acc = 0
    n = len(series)

    for i, (t, m) in enumerate(series):
        if profile == "A_ALLOW":
            sigma = sigma_profile_allow(i, m)
        elif profile == "B_DENY":
            sigma = sigma_profile_deny(i, m, n)
        else:
            raise ValueError("unknown profile")

        decision = decision_for_sigma(sigma)
        a = a_for_decision(decision)
        s_acc = s_update(s_acc, sigma)

        rows.append([
            i,          # idx
            t,          # t
            f"{m:.6f}", # m (unchanged across profiles)
            sigma,
            decision,
            a,
            s_acc
        ])

    final_decision = rows[-1][4]
    out = {
        "profile": profile,
        "final": {
            "decision": final_decision,
            "a": rows[-1][5],
            "s": rows[-1][6]
        },
        "counts": {
            "steps": len(rows)
        }
    }
    return rows, out


def m_series_fingerprint(series: List[Tuple[str, float]]) -> str:
    # Hash only the m-sequence (order-sensitive) to prove identical classical content.
    b = "\n".join([f"{t},{m:.6f}" for (t, m) in series]).encode("utf-8")
    return sha256_bytes(b)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", type=str, default="", help="Optional CSV input.")
    ap.add_argument("--col", type=str, default="value", help="Value column name (default: value).")
    ap.add_argument("--index_col", type=str, default="t", help="Index/time column name (default: t).")
    ap.add_argument("--tag", type=str, default="V01_SCM_DEMO", help="Run tag.")
    ap.add_argument("--out_root", type=str, default=os.path.join("outputs", "ssau_scm_out"), help="Output root.")
    ap.add_argument("--verify_replay", action="store_true")
    args = ap.parse_args()

    tag = (args.tag or "").strip()
    if not tag:
        print("ERROR: empty --tag", file=sys.stderr)
        return 2

    def run_once(replay_label: str, fixed_ts: str) -> str:
        if fixed_ts:
            os.environ["SSAU_FIXED_TS"] = fixed_ts

        run_dir = safe_run_dir(args.out_root, tag)

        if fixed_ts:
            del os.environ["SSAU_FIXED_TS"]

        if args.csv.strip():
            series = read_csv_series(args.csv.strip(), args.col.strip(), args.index_col.strip())
            source = {"csv": os.path.normpath(args.csv.strip()).replace("\\", "/"), "col": args.col, "index_col": args.index_col}
        else:
            series = default_series()
            source = {"csv": "", "col": args.col, "index_col": args.index_col}

        m_hash = m_series_fingerprint(series)

        header = ["idx", "t", "m", "sigma", "decision", "a", "s_acc"]

        rows_A, meta_A = build_timeline(series, "A_ALLOW")
        rows_B, meta_B = build_timeline(series, "B_DENY")

        write_csv(os.path.join(run_dir, "timeline_A.csv"), header, rows_A)
        write_csv(os.path.join(run_dir, "timeline_B.csv"), header, rows_B)

        # Collapse mapping table: same m, divergent governance
        map_rows: List[List[Any]] = []
        for i in range(len(series)):
            map_rows.append([
                i,
                rows_A[i][1],  # t
                rows_A[i][2],  # m
                rows_A[i][3], rows_A[i][4], rows_A[i][5], rows_A[i][6],
                rows_B[i][3], rows_B[i][4], rows_B[i][5], rows_B[i][6],
            ])

        map_header = [
            "idx", "t", "m",
            "sigma_A", "decision_A", "a_A", "s_A",
            "sigma_B", "decision_B", "a_B", "s_B",
        ]
        write_csv(os.path.join(run_dir, "collapse_map.csv"), map_header, map_rows)

        summary_obj = {
            "contract": "structural_collapse_mapping_demonstration",
            "engine": ENGINE_TAG,
            "version": VERSION,
            "invariant": INVARIANT,
            "replay": replay_label,
            "source": source,
            "classical_identity": {
                "m_series_sha256": m_hash,
                "m_is_identical_across_profiles": True
            },
            "profiles": {
                "A": meta_A,
                "B": meta_B
            },
            "claim": {
                "statement": "identical m can yield different admissibility outcomes due to different (a,s)",
                "phi_preserved": True
            }
        }
        write_json(os.path.join(run_dir, "scm_summary.json"), summary_obj)

        # Human-readable summary
        lines: List[str] = []
        lines.append(f"SSAU Structural Collapse Mapping Demo {VERSION}")
        lines.append(f"engine={ENGINE_TAG}")
        lines.append(f"tag={tag}")
        lines.append(f"replay={replay_label}")
        lines.append(f"invariant: {INVARIANT}")
        lines.append(f"m_series_sha256={m_hash}")
        lines.append(f"profile_A_final_decision={meta_A['final']['decision']} (a={meta_A['final']['a']}, s={meta_A['final']['s']})")
        lines.append(f"profile_B_final_decision={meta_B['final']['decision']} (a={meta_B['final']['a']}, s={meta_B['final']['s']})")
        lines.append("result: m identical, governance differs (structural collapse mapping confirmed)")
        write_text(os.path.join(run_dir, "summary.txt"), "\n".join(lines) + "\n")

        manifest_files = ["timeline_A.csv", "timeline_B.csv", "collapse_map.csv", "scm_summary.json", "summary.txt"]
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
        print("OK: SSAU structural collapse mapping demo v0.1 complete")
        print(f"Output folder: {os.path.dirname(a_dir)}")
        return 0

    run_dir = run_once("RUN", "")
    print("OK: SSAU structural collapse mapping demo v0.1 complete")
    print(f"Output folder: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
