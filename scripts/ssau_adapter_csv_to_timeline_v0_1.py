#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import hashlib
import os
import shutil
import sys
from typing import List, Tuple, Optional

VERSION = "v0.1"
ENGINE_TAG = "SSAU_ADAPTER_CSV__V01"

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

def write_csv(path: str, header: List[str], rows: List[List[str]]) -> None:
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
        h = sha256_file(p)
        rows.append(f"{fn}  {h}")
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
    name = f"{ts}__SSAU_ADAPTER_CSV__V01__{tag}"
    run_dir = os.path.join(out_root, name)
    ensure_dir(run_dir)
    return run_dir

def parse_float(s: str) -> Optional[float]:
    s = (s or "").strip()
    if s == "":
        return None
    try:
        return float(s)
    except Exception:
        return None

def sign(delta: float) -> int:
    if delta > 0.0:
        return 1
    if delta < 0.0:
        return -1
    return 0

def regime_from_triplet(prev_d: int, d: int, next_d: int) -> str:
    if d == 0:
        return "C:STABLE"
    if prev_d == 0 and d != 0:
        return "X:CROSS"
    if prev_d == 1 and d == 1 and next_d == 1:
        return "D:DRIFT_UP"
    if prev_d == -1 and d == -1 and next_d == -1:
        return "D:DRIFT_DOWN"
    if (prev_d == 1 and d == -1) or (prev_d == -1 and d == 1):
        return "M:TURN"
    if d == 1:
        return "D:UP"
    return "D:DOWN"

def build_timeline(rows: List[Tuple[str, float]]) -> List[List[str]]:
    if len(rows) < 2:
        raise ValueError("need at least 2 rows")

    idx = [r[0] for r in rows]
    val = [r[1] for r in rows]

    deltas: List[int] = []
    for i in range(1, len(val)):
        deltas.append(sign(val[i] - val[i-1]))

    deltas2: List[int] = [deltas[0]] + deltas + [deltas[-1]]

    out: List[List[str]] = []
    s_acc = 0
    for i in range(1, len(idx)):
        prev_d = deltas2[i-1]
        d = deltas2[i]
        next_d = deltas2[i+1]
        sigma = regime_from_triplet(prev_d, d, next_d)

        a = "ALLOW"
        if sigma.startswith("M:"):
            a = "ALLOW_RESTRICTED"

        if sigma != "C:STABLE":
            s_acc += 1

        out.append([
            str(i),
            idx[i],
            f"{val[i]:.12g}",
            sigma,
            a,
            str(s_acc),
        ])
    return out

def read_csv_series(path: str, col: str, idx_col: str) -> List[Tuple[str, float]]:
    out: List[Tuple[str, float]] = []
    with open(path, "r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        if r.fieldnames is None:
            raise ValueError("csv has no header")
        if col not in r.fieldnames:
            raise ValueError(f"missing column: {col}")
        if idx_col not in r.fieldnames:
            raise ValueError(f"missing index column: {idx_col}")
        for row in r:
            x = parse_float(row.get(col, ""))
            if x is None:
                continue
            idx = (row.get(idx_col, "") or "").strip()
            if idx == "":
                idx = str(len(out))
            out.append((idx, x))
    if len(out) < 2:
        raise ValueError("not enough numeric rows after filtering")
    return out

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--col", required=True)
    ap.add_argument("--index_col", default="t")
    ap.add_argument("--tag", default="V01_CSV_TIMELINE")
    ap.add_argument("--out_root", default=os.path.join("outputs", "ssau_csv_adapter_out"))
    ap.add_argument("--verify_replay", action="store_true")
    args = ap.parse_args()

    tag = (args.tag or "").strip()
    if not tag:
        print("ERROR: empty --tag", file=sys.stderr)
        return 2

    def run_once(replay_label: str, fixed_ts: str) -> str:
        os.environ["SSAU_FIXED_TS"] = fixed_ts
        run_dir = safe_run_dir(args.out_root, tag)
        del os.environ["SSAU_FIXED_TS"]

        series = read_csv_series(args.csv, args.col, args.index_col)
        timeline = build_timeline(series)

        header = ["i", "t", "m", "sigma", "a", "s"]
        write_csv(os.path.join(run_dir, "timeline.csv"), header, timeline)

        summary = []
        summary.append(f"SSAU CSV Adapter {VERSION}")
        summary.append(f"engine={ENGINE_TAG}")
        summary.append(f"tag={tag}")
        summary.append(f"replay={replay_label}")
        summary.append(f"csv={os.path.normpath(args.csv).replace('\\', '/')}")
        summary.append(f"col={args.col}")
        summary.append(f"index_col={args.index_col}")
        summary.append("invariant: phi((m,a,s)) = m")
        summary.append("note: observation-only; no prediction; no simulation")
        write_text(os.path.join(run_dir, "summary.txt"), "\n".join(summary) + "\n")

        manifest_files = ["timeline.csv", "summary.txt"]
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
        print("OK: SSAU CSV adapter v0.1 complete")
        print(f"Output folder: {os.path.dirname(a_dir)}")
        return 0

    run_dir = run_once("RUN", "")
    print("OK: SSAU CSV adapter v0.1 complete")
    print(f"Output folder: {run_dir}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
