#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSAU Adapter v0.2 — SSP Trace -> SSAU Timeline
Deterministic conversion of SSP artifacts into SSAU CAS-1 timeline.csv

Input (SSP):
  ssp_trace.csv columns typically:
    step, layer, event, x, gate

Output (SSAU):
  timeline.csv columns:
    idx, t, sigma, src_step, src_layer, src_event, src_gate, note

Hard guarantees:
  - No randomness
  - Stable CSV output across platforms (newline="\n", lineterminator="\n")
  - Optional --verify_replay creates REPLAY_A and REPLAY_B and compares bytes

Contract:
  - CAS-1 timeline with sigma labels suitable for ssau_extract_alphabet_v0_2.py
  - Preserves "observation-only" nature: it does not modify SSP logic, only maps it.
"""

import argparse
import csv
import hashlib
import os
import shutil
import sys
from typing import Dict, List, Tuple

VERSION = "v0.2"
ENGINE_TAG = "SSAU_ADAPTER_SSP__V02"


# ----------------------------
# Utilities
# ----------------------------

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def rm_tree(path: str) -> None:
    if os.path.isdir(path):
        shutil.rmtree(path)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def write_csv(path: str, header: List[str], rows: List[List[str]]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        for r in rows:
            w.writerow(r)

def write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)

def stable_relpaths(root: str) -> List[str]:
    rels: List[str] = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            rels.append(rel)
    rels.sort()
    return rels

def compare_trees(a_root: str, b_root: str) -> Tuple[bool, str]:
    a_files = stable_relpaths(a_root)
    b_files = stable_relpaths(b_root)
    if a_files != b_files:
        return False, "file list mismatch"
    for rel in a_files:
        ap = os.path.join(a_root, rel.replace("/", os.sep))
        bp = os.path.join(b_root, rel.replace("/", os.sep))
        with open(ap, "rb") as fa:
            ab = fa.read()
        with open(bp, "rb") as fb:
            bb = fb.read()
        if ab != bb:
            return False, f"byte mismatch at {rel}"
    return True, "OK"

def write_manifest(out_dir: str, files: List[str]) -> None:
    lines = ["MANIFEST_SHA256"]
    for fn in files:
        p = os.path.join(out_dir, fn)
        lines.append(f"{fn}  {sha256_file(p)}")
    write_text(os.path.join(out_dir, "MANIFEST.sha256"), "\n".join(lines) + "\n")


# ----------------------------
# Mapping: SSP row -> SSAU sigma
# ----------------------------

def pick_sigma(layer: str, event: str, gate: str) -> Tuple[str, str]:
    """
    Returns: (sigma, note)
    sigma vocabulary mirrors SSAU demo's style:
      L0:STABLE, L1:DRIFT, L2:THRESH, L3:META, L4:CROSS, L5:RECOVER, L6:IRREV, L7:DENY
    """

    L = (layer or "").strip().upper()
    E = (event or "").strip().upper()
    G = (gate or "").strip().upper()

    # Highest priority: explicit deny
    if G == "DENY" or "DENY" in E:
        return "L7:DENY", "gate_or_event_deny"

    # Cross / inadmissible posture-like events
    if "CROSS" in E or L == "X" or "INADMISS" in E:
        return "L4:CROSS", "cross_or_inadmissible"

    # Meta layer / meta events
    if "META" in E or L == "M":
        return "L3:META", "meta"

    # Threshold / restricted boundary events
    if "THRESH" in E or L == "T" or "RESTRICT" in E:
        return "L2:THRESH", "threshold_or_restricted"

    # Drift / unstable but allowed movement
    if "DRIFT" in E or L == "D":
        return "L1:DRIFT", "drift"

    # Recover (if you later add recover events in SSP)
    if "RECOVER" in E or L == "R":
        return "L5:RECOVER", "recover"

    # Irreversible (optional future SSP event type)
    if "IRREV" in E or L == "I":
        return "L6:IRREV", "irreversible"

    # Default stable
    return "L0:STABLE", "default_stable"


def read_ssp_trace(in_csv: str) -> List[Dict[str, str]]:
    with open(in_csv, "r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        need = ["step", "layer", "event", "gate"]
        for k in need:
            if k not in (r.fieldnames or []):
                raise SystemExit(f"ERROR: SSP trace missing required column '{k}'. Found: {r.fieldnames}")
        rows: List[Dict[str, str]] = []
        for row in r:
            rows.append({
                "step": (row.get("step") or "").strip(),
                "layer": (row.get("layer") or "").strip(),
                "event": (row.get("event") or "").strip(),
                "gate": (row.get("gate") or "").strip(),
            })
        return rows


def build_timeline(ssp_rows: List[Dict[str, str]]) -> List[List[str]]:
    out: List[List[str]] = []
    idx = 0
    for row in ssp_rows:
        sigma, note = pick_sigma(row["layer"], row["event"], row["gate"])
        # SSAU expects a timeline notion of t; we map t := SSP step (string preserved)
        t = row["step"]
        out.append([
            str(idx),
            t,
            sigma,
            row["step"],
            row["layer"],
            row["event"],
            row["gate"],
            note
        ])
        idx += 1
    return out


def run_once(out_dir: str, in_csv: str, tag: str) -> None:
    ensure_dir(out_dir)

    ssp_rows = read_ssp_trace(in_csv)
    timeline_rows = build_timeline(ssp_rows)

    header = ["idx", "t", "sigma", "src_step", "src_layer", "src_event", "src_gate", "note"]
    write_csv(os.path.join(out_dir, "timeline.csv"), header, timeline_rows)

    summary = []
    summary.append(f"SSAU Adapter SSP {VERSION}")
    summary.append(f"engine={ENGINE_TAG}")
    summary.append(f"tag={tag}")
    summary.append(f"in_csv={in_csv}")
    summary.append(f"rows_in={len(ssp_rows)}")
    summary.append(f"rows_out={len(timeline_rows)}")
    summary.append(f"sigma_col=sigma")
    write_text(os.path.join(out_dir, "summary.txt"), "\n".join(summary) + "\n")

    write_manifest(out_dir, ["timeline.csv", "summary.txt"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_csv", required=True, help="Path to SSP ssp_trace.csv")
    ap.add_argument("--tag", default="V02_ADAPTER", help="Run tag")
    ap.add_argument("--out_root", default=os.path.join("outputs", "ssau_adapter_out"))
    ap.add_argument("--verify_replay", action="store_true")
    args = ap.parse_args()

    tag = (args.tag or "").strip()
    if not tag:
        print("ERROR: empty --tag", file=sys.stderr)
        return 2

    out_root = args.out_root
    ensure_dir(out_root)

    if args.verify_replay:
        a_dir = os.path.join(out_root, f"REPLAY_A__{ENGINE_TAG}__{tag}")
        b_dir = os.path.join(out_root, f"REPLAY_B__{ENGINE_TAG}__{tag}")
        rm_tree(a_dir)
        rm_tree(b_dir)

        run_once(a_dir, args.in_csv, tag)
        run_once(b_dir, args.in_csv, tag)

        ok, why = compare_trees(a_dir, b_dir)
        if not ok:
            print(f"VERIFY_REPLAY: FAIL ({why})")
            return 1

        print("VERIFY_REPLAY: PASS (all artifacts byte-identical across REPLAY_A and REPLAY_B)")
        print(f"OK: SSAU adapter SSP {VERSION} complete")
        print(f"Output folder: {out_root}")
        return 0

    # Non-replay: single deterministic output folder (still deterministic; no timestamping)
    run_dir = os.path.join(out_root, f"RUN__{ENGINE_TAG}__{tag}")
    rm_tree(run_dir)
    run_once(run_dir, args.in_csv, tag)

    print(f"OK: SSAU adapter SSP {VERSION} complete")
    print(f"Output folder: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
