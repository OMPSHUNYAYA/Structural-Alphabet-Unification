#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import hashlib
import json
import math
import os
import shutil
import sys
from typing import Any, Dict, List, Tuple, Set

VERSION = "v0.1"
ENGINE_TAG = "SSAU_SRS__V01"


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
    name = f"{ts}__SSAU_SRS__V01__{tag}"
    run_dir = os.path.join(out_root, name)
    ensure_dir(run_dir)
    return run_dir


def parse_sigma(s: str) -> Tuple[str, str]:
    s = (s or "").strip()
    if ":" in s:
        a, b = s.split(":", 1)
        return a.strip(), b.strip()
    return "", s


def unify_key(role: str, core: str) -> str:
    role = (role or "").strip().upper()
    core = (core or "").strip().upper()
    return f"{role}:{core}" if role else core.upper()


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise ValueError("invalid json root")
    return obj


def symbols_from_input(obj: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()

    # SSAU extract format: {"alphabet": [ {"sigma": "...", "role": "...", ...}, ... ]}
    if "alphabet" in obj and isinstance(obj["alphabet"], list):
        for ent in obj["alphabet"]:
            if not isinstance(ent, dict):
                continue
            sigma = (ent.get("sigma", "") or "").strip()
            role = (ent.get("role", "") or "").strip()
            _, core = parse_sigma(sigma)
            k = unify_key(role, core)
            if k:
                out.add(k.upper())
        return out

    # SSAU unify format: {"unified_alphabet": [...]}
    if "unified_alphabet" in obj and isinstance(obj["unified_alphabet"], list):
        ua = obj["unified_alphabet"]

        # Case 1: list of strings (older/simple schema)
        if ua and isinstance(ua[0], str):
            for s in ua:
                if not isinstance(s, str):
                    continue
                k = (s or "").strip().upper()
                if k:
                    out.add(k)
            return out

        # Case 2: list of objects (your current schema) with u_sigma / role+core
        if ua and isinstance(ua[0], dict):
            for ent in ua:
                if not isinstance(ent, dict):
                    continue

                u = (ent.get("u_sigma", "") or "").strip()
                if u:
                    out.add(u.upper())
                    continue

                role = (ent.get("role", "") or "").strip()
                core = (ent.get("core", "") or "").strip()
                k = unify_key(role, core)
                if k:
                    out.add(k.upper())

            return out

        return out

    raise ValueError("unsupported input format (need alphabet[] or unified_alphabet[])")


def compute_growth(inputs: List[Tuple[str, str]]) -> Tuple[List[List[Any]], Dict[str, Any]]:
    srs_total: Set[str] = set()
    rows: List[List[Any]] = []

    for i, (nm, path) in enumerate(inputs, start=1):
        obj = load_json(path)
        sym = symbols_from_input(obj)

        before = len(srs_total)
        srs_total |= sym
        after = len(srs_total)
        delta = after - before

        h_total = math.log(after) if after > 0 else 0.0
        h_step = math.log(len(sym)) if len(sym) > 0 else 0.0

        rows.append([
            i,
            nm,
            os.path.normpath(path).replace("\\", "/"),
            len(sym),
            after,
            delta,
            f"{h_step:.9f}",
            f"{h_total:.9f}",
        ])

    out_obj = {
        "engine": ENGINE_TAG,
        "version": VERSION,
        "contract": "srs_growth_curve",
        "invariant": "phi((m,a,s)) = m",
        "formulae": {
            "H_struct(D)": "log(|SRS(D)|)",
            "H_unified": "log(|SRS(D1 ∪ D2)|)"
        },
        "counts": {
            "steps": len(inputs),
            "final_srs_size": len(srs_total)
        },
        "final_srs_sorted": sorted(list(srs_total))
    }

    return rows, out_obj


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", nargs="+", required=True, help="List of alphabet.json and/or ssau_unified_alphabet.json paths.")
    ap.add_argument("--names", nargs="*", default=[], help="Optional names for inputs; must match length of --inputs if provided.")
    ap.add_argument("--tag", type=str, default="V01_SRS_CURVE", help="Run tag.")
    ap.add_argument("--out_root", type=str, default=os.path.join("outputs", "ssau_srs_out"), help="Output root.")
    ap.add_argument("--verify_replay", action="store_true")
    args = ap.parse_args()

    tag = (args.tag or "").strip()
    if not tag:
        print("ERROR: empty --tag", file=sys.stderr)
        return 2

    in_paths = args.inputs
    if args.names and (len(args.names) != len(in_paths)):
        print("ERROR: --names length must match --inputs length", file=sys.stderr)
        return 2

    def run_once(replay_label: str, fixed_ts: str) -> str:
        os.environ["SSAU_FIXED_TS"] = fixed_ts
        run_dir = safe_run_dir(args.out_root, tag)
        del os.environ["SSAU_FIXED_TS"]

        inputs: List[Tuple[str, str]] = []
        for i, p in enumerate(in_paths):
            nm = args.names[i] if args.names else f"S{i+1}"
            inputs.append((nm, p))

        rows, out_obj = compute_growth(inputs)

        header = [
            "step",
            "name",
            "input_path",
            "symbols_in_input",
            "srs_total_size",
            "delta_added",
            "H_struct_input_log",
            "H_struct_total_log",
        ]
        write_csv(os.path.join(run_dir, "srs_growth_curve.csv"), header, rows)

        out_obj2 = dict(out_obj)
        out_obj2["tag"] = tag
        out_obj2["replay"] = replay_label
        write_json(os.path.join(run_dir, "srs_final.json"), out_obj2)

        summary: List[str] = []
        summary.append(f"SSAU SRS Growth Curve {VERSION}")
        summary.append(f"engine={ENGINE_TAG}")
        summary.append(f"tag={tag}")
        summary.append(f"replay={replay_label}")
        summary.append(f"steps={out_obj['counts']['steps']}")
        summary.append(f"final_srs_size={out_obj['counts']['final_srs_size']}")
        summary.append("formula: H_struct(D) = log(|SRS(D)|)")
        write_text(os.path.join(run_dir, "summary.txt"), "\n".join(summary) + "\n")

        manifest_files = ["srs_growth_curve.csv", "srs_final.json", "summary.txt"]
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
        print("OK: SSAU SRS growth curve v0.1 complete")
        print(f"Output folder: {os.path.dirname(a_dir)}")
        return 0

    run_dir = run_once("RUN", "")
    print("OK: SSAU SRS growth curve v0.1 complete")
    print(f"Output folder: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
