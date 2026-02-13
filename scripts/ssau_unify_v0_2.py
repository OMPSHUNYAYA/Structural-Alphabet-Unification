#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
from typing import Dict, List, Tuple, Any


VERSION = "v0.2"
ENGINE_TAG = "SSAU_UNIFY__V02"


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


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


def safe_run_dir(out_root: str, tag: str) -> str:
    ensure_dir(out_root)
    ts = os.environ.get("SSAU_FIXED_TS", "").strip()
    if not ts:
        import datetime
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"{ts}__SSAU_UNIFY__V02__{tag}"
    run_dir = os.path.join(out_root, name)
    ensure_dir(run_dir)
    return run_dir


def parse_sigma(s: str) -> Tuple[str, str]:
    s = (s or "").strip()
    if ":" in s:
        a, b = s.split(":", 1)
        return a.strip(), b.strip()
    return "", s


def load_alphabet_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise SystemExit(f"ERROR: alphabet json is not an object: {path}")
    if "alphabet" not in obj or not isinstance(obj["alphabet"], list):
        raise SystemExit(f"ERROR: missing 'alphabet' list: {path}")
    return obj


def load_transitions_csv(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        if not r.fieldnames:
            return out
        need = {"from_sigma", "to_sigma", "count"}
        if not need.issubset(set([c.strip() for c in r.fieldnames])):
            raise SystemExit(f"ERROR: transitions.csv missing columns {sorted(list(need))}: {path}")
        for row in r:
            fs = (row.get("from_sigma", "") or "").strip()
            ts = (row.get("to_sigma", "") or "").strip()
            c = (row.get("count", "") or "").strip()
            try:
                n = int(c)
            except Exception:
                n = 0
            out.append({"from_sigma": fs, "to_sigma": ts, "count": n})
    return out


def unify_key(role: str, core: str) -> str:
    role = (role or "").strip().upper()
    core = (core or "").strip().upper()
    return f"{role}:{core}"


def write_manifest(run_dir: str, files: List[str]) -> None:
    rows: List[str] = []
    rows.append("MANIFEST_SHA256")
    for fn in files:
        p = os.path.join(run_dir, fn)
        h = sha256_file(p)
        rows.append(f"{fn}  {h}")
    write_text(os.path.join(run_dir, "MANIFEST.sha256"), "\n".join(rows) + "\n")


def unify_alphabets(inputs: List[Tuple[str, Dict[str, Any]]]) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, str]]]:
    merged: Dict[str, Dict[str, Any]] = {}
    sigma_map_by_source: Dict[str, Dict[str, str]] = {}

    for source_name, obj in inputs:
        sigma_map_by_source[source_name] = {}
        for ent in obj["alphabet"]:
            sigma = (ent.get("sigma", "") or "").strip()
            role = (ent.get("role", "") or "").strip().upper()
            decision = (ent.get("decision", "") or "").strip().upper()
            count = int(ent.get("count", 0) or 0)
            first_index = int(ent.get("first_index", 0) or 0)

            _, core = parse_sigma(sigma)
            core = core.upper()
            ukey = unify_key(role, core)
            sigma_map_by_source[source_name][sigma] = ukey

            if ukey not in merged:
                merged[ukey] = {
                    "u_sigma": ukey,
                    "role": role,
                    "core": core,
                    "decision": decision,
                    "total_count": 0,
                    "first_index_min": first_index,
                    "sources": {}
                }

            merged[ukey]["total_count"] += count
            if first_index < merged[ukey]["first_index_min"]:
                merged[ukey]["first_index_min"] = first_index

            sblock = merged[ukey]["sources"].get(source_name)
            if not sblock:
                merged[ukey]["sources"][source_name] = {
                    "count": count,
                    "first_index": first_index,
                    "decision": decision
                }
            else:
                sblock["count"] = int(sblock.get("count", 0) or 0) + count
                if first_index < int(sblock.get("first_index", first_index) or first_index):
                    sblock["first_index"] = first_index

    out_list = list(merged.values())
    out_list.sort(key=lambda x: (-int(x["total_count"]), str(x["u_sigma"])))
    return out_list, sigma_map_by_source


def unify_transitions(transitions: List[Tuple[str, List[Dict[str, Any]]]], sigma_map_by_source: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
    agg: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for source_name, rows in transitions:
        smap = sigma_map_by_source.get(source_name, {})
        for r in rows:
            fs = (r.get("from_sigma", "") or "").strip()
            ts = (r.get("to_sigma", "") or "").strip()
            c = int(r.get("count", 0) or 0)
            uf = smap.get(fs, "")
            ut = smap.get(ts, "")
            if not uf or not ut:
                continue
            key = (uf, ut)
            if key not in agg:
                agg[key] = {"from_u_sigma": uf, "to_u_sigma": ut, "total_count": 0, "by_source": {}}
            agg[key]["total_count"] += c
            agg[key]["by_source"][source_name] = int(agg[key]["by_source"].get(source_name, 0) or 0) + c
    out = list(agg.values())
    out.sort(key=lambda x: (-int(x["total_count"]), str(x["from_u_sigma"]), str(x["to_u_sigma"])))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", nargs="+", required=True, help="List of alphabet.json inputs (from SSAU extract or other sources).")
    ap.add_argument("--names", nargs="*", default=[], help="Optional names for inputs; must match length of --inputs if provided.")
    ap.add_argument("--transitions", nargs="*", default=[], help="Optional transitions.csv files aligned with --inputs (same order). Use empty for inputs that have none.")
    ap.add_argument("--tag", type=str, default="V02_SSAU_UNIFY", help="Run tag.")
    ap.add_argument("--out_root", type=str, default=os.path.join("outputs", "ssau_unify_out"), help="Output root.")
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

    if args.transitions and (len(args.transitions) != len(in_paths)):
        print("ERROR: --transitions length must match --inputs length (use '' for none)", file=sys.stderr)
        return 2

    def run_once(replay_label: str, fixed_ts: str) -> str:
        os.environ["SSAU_FIXED_TS"] = fixed_ts
        run_dir = safe_run_dir(args.out_root, tag)
        del os.environ["SSAU_FIXED_TS"]

        inputs_loaded: List[Tuple[str, Dict[str, Any]]] = []
        for i, p in enumerate(in_paths):
            name = args.names[i] if args.names else f"S{i+1}"
            obj = load_alphabet_json(p)
            inputs_loaded.append((name, obj))

        unified_symbols, sigma_map_by_source = unify_alphabets(inputs_loaded)

        trans_loaded: List[Tuple[str, List[Dict[str, Any]]]] = []
        if args.transitions:
            for i, tp in enumerate(args.transitions):
                name = args.names[i] if args.names else f"S{i+1}"
                tpp = (tp or "").strip()
                if not tpp:
                    continue
                rows = load_transitions_csv(tpp)
                trans_loaded.append((name, rows))

        unified_edges = unify_transitions(trans_loaded, sigma_map_by_source) if trans_loaded else []

        out_obj = {
            "engine": ENGINE_TAG,
            "version": VERSION,
            "contract": "unify_alphabets_and_optional_transitions",
            "invariant": "phi((m,a,s))=m",
            "inputs": [
                {
                    "name": nm,
                    "alphabet_path": in_paths[i],
                    "transitions_path": (args.transitions[i] if args.transitions else "")
                }
                for i, (nm, _) in enumerate(inputs_loaded)
            ],
            "unified_alphabet": unified_symbols,
            "unified_edges_present": bool(unified_edges),
            "counts": {
                "unified_symbols": len(unified_symbols),
                "unified_edges": len(unified_edges)
            }
        }

        out_json = os.path.join(run_dir, "ssau_unified_alphabet.json")
        write_json(out_json, out_obj)

        map_rows: List[List[Any]] = []
        map_header = ["source", "sigma", "u_sigma"]
        for src, mp in sigma_map_by_source.items():
            keys = list(mp.keys())
            keys.sort()
            for s in keys:
                map_rows.append([src, s, mp[s]])
        write_csv(os.path.join(run_dir, "ssau_sigma_map.csv"), map_header, map_rows)

        if unified_edges:
            e_header = ["from_u_sigma", "to_u_sigma", "total_count"]
            e_rows: List[List[Any]] = []
            for e in unified_edges:
                e_rows.append([e["from_u_sigma"], e["to_u_sigma"], e["total_count"]])
            write_csv(os.path.join(run_dir, "ssau_unified_edges.csv"), e_header, e_rows)

        summary_lines: List[str] = []
        summary_lines.append(f"SSAU Unify {VERSION}")
        summary_lines.append(f"tag = {tag}")
        summary_lines.append(f"replay = {replay_label}")
        summary_lines.append(f"inputs = {len(in_paths)}")
        summary_lines.append(f"unified_symbols = {len(unified_symbols)}")
        summary_lines.append(f"unified_edges = {len(unified_edges)}")
        write_text(os.path.join(run_dir, "summary.txt"), "\n".join(summary_lines) + "\n")

        manifest_files = ["ssau_unified_alphabet.json", "ssau_sigma_map.csv", "summary.txt"]
        if unified_edges:
            manifest_files.append("ssau_unified_edges.csv")
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
        print("OK: SSAU unify v0.2 complete")
        print(f"Output folder: {os.path.dirname(a_dir)}")
        return 0

    run_dir = run_once("RUN", "")
    print("OK: SSAU unify v0.2 complete")
    print(f"Output folder: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
