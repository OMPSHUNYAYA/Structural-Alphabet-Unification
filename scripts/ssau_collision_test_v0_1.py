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
ENGINE_TAG = "SSAU_COLLISION_TEST__V01"

LATTICE = ["DENY", "ABSTAIN", "ALLOW_RESTRICTED", "ALLOW"]
RANK = {d: i for i, d in enumerate(LATTICE)}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)


def rm_tree(p: str) -> None:
    if os.path.isdir(p):
        shutil.rmtree(p)


def write_text(path: str, s: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)


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
    for dp, _, fns in os.walk(root):
        for fn in fns:
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            rels.append(rel)
    rels.sort()
    return rels


def compare_trees(a_root: str, b_root: str) -> Tuple[bool, str]:
    a = stable_relpaths(a_root)
    b = stable_relpaths(b_root)
    if a != b:
        return False, "file list mismatch"
    for rel in a:
        ap = os.path.join(a_root, rel.replace("/", os.sep))
        bp = os.path.join(b_root, rel.replace("/", os.sep))
        with open(ap, "rb") as fa:
            ab = fa.read()
        with open(bp, "rb") as fb:
            bb = fb.read()
        if ab != bb:
            return False, "byte mismatch at " + rel
    return True, "OK"


def safe_run_dir(out_root: str, folder_tag: str) -> str:
    ensure_dir(out_root)
    ts = os.environ.get("SSAU_FIXED_TS", "").strip()
    if not ts:
        import datetime
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"{ts}__{ENGINE_TAG}__{folder_tag}"
    run_dir = os.path.join(out_root, name)
    ensure_dir(run_dir)
    return run_dir


def parse_sigma(sigma: str) -> Tuple[str, str]:
    s = (sigma or "").strip()
    if ":" in s:
        a, b = s.split(":", 1)
        return a.strip().upper(), b.strip().upper()
    return "", s.strip().upper()


def unify_key(role: str, core: str) -> str:
    return f"{(role or '').strip().upper()}:{(core or '').strip().upper()}"


def min_decision(decisions: List[str]) -> str:
    best = None
    best_rank = 10**9
    for d in decisions:
        dd = (d or "").strip().upper()
        r = RANK.get(dd, 10**8)
        if r < best_rank:
            best_rank = r
            best = dd
    return best or "ABSTAIN"


def load_alphabet(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise SystemExit("ERROR: alphabet json not an object: " + path)
    if "alphabet" not in obj or not isinstance(obj["alphabet"], list):
        raise SystemExit("ERROR: missing 'alphabet' list: " + path)
    return obj


def write_manifest(run_dir: str, files: List[str]) -> None:
    rows = ["MANIFEST_SHA256"]
    for fn in sorted(files):
        p = os.path.join(run_dir, fn)
        rows.append(f"{fn}  {sha256_file(p)}")
    write_text(os.path.join(run_dir, "MANIFEST.sha256"), "\n".join(rows) + "\n")


def make_synthetic_alphabets(run_dir: str) -> List[str]:
    a1 = {
        "alphabet": [
            {"sigma": "ROLE:TERMINAL:DENY", "role": "ROLE", "decision": "DENY", "count": 10, "first_index": 1},
            {"sigma": "MODE:STABLE", "role": "MODE", "decision": "ALLOW", "count": 50, "first_index": 2},
            {"sigma": "MODE:DRIFTING", "role": "MODE", "decision": "ALLOW_RESTRICTED", "count": 20, "first_index": 3},
            {"sigma": "EDGE:COLLIDE_X", "role": "EDGE", "decision": "ALLOW", "count": 5, "first_index": 4},
        ]
    }
    a2 = {
        "alphabet": [
            {"sigma": "ROLE:TERMINAL:DENY", "role": "ROLE", "decision": "DENY", "count": 7, "first_index": 1},
            {"sigma": "EDGE:COLLIDE_X", "role": "EDGE", "decision": "DENY", "count": 3, "first_index": 9},
            {"sigma": "EDGE:COLLIDE_Y", "role": "EDGE", "decision": "ABSTAIN", "count": 4, "first_index": 10},
        ]
    }
    a3 = {
        "alphabet": [
            {"sigma": "EDGE:COLLIDE_X", "role": "EDGE", "decision": "ABSTAIN", "count": 2, "first_index": 6},
            {"sigma": "EDGE:COLLIDE_Y", "role": "EDGE", "decision": "ALLOW", "count": 1, "first_index": 7},
            {"sigma": "MODE:STABLE", "role": "MODE", "decision": "ALLOW", "count": 8, "first_index": 8},
        ]
    }

    p1 = os.path.join(run_dir, "synthetic_alphabet_01.json")
    p2 = os.path.join(run_dir, "synthetic_alphabet_02.json")
    p3 = os.path.join(run_dir, "synthetic_alphabet_03.json")
    write_json(p1, a1)
    write_json(p2, a2)
    write_json(p3, a3)
    return [p1, p2, p3]


def collision_analyze(alphabet_paths: List[str]) -> Dict[str, Any]:
    per_key: Dict[str, Dict[str, Any]] = {}
    for ap in alphabet_paths:
        obj = load_alphabet(ap)
        src = os.path.basename(ap)
        for ent in obj["alphabet"]:
            sigma = (ent.get("sigma", "") or "").strip()
            role = (ent.get("role", "") or "").strip().upper()
            decision = (ent.get("decision", "") or "").strip().upper()
            _, core = parse_sigma(sigma)
            ukey = unify_key(role, core)

            block = per_key.get(ukey)
            if not block:
                block = {
                    "u_sigma": ukey,
                    "role": role,
                    "core": core,
                    "decisions_seen": [],
                    "sources": {},
                }
                per_key[ukey] = block

            if decision and decision not in block["decisions_seen"]:
                block["decisions_seen"].append(decision)
                block["decisions_seen"].sort(key=lambda d: RANK.get(d, 10**8))

            if src not in block["sources"]:
                block["sources"][src] = {"decision": decision, "count": int(ent.get("count", 0) or 0)}
            else:
                block["sources"][src]["count"] = int(block["sources"][src].get("count", 0) or 0) + int(ent.get("count", 0) or 0)

    collisions = []
    ok = []
    for _, block in per_key.items():
        ds = block["decisions_seen"]
        resolved = min_decision(ds)
        out = dict(block)
        out["resolved_decision"] = resolved
        out["collision"] = (len(ds) > 1)
        if out["collision"]:
            collisions.append(out)
        else:
            ok.append(out)

    collisions.sort(key=lambda x: x["u_sigma"])
    ok.sort(key=lambda x: x["u_sigma"])

    summary = {
        "version": VERSION,
        "engine_tag": ENGINE_TAG,
        "governance_lattice": LATTICE,
        "alphabet_count": len(alphabet_paths),
        "unique_u_sigma": len(per_key),
        "collision_u_sigma": len(collisions),
        "noncollision_u_sigma": len(ok),
    }

    return {
        "summary": summary,
        "collisions": collisions,
        "all": ok + collisions,
    }


def run_once(out_root: str, folder_tag: str, base_tag: str, alphabet_paths: List[str], synthetic: bool) -> str:
    run_dir = safe_run_dir(out_root, folder_tag)
    created: List[str] = []

    if synthetic:
        syn_paths = make_synthetic_alphabets(run_dir)
        alphabet_paths = syn_paths
        created += [os.path.basename(p) for p in syn_paths]

    report = collision_analyze(alphabet_paths)
    write_json(os.path.join(run_dir, "collision_report.json"), report)
    created.append("collision_report.json")

    rows: List[List[Any]] = []
    for ent in report["all"]:
        u = ent["u_sigma"]
        ds = ",".join(ent["decisions_seen"])
        rd = ent["resolved_decision"]
        c = "YES" if ent.get("collision") else "NO"
        rows.append([u, c, ds, rd, len(ent.get("sources", {}))])

    write_csv(
        os.path.join(run_dir, "collision_table.csv"),
        ["u_sigma", "collision", "decisions_seen", "resolved_decision", "source_count"],
        rows,
    )
    created.append("collision_table.csv")

    s = []
    s.append(f"SSAU Collision Test {VERSION}")
    s.append(f"ENGINE_TAG: {ENGINE_TAG}")
    s.append(f"tag: {base_tag}")
    s.append("")
    s.append(f"unique_u_sigma: {report['summary']['unique_u_sigma']}")
    s.append(f"collision_u_sigma: {report['summary']['collision_u_sigma']}")
    s.append(f"noncollision_u_sigma: {report['summary']['noncollision_u_sigma']}")
    s.append("")
    s.append("governance_lattice_order:")
    for d in LATTICE:
        s.append(f"  {d}")
    s.append("")
    s.append("resolution_rule:")
    s.append("  resolved_decision = min(decisions_seen) under lattice order")
    s.append("")
    write_text(os.path.join(run_dir, "summary.txt"), "\n".join(s) + "\n")
    created.append("summary.txt")

    write_manifest(run_dir, created)
    return run_dir


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--out_root", default=os.path.join("outputs", "ssau_collision_out"))
    ap.add_argument("--verify_replay", action="store_true")
    ap.add_argument("--synthetic", action="store_true")
    ap.add_argument("--alphabet", action="append", default=[])
    args = ap.parse_args()

    if not args.synthetic and not args.alphabet:
        raise SystemExit("ERROR: provide --synthetic or at least one --alphabet path")

    base_tag = args.tag

    if args.verify_replay:
        os.environ["SSAU_FIXED_TS"] = "20000101_000000"
        a_dir = run_once(args.out_root, f"REPLAY_A__{base_tag}", base_tag, list(args.alphabet), args.synthetic)
        b_dir = run_once(args.out_root, f"REPLAY_B__{base_tag}", base_tag, list(args.alphabet), args.synthetic)
        ok, msg = compare_trees(a_dir, b_dir)
        if not ok:
            raise SystemExit("VERIFY_REPLAY: FAIL (" + msg + ")")
        print("VERIFY_REPLAY: PASS (all artifacts byte-identical across REPLAY_A and REPLAY_B)")
        print("OK: SSAU collision test v0.1 complete")
        print("Output folder:", args.out_root)
        return 0

    out_dir = run_once(args.out_root, base_tag, base_tag, list(args.alphabet), args.synthetic)
    print("OK: SSAU collision test v0.1 complete")
    print("Run folder:", out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
