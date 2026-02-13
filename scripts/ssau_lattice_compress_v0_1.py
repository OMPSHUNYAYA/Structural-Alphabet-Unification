#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
from math import log
from typing import Any, Dict, List, Tuple

VERSION = "v0.1"
ENGINE_TAG = "SSAU_LATTICE_COMPRESS__V01"
INVARIANT = "phi((m,a,s)) = m"

G_ORDER = ["DENY", "ABSTAIN", "ALLOW_RESTRICTED", "ALLOW"]
G_RANK = {k: i for i, k in enumerate(G_ORDER)}

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def rm_tree(path: str) -> None:
    if os.path.isdir(path):
        shutil.rmtree(path)

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)

def write_json(path: str, obj: Any) -> None:
    b = json.dumps(obj, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    with open(path, "wb") as f:
        f.write(b)

def write_csv(path: str, header: List[str], rows: List[List[str]]) -> None:
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
            return False, "byte mismatch at " + rel
    return True, "OK"

def write_manifest(out_dir: str, files: List[str]) -> None:
    lines = ["MANIFEST_SHA256"]
    for fn in files:
        p = os.path.join(out_dir, fn.replace("/", os.sep))
        lines.append(fn + "  " + sha256_file(p))
    write_text(os.path.join(out_dir, "MANIFEST.sha256"), "\n".join(lines) + "\n")

def lattice_join(a: str, b: str) -> str:
    return G_ORDER[max(G_RANK[a], G_RANK[b])]

def lattice_meet(a: str, b: str) -> str:
    return G_ORDER[min(G_RANK[a], G_RANK[b])]

def build_lattice_tables() -> Tuple[Dict[str, Any], List[List[str]]]:
    table_rows: List[List[str]] = []
    header = ["x", "y", "x_join_y", "x_meet_y"]
    for x in G_ORDER:
        for y in G_ORDER:
            table_rows.append([x, y, lattice_join(x, y), lattice_meet(x, y)])
    lattice_obj = {
        "engine": ENGINE_TAG,
        "version": VERSION,
        "governance_set": G_ORDER,
        "order": "DENY <= ABSTAIN <= ALLOW_RESTRICTED <= ALLOW",
        "join": "x ∨ y = max(x,y) under the order",
        "meet": "x ∧ y = min(x,y) under the order",
    }
    return lattice_obj, [header] + table_rows

def read_alphabet_json(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))

def compression_from_alphabet(alpha: Dict[str, Any]) -> Dict[str, Any]:
    items = alpha.get("alphabet", [])
    sigmas = []
    roles = []
    decisions = []
    counts_total = 0
    refusal_sigmas = 0

    for it in items:
        s = str(it.get("sigma", "")).strip()
        r = str(it.get("role", "")).strip()
        d = str(it.get("decision", "")).strip()
        c = int(it.get("count", 0))
        if s != "":
            sigmas.append(s)
        if r != "":
            roles.append(r)
        if d != "":
            decisions.append(d)
        counts_total += max(0, c)
        if d in ("DENY", "ABSTAIN"):
            refusal_sigmas += 1

    uniq_sigma = sorted(set(sigmas))
    uniq_role = sorted(set(roles))
    uniq_dec = sorted(set(decisions))

    K_sigma = len(uniq_sigma)
    K_role = len(uniq_role)
    K_dec = len(uniq_dec)

    def safe_log(k: int) -> float:
        if k <= 0:
            return 0.0
        return log(k)

    H_sigma = safe_log(K_sigma)
    H_role = safe_log(K_role)
    H_dec = safe_log(K_dec)

    def safe_div(a: float, b: float) -> float:
        if b == 0.0:
            return 0.0
        return a / b

    CR_sigma_to_role = safe_div(float(K_sigma), float(max(1, K_role)))
    CR_sigma_to_dec = safe_div(float(K_sigma), float(max(1, K_dec)))
    CR_role_to_dec = safe_div(float(K_role), float(max(1, K_dec)))

    RED_sigma_to_dec = 0.0
    if K_sigma > 1 and H_sigma > 0.0:
        RED_sigma_to_dec = 1.0 - safe_div(H_dec, H_sigma)

    return {
        "K_sigma": K_sigma,
        "K_role": K_role,
        "K_decision": K_dec,
        "unique_decisions": uniq_dec,
        "unique_roles": uniq_role,
        "H_sigma": H_sigma,
        "H_role": H_role,
        "H_decision": H_dec,
        "CR_sigma_to_role": CR_sigma_to_role,
        "CR_sigma_to_decision": CR_sigma_to_dec,
        "CR_role_to_decision": CR_role_to_dec,
        "RED_sigma_to_decision": RED_sigma_to_dec,
        "refusal_sigma_count": refusal_sigmas,
        "counts_total": counts_total,
    }

def validate_decisions(uniq_decisions: List[str]) -> Tuple[bool, str]:
    bad = [d for d in uniq_decisions if d not in G_RANK]
    if bad:
        return False, "invalid decisions found: " + ",".join(bad)
    return True, "OK"

def run_once(out_dir: str, alphabet_paths: List[str], tag: str) -> None:
    ensure_dir(out_dir)

    lattice_obj, lattice_table = build_lattice_tables()

    write_json(os.path.join(out_dir, "lattice.json"), lattice_obj)
    write_csv(os.path.join(out_dir, "lattice_table.csv"), lattice_table[0], lattice_table[1:])

    reports: List[Dict[str, Any]] = []
    for p in alphabet_paths:
        a = read_alphabet_json(p)
        comp = compression_from_alphabet(a)
        ok, why = validate_decisions(comp["unique_decisions"])
        comp["decision_validation"] = {"ok": ok, "why": why}
        comp["alphabet_path"] = p.replace("\\", "/")
        reports.append(comp)

    unified = {
        "engine": ENGINE_TAG,
        "version": VERSION,
        "tag": tag,
        "invariant": INVARIANT,
        "governance_set": G_ORDER,
        "n_inputs": len(alphabet_paths),
        "inputs": [p.replace("\\", "/") for p in alphabet_paths],
        "reports": reports,
    }

    write_json(os.path.join(out_dir, "compression_report.json"), unified)

    lines = []
    lines.append("SSAU Lattice + Compression Report " + VERSION)
    lines.append("engine=" + ENGINE_TAG)
    lines.append("tag=" + tag)
    lines.append("invariant: " + INVARIANT)
    lines.append("governance_order: DENY <= ABSTAIN <= ALLOW_RESTRICTED <= ALLOW")
    lines.append("")

    for i, rep in enumerate(reports):
        lines.append("INPUT[" + str(i) + "]: " + rep.get("alphabet_path", ""))
        lines.append("  K_sigma=" + str(rep["K_sigma"]) + "  K_role=" + str(rep["K_role"]) + "  K_decision=" + str(rep["K_decision"]))
        lines.append("  CR_sigma_to_role=" + f"{rep['CR_sigma_to_role']:.6g}" + "  CR_sigma_to_decision=" + f"{rep['CR_sigma_to_decision']:.6g}" + "  CR_role_to_decision=" + f"{rep['CR_role_to_decision']:.6g}")
        lines.append("  H_sigma=" + f"{rep['H_sigma']:.6g}" + "  H_role=" + f"{rep['H_role']:.6g}" + "  H_decision=" + f"{rep['H_decision']:.6g}")
        lines.append("  RED_sigma_to_decision=" + f"{rep['RED_sigma_to_decision']:.6g}")
        lines.append("  refusal_sigma_count=" + str(rep["refusal_sigma_count"]))
        v = rep.get("decision_validation", {})
        lines.append("  decision_validation=" + ("OK" if v.get("ok") else "FAIL") + " (" + str(v.get("why", "")) + ")")
        lines.append("")

    write_text(os.path.join(out_dir, "summary.txt"), "\n".join(lines) + "\n")

    files = ["lattice.json", "lattice_table.csv", "compression_report.json", "summary.txt"]
    write_manifest(out_dir, files)

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--alphabet", action="append", required=True, help="Path to alphabet.json (repeatable)")
    ap.add_argument("--tag", default="V01_LATTICE_COMPRESS")
    ap.add_argument("--out_root", default=os.path.join("outputs", "ssau_lattice_compress_out"))
    ap.add_argument("--verify_replay", action="store_true")
    args = ap.parse_args()

    tag = (args.tag or "").strip()
    if not tag:
        print("ERROR: empty --tag", file=sys.stderr)
        return 2

    out_root = args.out_root
    ensure_dir(out_root)

    if args.verify_replay:
        a_dir = os.path.join(out_root, "REPLAY_A__" + ENGINE_TAG + "__" + tag)
        b_dir = os.path.join(out_root, "REPLAY_B__" + ENGINE_TAG + "__" + tag)
        rm_tree(a_dir)
        rm_tree(b_dir)

        run_once(a_dir, args.alphabet, tag)
        run_once(b_dir, args.alphabet, tag)

        ok, why = compare_trees(a_dir, b_dir)
        if not ok:
            print("VERIFY_REPLAY: FAIL (" + why + ")", file=sys.stderr)
            return 1

        print("VERIFY_REPLAY: PASS (all artifacts byte-identical across REPLAY_A and REPLAY_B)")
        print("OK: SSAU lattice+compression " + VERSION + " complete")
        print("Output folder: " + out_root)
        return 0

    run_dir = os.path.join(out_root, "RUN__" + ENGINE_TAG + "__" + tag)
    rm_tree(run_dir)
    run_once(run_dir, args.alphabet, tag)

    print("OK: SSAU lattice+compression " + VERSION + " complete")
    print("Output folder: " + run_dir)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
