#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSAU Alphabet Extractor v0.2
Extracts (alphabet.json, transitions.csv, summary.txt, MANIFEST.sha256) from an existing timeline CSV.

Invariant preserved:
  phi((m,a,s)) = m
"""

import argparse
import csv
import hashlib
import json
import os
import sys
from typing import Dict, List, Tuple


VERSION = "v0.2"
ENGINE_TAG = "SSAU_EXTRACT__V02"


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


def write_csv(path: str, header: List[str], rows: List[List[str]]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        for r in rows:
            w.writerow(r)


def write_manifest(folder: str, files: List[str]) -> None:
    lines = []
    for fn in sorted(files):
        p = os.path.join(folder, fn)
        h = sha256_file(p)
        lines.append(f"{h}  {fn}")
    write_text(os.path.join(folder, "MANIFEST.sha256"), "\n".join(lines) + "\n")


def role_of_sigma(sigma: str) -> str:
    s = sigma.upper()
    if "ABSTAIN" in s:
        return "A"
    if "DENY" in s or "REJECT" in s:
        return "N"
    if "IRREV" in s:
        return "I"
    if "RECOVER" in s or "RESET" in s:
        return "R"
    if "CROSS" in s:
        return "X"
    if "META" in s:
        return "M"
    if "THRESH" in s:
        return "T"
    if "STABLE" in s or "OK" in s:
        return "C"
    return "D"


def decision_from_role(role: str) -> str:
    if role == "N":
        return "DENY"
    if role == "A":
        return "ABSTAIN"
    if role in ("T", "M", "X"):
        return "ALLOW_RESTRICTED"
    return "ALLOW"


def read_sigmas(in_csv: str, sigma_col: str) -> Tuple[List[str], int]:
    with open(in_csv, "r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        if sigma_col not in r.fieldnames:
            raise SystemExit(f"ERROR: sigma_col '{sigma_col}' not found in CSV header: {r.fieldnames}")
        sigmas: List[str] = []
        n = 0
        for row in r:
            n += 1
            sigmas.append((row.get(sigma_col) or "").strip())
    return sigmas, n


def build_outputs(sigmas: List[str]) -> Tuple[Dict, List[List[str]], Dict[str, int]]:
    unique = sorted(set([s for s in sigmas if s != ""]))

    first_idx: Dict[str, int] = {}
    counts: Dict[str, int] = {}
    for i, s in enumerate(sigmas):
        if s == "":
            continue
        if s not in first_idx:
            first_idx[s] = i
        counts[s] = counts.get(s, 0) + 1

    transitions: Dict[str, int] = {}
    chain = [s for s in sigmas if s != ""]
    for i in range(len(chain) - 1):
        a = chain[i]
        b = chain[i + 1]
        k = a + " -> " + b
        transitions[k] = transitions.get(k, 0) + 1

    t_rows: List[List[str]] = []
    for k in sorted(transitions.keys()):
        parts = k.split(" -> ")
        t_rows.append([parts[0], parts[1], str(transitions[k])])

    alphabet = {
        "engine": ENGINE_TAG,
        "version": VERSION,
        "contract": "CAS-1",
        "invariant": "phi((m,a,s)) = m",
        "alphabet": [],
        "notes": {
            "roles": "GB-1 roles: C,D,T,M,X,I,R,N,A",
            "decisions": "ALLOW, ALLOW_RESTRICTED, DENY, ABSTAIN",
        }
    }

    for s in unique:
        role = role_of_sigma(s)
        decision = decision_from_role(role)
        alphabet["alphabet"].append({
            "sigma": s,
            "role": role,
            "decision": decision,
            "count": counts.get(s, 0),
            "first_index": first_idx.get(s, 0),
        })

    stats = {
        "timeline_len": len(chain),
        "alphabet_size": len(unique),
        "transition_edges": len(transitions),
    }

    late = 0
    if len(chain) > 0:
        cutoff = int(len(chain) * 0.75)
        for s in unique:
            if first_idx.get(s, 0) >= cutoff:
                late += 1
    stats["late_emergent_symbols"] = late

    return alphabet, t_rows, stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_csv", required=True)
    ap.add_argument("--sigma_col", default="sigma")
    ap.add_argument("--tag", default="SSAU_EXTRACT")
    ap.add_argument("--out_dir", required=True)
    args = ap.parse_args()

    ensure_dir(args.out_dir)

    sigmas, n_rows = read_sigmas(args.in_csv, args.sigma_col)
    alphabet, t_rows, stats = build_outputs(sigmas)

    write_text(os.path.join(args.out_dir, "alphabet.json"), json.dumps(alphabet, indent=2) + "\n")
    write_csv(os.path.join(args.out_dir, "transitions.csv"), ["from_sigma", "to_sigma", "count"], t_rows)

    summary = []
    summary.append(f"SSAU Extractor {VERSION}")
    summary.append(f"engine={ENGINE_TAG}")
    summary.append(f"tag={args.tag}")
    summary.append(f"invariant=phi((m,a,s)) = m")
    summary.append(f"in_csv={args.in_csv}")
    summary.append(f"rows_read={n_rows}")
    summary.append(f"timeline_len={stats['timeline_len']}")
    summary.append(f"alphabet_size={stats['alphabet_size']}")
    summary.append(f"transition_edges={stats['transition_edges']}")
    summary.append(f"late_emergent_symbols={stats['late_emergent_symbols']}")
    write_text(os.path.join(args.out_dir, "summary.txt"), "\n".join(summary) + "\n")

    write_manifest(args.out_dir, ["alphabet.json", "transitions.csv", "summary.txt"])
    print("OK: SSAU extract complete")
    print("out_dir =", args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
