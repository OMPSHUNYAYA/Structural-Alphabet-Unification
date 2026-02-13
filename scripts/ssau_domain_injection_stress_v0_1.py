#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
from typing import Any, Dict, List, Tuple, Set

VERSION = "v0.1"
ENGINE_TAG = "SSAU_INJECT__V01"
INVARIANT = "phi((m,a,s)) = m"


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
    name = f"{ts}__SSAU_INJECT__V01__{tag}"
    run_dir = os.path.join(out_root, name)
    ensure_dir(run_dir)
    return run_dir


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise ValueError("invalid json root")
    return obj


def extract_sigma_set(alpha_obj: Dict[str, Any]) -> Set[str]:
    sset: Set[str] = set()
    if "alphabet" not in alpha_obj or not isinstance(alpha_obj["alphabet"], list):
        raise ValueError("expected alphabet.json with top-level key 'alphabet' as list")

    for ent in alpha_obj["alphabet"]:
        if not isinstance(ent, dict):
            continue
        sigma = (ent.get("sigma", "") or "").strip()
        if sigma:
            sset.add(sigma.upper())
    return sset


def canonical_injected_sigmas(prefix: str, n: int) -> List[str]:
    # Deterministic, stable ordering
    # Example: INJ0001, INJ0002, ...
    out: List[str] = []
    for i in range(1, n + 1):
        out.append(f"{prefix}{i:04d}".upper())
    return out


def inject_alphabet(
    base_obj: Dict[str, Any],
    inject_n: int,
    prefix: str,
    role: str,
    decision: str
) -> Tuple[Dict[str, Any], List[str], List[List[Any]]]:

    base = json.loads(json.dumps(base_obj))  # deep copy (deterministic)
    existing = extract_sigma_set(base)

    injected = canonical_injected_sigmas(prefix, inject_n)

    # Ensure no collisions (hard fail, deterministic)
    collisions = [s for s in injected if s.upper() in existing]
    if collisions:
        raise ValueError("collision with existing sigma: " + ", ".join(collisions))

    # Append entries deterministically in injected order
    if "alphabet" not in base or not isinstance(base["alphabet"], list):
        raise ValueError("invalid base alphabet")

    rows: List[List[Any]] = []
    for s in injected:
        ent = {
            "sigma": s,
            "role": (role or "").strip().upper(),
            "decision": (decision or "").strip().upper(),
            "count": 0,
            "first_index": -1
        }
        base["alphabet"].append(ent)
        rows.append([s, ent["role"], ent["decision"], ent["count"], ent["first_index"]])

    plan = {
        "engine": ENGINE_TAG,
        "version": VERSION,
        "contract": "domain_injection_stress",
        "invariant": INVARIANT,
        "injected_count": inject_n,
        "prefix": prefix.upper(),
        "role": (role or "").strip().upper(),
        "decision": (decision or "").strip().upper(),
        "injected_sigmas": injected
    }

    return base, injected, rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="Path to a base alphabet.json (SSAU format).")
    ap.add_argument("--tag", default="V01_INJECT", help="Run tag.")
    ap.add_argument("--out_root", default=os.path.join("outputs", "ssau_inject_out"), help="Output root.")
    ap.add_argument("--inject_counts", nargs="+", required=True, help="List of injection sizes, e.g., 0 5 10 25 50")
    ap.add_argument("--prefix", default="INJ", help="Injected sigma prefix (default INJ).")
    ap.add_argument("--role", default="X", help="Injected role (default X).")
    ap.add_argument("--decision", default="ALLOW_RESTRICTED", help="Injected decision (default ALLOW_RESTRICTED).")
    ap.add_argument("--verify_replay", action="store_true")
    args = ap.parse_args()

    tag = (args.tag or "").strip()
    if not tag:
        print("ERROR: empty --tag", file=sys.stderr)
        return 2

    try:
        inject_counts = [int(x) for x in args.inject_counts]
    except Exception:
        print("ERROR: --inject_counts must be integers", file=sys.stderr)
        return 2

    if any(n < 0 for n in inject_counts):
        print("ERROR: inject counts must be >= 0", file=sys.stderr)
        return 2

    base_path = args.base
    if not os.path.isfile(base_path):
        print(f"ERROR: base not found: {base_path}", file=sys.stderr)
        return 2

    def run_once(replay_label: str, fixed_ts: str) -> str:
        if fixed_ts:
            os.environ["SSAU_FIXED_TS"] = fixed_ts
        run_dir = safe_run_dir(args.out_root, tag)
        if fixed_ts:
            del os.environ["SSAU_FIXED_TS"]

        base_obj = load_json(base_path)

        # Produce one injected alphabet per inject_n
        index_rows: List[List[Any]] = []
        produced_paths: List[str] = []

        for inject_n in inject_counts:
            out_sub = f"INJECT_{inject_n:06d}"
            out_sub_dir = os.path.join(run_dir, out_sub)
            ensure_dir(out_sub_dir)

            injected_alpha, injected_sigmas, inj_rows = inject_alphabet(
                base_obj=base_obj,
                inject_n=inject_n,
                prefix=args.prefix,
                role=args.role,
                decision=args.decision
            )

            alpha_out = os.path.join(out_sub_dir, "alphabet.json")
            plan_out = os.path.join(out_sub_dir, "injection_plan.json")
            inj_csv = os.path.join(out_sub_dir, "injected_symbols.csv")
            summ_out = os.path.join(out_sub_dir, "summary.txt")

            write_json(alpha_out, injected_alpha)
            write_json(plan_out, {
                "replay": replay_label,
                "base_path": os.path.normpath(base_path).replace("\\", "/"),
                **{
                    "engine": ENGINE_TAG,
                    "version": VERSION,
                    "contract": "domain_injection_stress",
                    "invariant": INVARIANT,
                    "inject_n": inject_n,
                    "prefix": args.prefix.upper(),
                    "role": args.role.upper(),
                    "decision": args.decision.upper(),
                    "injected_sigmas": injected_sigmas
                }
            })

            write_csv(inj_csv,
                      ["sigma", "role", "decision", "count", "first_index"],
                      inj_rows)

            summary_lines: List[str] = []
            summary_lines.append(f"SSAU Domain Injection Stress {VERSION}")
            summary_lines.append(f"engine={ENGINE_TAG}")
            summary_lines.append(f"tag={tag}")
            summary_lines.append(f"replay={replay_label}")
            summary_lines.append(f"base={os.path.normpath(base_path).replace('\\', '/')}")
            summary_lines.append(f"inject_n={inject_n}")
            summary_lines.append(f"prefix={args.prefix.upper()}")
            summary_lines.append(f"role={args.role.upper()}")
            summary_lines.append(f"decision={args.decision.upper()}")
            write_text(summ_out, "\n".join(summary_lines) + "\n")

            write_manifest(out_sub_dir, ["alphabet.json", "injection_plan.json", "injected_symbols.csv", "summary.txt"])

            produced_paths.append(os.path.join(out_sub, "alphabet.json").replace("\\", "/"))
            index_rows.append([inject_n, out_sub.replace("\\", "/"), f"{out_sub}/alphabet.json"])

        # Index at root run_dir
        write_csv(os.path.join(run_dir, "injection_index.csv"),
                  ["inject_n", "folder", "alphabet_path_rel"],
                  index_rows)

        write_json(os.path.join(run_dir, "run_summary.json"), {
            "engine": ENGINE_TAG,
            "version": VERSION,
            "contract": "domain_injection_stress",
            "invariant": INVARIANT,
            "tag": tag,
            "replay": replay_label,
            "base_path": os.path.normpath(base_path).replace("\\", "/"),
            "inject_counts": inject_counts,
            "produced": produced_paths
        })

        write_text(os.path.join(run_dir, "summary.txt"),
                   "OK: domain injection stress complete\n" +
                   f"engine={ENGINE_TAG}\n" +
                   f"version={VERSION}\n" +
                   f"tag={tag}\n" +
                   f"replay={replay_label}\n" +
                   f"base={os.path.normpath(base_path).replace('\\', '/')}\n" +
                   f"inject_counts={','.join(str(x) for x in inject_counts)}\n")

        write_manifest(run_dir, ["injection_index.csv", "run_summary.json", "summary.txt"])
        return run_dir

    if args.verify_replay:
        a_dir = run_once("REPLAY_A", "20000101_000000")
        b_dir = run_once("REPLAY_B", "20000101_000000")
        ok, why = compare_trees(a_dir, b_dir)
        if not ok:
            print(f"VERIFY_REPLAY: FAIL ({why})", file=sys.stderr)
            return 1
        print("VERIFY_REPLAY: PASS (all artifacts byte-identical across REPLAY_A and REPLAY_B)")
        print("OK: SSAU domain injection stress v0.1 complete")
        print(f"Output folder: {os.path.dirname(a_dir)}")
        return 0

    run_dir = run_once("RUN", "")
    print("OK: SSAU domain injection stress v0.1 complete")
    print(f"Output folder: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
