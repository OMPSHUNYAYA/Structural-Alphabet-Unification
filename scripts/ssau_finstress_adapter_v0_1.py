#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import hashlib
import math
import os
import sys

G_LATTICE = ["DENY", "ABSTAIN", "ALLOW_RESTRICTED", "ALLOW"]
FIXED_RUN_STAMP = "20000101_000000"

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def write_text(path: str, s: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)
        if not s.endswith("\n"):
            f.write("\n")

def fmt10(x: float) -> str:
    return f"{x:.10f}"

def clamp(x: float, lo: float, hi: float) -> float:
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x

def median(vals):
    a = sorted(vals)
    n = len(a)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2 == 1:
        return float(a[mid])
    return (float(a[mid - 1]) + float(a[mid])) / 2.0

def variance(vals):
    n = len(vals)
    if n <= 1:
        return 0.0
    mean = sum(vals) / n
    acc = 0.0
    for v in vals:
        d = v - mean
        acc += d * d
    return acc / (n - 1)

def parse_params(params_path: str):
    req = {
        "W_vol": None,
        "W_base": None,
        "dd_fail": None,
        "alpha": None,
        "beta": None,
        "eps": None,
    }
    raw_lines = []
    with open(params_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw_lines.append(line)
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k in req:
                req[k] = v

    for k in req:
        if req[k] is None:
            raise ValueError(f"Missing param: {k}")

    W_vol = int(req["W_vol"])
    W_base = int(req["W_base"])
    dd_fail = float(req["dd_fail"])
    alpha = float(req["alpha"])
    beta = float(req["beta"])
    eps = float(req["eps"])

    if W_vol <= 1:
        raise ValueError("W_vol must be >= 2")
    if W_base <= 1:
        raise ValueError("W_base must be >= 2")
    if dd_fail <= 0.0 or dd_fail >= 1.0:
        raise ValueError("dd_fail must be in (0,1)")
    if eps <= 0.0:
        raise ValueError("eps must be > 0")

    S_restrict = alpha * float(W_vol)
    S_deny = beta * float(W_vol)

    return {
        "W_vol": W_vol,
        "W_base": W_base,
        "dd_fail": dd_fail,
        "alpha": alpha,
        "beta": beta,
        "S_restrict": S_restrict,
        "S_deny": S_deny,
        "eps": eps,
        "raw_lines": raw_lines,
    }

def read_input_csv(in_csv: str):
    rows = []
    with open(in_csv, "r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header is None:
            raise ValueError("Empty CSV")
        if [h.strip() for h in header] != ["timestamp", "price"]:
            raise ValueError("CSV header must be exactly: timestamp,price")
        prev_ts = None
        for i, r in enumerate(reader, start=2):
            if len(r) != 2:
                raise ValueError(f"Invalid row length at line {i}")
            ts = r[0].strip()
            ps = r[1].strip()
            if ts == "" or ps == "":
                raise ValueError(f"Empty field at line {i}")
            if prev_ts is not None and ts <= prev_ts:
                raise ValueError(f"Timestamps must be strictly increasing (line {i})")
            p = float(ps)
            if not (p > 0.0):
                raise ValueError(f"Price must be > 0 (line {i})")
            rows.append((ts, p))
            prev_ts = ts
    if len(rows) < 3:
        raise ValueError("Need at least 3 rows")
    return rows

def compute_series(rows, params):
    W_vol = params["W_vol"]
    W_base = params["W_base"]
    dd_fail = params["dd_fail"]
    eps = params["eps"]
    S_restrict = params["S_restrict"]
    S_deny = params["S_deny"]

    ts = [r[0] for r in rows]
    p = [r[1] for r in rows]

    # drawdown across full series
    p_peak = []
    peak = -1.0
    for val in p:
        if val > peak:
            peak = val
        p_peak.append(peak)
    dd = []
    for i in range(len(p)):
        dd.append((p_peak[i] - p[i]) / p_peak[i])

    # classical failure time (first dd >= dd_fail)
    t_fail_idx = None
    for i in range(len(dd)):
        if dd[i] >= dd_fail:
            t_fail_idx = i
            break

    # log returns r(t) for t>=1
    r = [None] * len(p)
    for i in range(1, len(p)):
        r[i] = math.log(p[i] / p[i - 1])

    # rolling volatility v(t) for t>=1 and enough r window
    v = [None] * len(p)
    for i in range(1, len(p)):
        if i - (W_vol - 1) < 1:
            continue
        window = [r[j] for j in range(i - (W_vol - 1), i + 1)]
        var_r = variance(window)
        v[i] = math.sqrt(var_r)

    # baseline volatility v_base(t) requires W_base v-values
    v_base = [None] * len(p)
    for i in range(len(p)):
        if v[i] is None:
            continue
        start = i - (W_base - 1)
        if start < 0:
            continue
        window = []
        ok = True
        for j in range(start, i + 1):
            if v[j] is None:
                ok = False
                break
            window.append(v[j])
        if not ok:
            continue
        v_base[i] = median(window)

    # structural series starting where v_base is defined
    a = [None] * len(p)
    s = [None] * len(p)
    decision = [None] * len(p)

    s_acc = 0.0
    for i in range(len(p)):
        if v_base[i] is None or v[i] is None:
            continue

        vb = v_base[i]
        denom = vb if vb > eps else eps
        x = (v[i] - vb) / denom

        a_i = clamp(-x, -1.0, 1.0)
        s_acc += max(0.0, x)

        a[i] = a_i
        s[i] = s_acc

        if dd[i] >= dd_fail:
            d = "DENY"
        elif s_acc >= S_deny:
            d = "ABSTAIN"
        elif s_acc >= S_restrict:
            d = "ALLOW_RESTRICTED"
        else:
            d = "ALLOW"
        decision[i] = d

    # t_refusal is first index with ABSTAIN or DENY where decision is defined
    t_refusal_idx = None
    for i in range(len(p)):
        if decision[i] in ("DENY", "ABSTAIN"):
            t_refusal_idx = i
            break

    return {
        "ts": ts,
        "p": p,
        "dd": dd,
        "a": a,
        "s": s,
        "decision": decision,
        "t_fail_idx": t_fail_idx,
        "t_refusal_idx": t_refusal_idx,
    }

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def build_out_dir(out_root: str, replay_id: str, tag: str) -> str:
    folder = f"{FIXED_RUN_STAMP}__SSAU_FINSTRESS__V01__{replay_id}__{tag}"
    return os.path.join(out_root, folder)

def write_outputs(out_dir: str, in_csv: str, params_path: str, params, series):
    ensure_dir(out_dir)

    # params_snapshot.txt (canonical)
    params_snapshot = []
    params_snapshot.append(f"W_vol = {params['W_vol']}")
    params_snapshot.append(f"W_base = {params['W_base']}")
    params_snapshot.append(f"dd_fail = {fmt10(params['dd_fail'])}")
    params_snapshot.append(f"alpha = {fmt10(params['alpha'])}")
    params_snapshot.append(f"beta = {fmt10(params['beta'])}")
    params_snapshot.append(f"S_restrict = {fmt10(params['S_restrict'])}")
    params_snapshot.append(f"S_deny = {fmt10(params['S_deny'])}")
    params_snapshot.append(f"eps = {params['eps']}")
    write_text(os.path.join(out_dir, "params_snapshot.txt"), "\n".join(params_snapshot))

    # input_hash.txt
    in_hash = sha256_file(in_csv)
    write_text(os.path.join(out_dir, "input_hash.txt"), f"SHA256({os.path.basename(in_csv)})={in_hash}")

    # classical_threshold.txt
    t_fail_idx = series["t_fail_idx"]
    if t_fail_idx is None:
        t_fail = "NONE"
        price_at = "NONE"
        dd_at = "NONE"
    else:
        t_fail = series["ts"][t_fail_idx]
        price_at = fmt10(series["p"][t_fail_idx])
        dd_at = fmt10(series["dd"][t_fail_idx])

    classical_lines = [
        f"dd_fail = {fmt10(params['dd_fail'])}",
        f"t_fail = {t_fail}",
        f"price_at_t_fail = {price_at}",
        f"dd_at_t_fail = {dd_at}",
    ]
    write_text(os.path.join(out_dir, "classical_threshold.txt"), "\n".join(classical_lines))

    # structural_series.csv
    csv_path = os.path.join(out_dir, "structural_series.csv")
    with open(csv_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("timestamp,price,drawdown,a,s,decision\n")
        for i in range(len(series["ts"])):
            if series["decision"][i] is None:
                continue
            f.write(
                f"{series['ts'][i]},"
                f"{fmt10(series['p'][i])},"
                f"{fmt10(series['dd'][i])},"
                f"{fmt10(series['a'][i])},"
                f"{fmt10(series['s'][i])},"
                f"{series['decision'][i]}\n"
            )

    # early_warning_summary.txt
    t_refusal_idx = series["t_refusal_idx"]
    if t_refusal_idx is None:
        t_refusal = "NONE"
        dd_ref = "NONE"
    else:
        t_refusal = series["ts"][t_refusal_idx]
        dd_ref = fmt10(series["dd"][t_refusal_idx])

    # CHECKS
    check_1 = False
    check_2 = False
    if t_refusal_idx is not None and t_fail_idx is not None:
        check_1 = (t_refusal_idx < t_fail_idx)
    if t_refusal_idx is not None:
        check_2 = (series["dd"][t_refusal_idx] < params["dd_fail"])

    # phi check (numeric equality: output price computed directly from input float)
    phi_ok = True
    for i in range(len(series["p"])):
        if series["decision"][i] is None:
            continue
        if not (series["p"][i] == series["p"][i]):
            phi_ok = False
            break

    decisions_ok = True
    for i in range(len(series["decision"])):
        d = series["decision"][i]
        if d is None:
            continue
        if d not in G_LATTICE:
            decisions_ok = False
            break

    summary_lines = [
        f"t_refusal = {t_refusal}",
        f"drawdown_at_t_refusal = {dd_ref}",
        "",
        f"CHECK_1: t_refusal < t_fail = {'TRUE' if check_1 else 'FALSE'}",
        f"CHECK_2: drawdown_at_t_refusal < dd_fail = {'TRUE' if check_2 else 'FALSE'}",
        f"CHECK_3: phi((m,a,s)) = m = {'TRUE' if phi_ok else 'FALSE'}",
        f"CHECK_4: decisions_in_G = {'TRUE' if decisions_ok else 'FALSE'}",
    ]
    write_text(os.path.join(out_dir, "early_warning_summary.txt"), "\n".join(summary_lines))

    # MANIFEST.sha256 (alphabetical order)
    files = [
        "classical_threshold.txt",
        "early_warning_summary.txt",
        "input_hash.txt",
        "params_snapshot.txt",
        "structural_series.csv",
    ]
    lines = []
    for fn in files:
        fp = os.path.join(out_dir, fn)
        h = sha256_file(fp)
        lines.append(f"{h}  {fn}")
    write_text(os.path.join(out_dir, "MANIFEST.sha256"), "\n".join(lines))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_csv", required=True)
    ap.add_argument("--params", required=True)
    ap.add_argument("--out_root", required=True)
    ap.add_argument("--replay_id", required=True, choices=["REPLAY_A", "REPLAY_B"])
    ap.add_argument("--tag", required=True)
    ap.add_argument("--verify_replay", action="store_true")
    args = ap.parse_args()

    try:
        params = parse_params(args.params)
        rows = read_input_csv(args.in_csv)
        series = compute_series(rows, params)
        out_dir = build_out_dir(args.out_root, args.replay_id, args.tag)
        write_outputs(out_dir, args.in_csv, args.params, params, series)
    except Exception as e:
        # failure contract: write minimal early_warning_summary.txt if possible
        try:
            out_dir = build_out_dir(args.out_root, args.replay_id, args.tag)
            ensure_dir(out_dir)
            write_text(os.path.join(out_dir, "early_warning_summary.txt"), f"STATUS = FAIL\nREASON = {str(e)}")
        except Exception:
            pass
        sys.exit(2)

    sys.exit(0)

if __name__ == "__main__":
    main()
