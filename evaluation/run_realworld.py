"""Run MailScope over a folder of REAL-WORLD .eml files that this project did not write.

usage: python3 -I evaluation/run_realworld.py <folder> [--limit N] [--out summary.json]

Intended corpus: Phishing Pot (https://github.com/rf-peixoto/phishing_pot, CC BY-NC 4.0). It is NOT
copied into this project; clone it somewhere else and point this script at its `email` folder.

What this can and cannot tell you
  * Every file in that corpus is malicious or unsolicited mail (phishing, fraud, spam, malware
    delivery). There is NO legitimate mail in it, so this measures the DETECTION RATE on real
    phishing-type mail. It says NOTHING about false positives.
  * Individual messages are not labelled by type, so the result is "flagged / not flagged", not
    phishing-vs-spam accuracy.
  * Files are only parsed as text. Nothing is opened, rendered or visited, and this script makes
    network access impossible while it runs (any attempt is counted and reported).
  * Only aggregate numbers and file NAMES of misses are written, never message content.
"""
import argparse
import collections
import json
import os
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from mailscope import analyze_bytes  # noqa: E402

network_attempts = 0


def _blocked(*_a, **_k):
    global network_attempts
    network_attempts += 1
    raise OSError("network access is disabled during the real-world run")


socket.socket.connect = _blocked
socket.create_connection = _blocked
socket.getaddrinfo = _blocked


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    names = sorted(n for n in os.listdir(args.folder) if n.lower().endswith(".eml"))
    if args.limit:
        names = names[: args.limit]
    codes = collections.Counter()
    bands = collections.Counter()
    sig_counter = collections.Counter()
    missed_at_15, missed_at_40, failures = [], [], []
    flagged40 = flagged15 = 0
    non_english = non_english_flagged40 = 0
    t0 = time.time()
    for i, n in enumerate(names, 1):
        try:
            with open(os.path.join(args.folder, n), "rb") as fh:
                raw = fh.read()
            a = analyze_bytes(raw)
        except Exception as exc:  # the engine promises not to raise; if it does, that is a failure we must show
            failures.append((n, f"EXCEPTION {exc.__class__.__name__}"))
            continue
        codes[a.verdict_code] += 1
        bands[a.indicator_band] += 1
        if a.verdict_code == "incomplete":
            failures.append((n, "incomplete: " + "; ".join(a.errors)[:120]))
            continue
        for s in a.signals:
            sig_counter[s.id.split(":")[0]] += 1
        ne = any("does not look English" in u for u in a.unknowns)
        non_english += ne
        if a.indicator >= 40:
            flagged40 += 1
            non_english_flagged40 += ne
        else:
            missed_at_40.append(n)
        if a.indicator >= 15:
            flagged15 += 1
        else:
            missed_at_15.append(n)
        if i % 2000 == 0:
            print(f"  ... {i}/{len(names)}", file=sys.stderr)
    scored = len(names) - len(failures)
    summary = {
        "messages": len(names), "scored": scored, "analysis_failures": len(failures),
        "flagged_at_40": flagged40, "flagged_at_15": flagged15,
        "rate_at_40": round(flagged40 / scored, 4) if scored else None,
        "rate_at_15": round(flagged15 / scored, 4) if scored else None,
        "verdict_codes": dict(codes), "indicator_bands": dict(bands),
        "network_attempts_blocked": network_attempts,
        "non_english_messages": non_english, "non_english_flagged_at_40": non_english_flagged40,
        "seconds": round(time.time() - t0, 1),
        "most_common_signals": sig_counter.most_common(25),
        "failures_first_20": failures[:20],
        "not_flagged_at_40_first_40_names": missed_at_40[:40],
        "not_flagged_at_15_count": len(missed_at_15),
    }
    print(json.dumps(summary, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({**summary, "not_flagged_at_40_all": missed_at_40, "not_flagged_at_15_all": missed_at_15,
                       "failures_all": failures}, fh, indent=1)


if __name__ == "__main__":
    main()
