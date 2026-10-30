"""Evaluate MailScope on a labelled folder of .eml files.

usage: python evaluation/run_eval.py <dir> [--threshold 40] [--verbose]

Labels: phishing | scam_spam | legit.  A message counts as "flagged" when the
indicator is >= threshold. Phishing and scam_spam are the positive class.
Analysis failures (exceptions, 'incomplete' verdicts) are counted separately and
never silently treated as correct.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from mailscope import analyze_bytes  # noqa: E402
from baseline_keyword import baseline_score  # noqa: E402

POS = {"phishing", "scam_spam"}


def run(dirpath, threshold):
    labels = json.load(open(os.path.join(dirpath, "labels.json"), encoding="utf-8"))
    rows = []
    for cid, meta in sorted(labels.items()):
        raw = open(os.path.join(dirpath, cid + ".eml"), "rb").read()
        try:
            a = analyze_bytes(raw)
            failed = a.verdict_code == "incomplete"
            rows.append(dict(id=cid, label=meta["label"], note=meta["note"], score=a.indicator, band=a.indicator_band,
                             code=a.verdict_code, verdict=a.verdict, failed=failed, base=baseline_score(raw),
                             top=[s.id for s in a.signals[:4]]))
        except Exception as exc:
            rows.append(dict(id=cid, label=meta["label"], note=meta["note"], score=0, band="-", code="exception",
                             verdict=f"EXCEPTION {exc!r}", failed=True, base=baseline_score(raw), top=[]))
    return rows


def metrics(rows, key, threshold):
    tp = fp = fn = tn = 0
    for r in rows:
        if r["failed"]:
            continue
        flagged = r[key] >= threshold
        pos = r["label"] in POS
        tp += flagged and pos; fp += flagged and not pos
        fn += (not flagged) and pos; tn += (not flagged) and not pos
    return tp, fp, fn, tn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--threshold", type=int, default=40)
    ap.add_argument("--base-threshold", type=int, default=50)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    rows = run(a.dir, a.threshold)
    n_pos = sum(r["label"] in POS for r in rows); n_neg = len(rows) - n_pos
    print(f"Set: {a.dir}   messages: {len(rows)} ({n_pos} suspicious, {n_neg} legitimate)")
    for name, key, th in (("MailScope", "score", a.threshold), ("MailScope (low-signal threshold 15)", "score", 15),
                          ("Naive keyword baseline*", "base", a.base_threshold)):
        tp, fp, fn, tn = metrics(rows, key, th)
        rec = tp / (tp + fn) if tp + fn else float("nan")
        prec = tp / (tp + fp) if tp + fp else float("nan")
        print(f"  {name:38s} flag>={th:<3d} TP={tp:2d} FN={fn:2d} FP={fp:2d} TN={tn:2d}  recall={rec:.2f} precision={prec:.2f}")
    fails = [r for r in rows if r["failed"]]
    print(f"  Analysis failures: {len(fails)}" + ("  -> " + ", ".join(r['id'] for r in fails) if fails else ""))
    # phishing vs spam typing among flagged positives
    wrong_type = [r for r in rows if r["label"] in POS and r["score"] >= a.threshold and
                  ((r["label"] == "phishing") != (r["code"] in ("phishing_likely", "suspicious")))]
    print(f"  Flagged but typed differently from label (phishing vs spam/scam): {len(wrong_type)}"
          + ("  -> " + ", ".join(f"{r['id']}[{r['code']}]" for r in wrong_type) if wrong_type else ""))
    print("\nDisagreements at threshold %d:" % a.threshold)
    bad = [r for r in rows if not r["failed"] and ((r["score"] >= a.threshold) != (r["label"] in POS))]
    for r in bad:
        kind = "FALSE NEGATIVE" if r["label"] in POS else "FALSE POSITIVE"
        print(f"  {kind}: {r['id']} label={r['label']} score={r['score']} verdict='{r['verdict']}' signals={r['top']}\n      note: {r['note']}")
    if not bad:
        print("  (none)")
    if a.verbose:
        print("\nAll rows:")
        for r in rows:
            print(f"  {r['id']:34s} {r['label']:10s} score={r['score']:3d} {r['band']:8s} {r['code']:16s} base={r['base']:3d} {r['top']}")
    print("\n* The keyword baseline is MY reconstruction of a simple additive keyword scorer, written for comparison. "
          "It is not your original code.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
