"""Command line: python -m mailscope message.eml [--format text|json|html] [--dkim] [--feed FILE]"""
import argparse
import sys

from .report_tools import to_html, to_json, to_text
from .risk_assessment import analyze_bytes


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mailscope", description="Analyse a saved .eml file locally.")
    p.add_argument("file")
    p.add_argument("--format", choices=["text", "json", "html"], default="text")
    p.add_argument("--dkim", action="store_true", help="verify DKIM signatures (does DNS lookups for signer keys)")
    p.add_argument("--feed", default="", help="local text file of known-bad domains/URLs")
    args = p.parse_args(argv)
    try:
        raw = open(args.file, "rb").read()
    except OSError as exc:
        print(f"Cannot read file: {exc}", file=sys.stderr)
        return 2
    a = analyze_bytes(raw, dkim_enabled=args.dkim, feed_path=args.feed)
    print({"text": to_text, "json": to_json, "html": to_html}[args.format](a))
    return 0


if __name__ == "__main__":
    sys.exit(main())
