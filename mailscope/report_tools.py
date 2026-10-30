"""Exportable reports (text, JSON, HTML). All English; HTML is static and escaped."""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone

from .models import Assessment

LIMITS = [
    "MailScope is a first-pass triage aid. It cannot prove that a message is genuine, and it can miss well-crafted attacks.",
    "It never opens attachments, renders HTML, loads images or visits links, so what those would show is unknown.",
    "SPF/DMARC and the true delivery path cannot be reconstructed from an exported file.",
    "The indicator is an evidence-strength score from expert-set weights, not a probability.",
]


def defang(url: str) -> str:
    """Make a URL unclickable in reports: http -> hxxp, dots in the host bracketed."""
    u = re.sub(r"(?i)^http", "hxxp", url.strip())
    m = re.match(r"(?i)^(hxxps?://)?([^/?#]+)(.*)$", u, re.S)
    if not m:
        return u
    return (m.group(1) or "") + m.group(2).replace(".", "[.]") + m.group(3)


URL_IN_TEXT = re.compile(r"(?i)\b(https?://[^\s<>\"')]+)")


def defang_text(text: str) -> str:
    """Defang every URL inside free text (evidence lines, wording snippets)."""
    return URL_IN_TEXT.sub(lambda m: defang(m.group(1)), str(text))


def to_json(a: Assessment) -> str:
    d = a.to_dict()
    for key in ("reasons", "signals"):
        for sig in d[key]:
            sig["evidence"] = [defang_text(x) for x in sig["evidence"]]
            sig["detail"] = defang_text(sig["detail"])
    d["unknowns"] = [defang_text(x) for x in d["unknowns"]]
    d["generated_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    d["links"] = [dict(l, url=defang(l["url"])) for l in d["links"]]
    return json.dumps(d, indent=2, ensure_ascii=False)


def to_text(a: Assessment) -> str:
    L = ["MAILSCOPE REPORT", "=" * 60, f"Verdict:   {a.verdict}",
         f"Indicator: {a.indicator}/100 ({a.indicator_band})", f"           {a.indicator_meaning}",
         f"Evidence coverage: {a.evidence_coverage}", "", "SENDER / ORIGIN", f"  {a.origin_status}", f"  {a.origin_detail}",
         "", "CONTENT, LINKS, ATTACHMENTS", f"  {a.content_status}", "", "MESSAGE"]
    L += [f"  {k}: {v}" for k, v in a.parsed_summary.items()]
    L += ["", "MAIN REASONS"]
    for s in a.reasons or []:
        L.append(f"  [{s.strength}] {s.title}")
        L.append(f"      {s.detail}")
        L += [f"      - {defang_text(e)}" for e in s.evidence]
    if not a.reasons:
        L.append("  (none)")
    L += ["", "WHAT TO DO"] + [f"  - {x}" for x in a.actions]
    L += ["", "WHAT COULD NOT BE VERIFIED"] + [f"  - {x}" for x in a.unknowns]
    L += ["", "CHECKS"] + [f"  {k}: {v}" for k, v in a.checks_run.items()]
    if a.auth_claims:
        L += ["", "RECORDED AUTHENTICATION CLAIMS (untrusted text, not verified)"] + [f"  {c}" for c in a.auth_claims]
    if a.links:
        L += ["", "LINKS (defanged)"] + [f"  {defang(l.url)}  [{l.source}]" for l in a.links[:50]]
    if a.attachments:
        L += ["", "ATTACHMENTS (never opened)"] + [f"  {t.filename}  {t.content_type}  {t.size} bytes  sha256={t.sha256}" for t in a.attachments]
    L += ["", "LIMITS"] + [f"  - {x}" for x in LIMITS]
    return "\n".join(L)


def to_html(a: Assessment) -> str:
    e = html.escape
    color = {"phishing_likely": "#b3261e", "suspicious": "#b3261e", "spam_scam": "#9a5b00", "minor": "#7a6200",
             "none": "#3b5b3b", "incomplete": "#555"}.get(a.verdict_code, "#333")
    def ul(items): return "<ul>" + "".join(f"<li>{e(str(i))}</li>" for i in items) + "</ul>"
    reasons = "".join(
        f"<div class='r'><b>{e(s.title)}</b> <span class='t'>{e(s.strength)}</span><p>{e(s.detail)}</p>{ul([defang_text(x) for x in s.evidence])}</div>"
        for s in a.reasons) or "<p>None.</p>"
    rows = "".join(f"<tr><th>{e(str(k))}</th><td>{e(str(v))}</td></tr>" for k, v in a.parsed_summary.items())
    checks = "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in a.checks_run.items())
    links = ul([f"{defang(l.url)}  [{l.source}]" for l in a.links[:50]]) if a.links else "<p>None.</p>"
    atts = ul([f"{t.filename} - {t.content_type}, {t.size} bytes, sha256 {t.sha256}" for t in a.attachments]) if a.attachments else "<p>None.</p>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>MailScope report</title><style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:820px;margin:2rem auto;padding:0 1rem;color:#222}}
h1{{font-size:1.3rem}} h2{{font-size:1.05rem;margin-top:1.6rem;border-bottom:1px solid #ddd}}
.v{{border-left:6px solid {color};padding:.6rem 1rem;background:#f7f7f7}} .v b{{color:{color};font-size:1.2rem}}
th{{text-align:left;padding-right:1rem;vertical-align:top}} .t{{font-size:.8rem;color:#666}} .r{{margin:.6rem 0}}
code{{background:#eee;padding:0 3px}}</style></head><body>
<h1>MailScope report</h1>
<div class="v"><b>{e(a.verdict)}</b><br>Indicator: <b>{a.indicator}/100</b> ({e(a.indicator_band)}). Evidence coverage: {e(a.evidence_coverage)}.<br>
<small>{e(a.indicator_meaning)}</small></div>
<h2>Sender / origin</h2><p><b>{e(a.origin_status)}</b><br>{e(a.origin_detail)}</p>
<h2>Content, links, attachments</h2><p>{e(a.content_status)}</p>
<h2>Main reasons</h2>{reasons}
<h2>What to do</h2>{ul(a.actions)}
<h2>What could not be verified</h2>{ul(a.unknowns)}
<h2>Message</h2><table>{rows}</table>
<h2>Checks performed</h2><table>{checks}</table>
<h2>Links (defanged, never visited)</h2>{links}
<h2>Attachments (never opened)</h2>{atts}
<h2>Limits</h2>{ul(LIMITS)}</body></html>"""
