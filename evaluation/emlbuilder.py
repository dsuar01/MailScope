"""Tiny helper used by the case generators to write .eml files."""
from email.message import EmailMessage
from email.utils import formatdate
import json
import os


def mk(frm, subject, text, *, to="recipient@example.org", html=None, reply_to=None,
       attachments=(), headers=None, msgid=None):
    m = EmailMessage()
    m["From"] = frm
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = formatdate(1_700_000_000, localtime=False)
    m["Message-ID"] = msgid or "<case@mailscope.test>"
    if reply_to:
        m["Reply-To"] = reply_to
    for k, v in (headers or {}).items():
        m[k] = v
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for name, ctype, data in attachments:
        main, sub = ctype.split("/", 1)
        m.add_attachment(data, maintype=main, subtype=sub, filename=name)
    return m.as_bytes()


def write_cases(outdir, cases):
    """cases: list of (id, label, note, bytes). Writes <id>.eml and labels.json."""
    os.makedirs(outdir, exist_ok=True)
    labels = {}
    for cid, label, note, raw in cases:
        with open(os.path.join(outdir, f"{cid}.eml"), "wb") as fh:
            fh.write(raw)
        labels[cid] = {"label": label, "note": note}
    with open(os.path.join(outdir, "labels.json"), "w", encoding="utf-8") as fh:
        json.dump(labels, fh, indent=2, ensure_ascii=False)
