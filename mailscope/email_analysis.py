"""Safe MIME parsing.

Nothing here executes, renders, or fetches anything. HTML is only tokenised into
text, links and a few structural facts. Attachments stay as bytes in memory.
"""
from __future__ import annotations

import email
import hashlib
import re
import unicodedata
from email import policy
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .domains import normalize_host, registrable_domain
from .models import Attachment, Link, ParsedEmail

MAX_BYTES = 25 * 1024 * 1024
MAX_PART_TEXT = 2 * 1024 * 1024
URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'\)\]]+)""")
ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)


def clean_text(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "").translate(ZERO_WIDTH)
    return re.sub(r"[ \t\r\f\v]+", " ", s)


class _HTMLScan(HTMLParser):
    """Collects visible text, anchors, forms and structural flags. Never renders."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.anchors: list[tuple[str, str]] = []
        self.form_actions: list[str] = []
        self.has_password = False
        self.has_form = False
        self.has_script = False
        self.remote_images = 0
        self.iframes: list[str] = []
        self._a_href: str | None = None
        self._a_text: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip += 1
            if tag == "script":
                self.has_script = True
        elif tag == "a" and a.get("href"):
            self._a_href, self._a_text = a["href"], []
        elif tag == "form":
            self.has_form = True
            if a.get("action"):
                self.form_actions.append(a["action"])
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.has_password = True
        elif tag == "img" and re.match(r"(?i)https?://", a.get("src", "")):
            self.remote_images += 1
        elif tag in ("iframe", "embed", "object") and a.get("src"):
            self.iframes.append(a["src"])
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._a_href is not None:
            self.anchors.append((self._a_href, " ".join("".join(self._a_text).split())))
            self._a_href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._a_href is not None:
            self._a_text.append(data)


def _safe_decode(data: bytes, charset: str | None) -> str:
    """Decode bytes with the declared charset; an unknown or bogus charset name falls back, never raises."""
    for cs in (charset, "utf-8"):
        if not cs:
            continue
        try:
            return data.decode(cs, "replace")
        except (LookupError, ValueError):
            continue
    return data.decode("latin-1", "replace")


def _decode_part(part) -> str:
    try:
        content = part.get_content()
        if isinstance(content, bytes):
            content = _safe_decode(content, part.get_content_charset())
        return content[:MAX_PART_TEXT]
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return _safe_decode(payload[:MAX_PART_TEXT], part.get_content_charset())


def _addr(value: str) -> tuple[str, str]:
    name, addr = parseaddr(value or "")
    return name.strip(), addr.strip().lower()


def make_link(url: str, text: str = "", source: str = "text") -> Link | None:
    url = url.strip().strip(".,;:!?)>\"'")
    if not url:
        return None
    probe = url if re.match(r"(?i)^[a-z][a-z0-9+.-]*:", url) else "http://" + url
    scheme = probe.split(":", 1)[0].lower()
    if scheme not in ("http", "https"):
        return None  # mailto:, tel:, cid:, javascript: are handled elsewhere
    try:
        parts = urlsplit(probe)
        host = normalize_host(parts.hostname or "")
    except ValueError:
        return Link(url=url, text=text, source=source, flags=["unparseable"])
    if not host:
        return None
    link = Link(url=url, host=host, registrable=registrable_domain(host), text=text, source=source)
    if "@" in (parts.netloc or ""):
        link.flags.append("userinfo")
    if scheme == "http":
        link.flags.append("plain_http")
    return link


def parse_email(raw: bytes) -> ParsedEmail:
    pe = ParsedEmail(raw=raw[:MAX_BYTES])
    if len(raw) > MAX_BYTES:
        pe.parse_notes.append("File larger than 25 MB: only the first 25 MB were analysed.")
    msg = email.message_from_bytes(pe.raw, policy=policy.default)

    for k in msg.keys():
        pe.headers.setdefault(k.lower(), []).append(str(msg[k]) if msg[k] is not None else "")
    for d in msg.defects if hasattr(msg, "defects") else []:
        pe.parse_notes.append(f"MIME defect: {d.__class__.__name__}")

    def h(name: str) -> str:
        v = pe.headers.get(name.lower())
        return v[0] if v else ""

    pe.from_name, pe.from_addr = _addr(h("from"))
    pe.from_domain = pe.from_addr.rsplit("@", 1)[-1] if "@" in pe.from_addr else ""
    if len(pe.headers.get("from", [])) > 1:
        pe.parse_notes.append("Message has more than one From header (unusual).")
    pe.reply_to_addrs = [a.lower() for _, a in getaddresses(pe.headers.get("reply-to", [])) if a]
    pe.return_path = _addr(h("return-path"))[1]
    pe.sender_hdr = _addr(h("sender"))[1]
    pe.message_id = h("message-id").strip()
    pe.subject = clean_text(h("subject"))
    pe.date = h("date")

    text_parts, html_parts = [], []
    scans: list[_HTMLScan] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if filename or disp == "attachment" or (ctype not in ("text/plain", "text/html") and not ctype.startswith("multipart")):
            if ctype in ("message/rfc822",):
                pe.parse_notes.append("Contains an attached email (message/rfc822); its contents are not analysed separately.")
            payload = part.get_payload(decode=True) or b""
            if isinstance(payload, str):
                payload = payload.encode("utf-8", "replace")
            name = str(filename or f"(unnamed {ctype})")
            pe.attachments.append(Attachment(
                filename=name, content_type=ctype, size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(), magic=payload[:8].hex()))
            pe.attachment_payloads.append((name, payload))
            continue
        content = _decode_part(part)
        if ctype == "text/html":
            html_parts.append(content)
        else:
            text_parts.append(content)

    pe.text = clean_text("\n".join(text_parts))
    seen: set[str] = set()

    def add(link: Link | None):
        if link and (link.url, link.source) not in seen:
            seen.add((link.url, link.source))
            pe.links.append(link)

    for html in html_parts:
        pe.has_html = True
        sc = _HTMLScan()
        try:
            sc.feed(html)
            sc.close()
        except Exception as exc:  # malformed HTML must not crash analysis
            pe.parse_notes.append(f"HTML parsing problem: {exc.__class__.__name__}")
        scans.append(sc)
        pe.has_password_field |= sc.has_password
        pe.has_form |= sc.has_form
        pe.has_script |= sc.has_script
        pe.remote_image_count += sc.remote_images
        pe.html_text += clean_text("".join(sc.text)) + "\n"
        for href, txt in sc.anchors:
            add(make_link(href, clean_text(txt), "html-a"))
        for act in sc.form_actions:
            add(make_link(act, "", "html-form"))
        for src in sc.iframes:
            add(make_link(src, "", "html-embed"))
    for blob in (pe.text, pe.html_text):
        for m in URL_RE.finditer(blob):
            add(make_link(m.group(1), "", "text"))

    if not (pe.text.strip() or pe.html_text.strip()):
        pe.parse_notes.append("No readable text body was found (possibly image-only or attachment-only).")
    return pe


def visible_body(pe: ParsedEmail) -> str:
    """Single text blob for content analysis: subject + plain text + visible HTML text."""
    return clean_text("\n".join(x for x in (pe.subject, pe.text, pe.html_text) if x))
