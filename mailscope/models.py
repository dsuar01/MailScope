"""Shared data structures. Plain dataclasses, no logic."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

# Strength tiers. The numbers are *evidence weights*, not probabilities.
STRENGTH_WEIGHT = {"strong": 0.60, "moderate": 0.30, "weak": 0.10, "combo": 0.75}

# Which kind of problem a signal category points to.
PHISH_CATEGORIES = {"impersonation", "deceptive_link", "credential", "payment",
                    "attachment", "reputation", "combo"}
SPAM_CATEGORIES = {"scam", "spam"}
ORIGIN_CATEGORIES = {"origin", "auth"}
SUPPORT_CATEGORIES = {"pressure"}  # urgency/threat wording: supports, never decides


@dataclass
class Signal:
    id: str
    category: str
    strength: str            # strong | moderate | weak | combo
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)

    @property
    def weight(self) -> float:
        return STRENGTH_WEIGHT[self.strength]


@dataclass
class Link:
    url: str
    host: str = ""
    registrable: str = ""
    text: str = ""            # visible anchor text, if any
    source: str = "text"      # html-a | html-form | text | pdf
    flags: list[str] = field(default_factory=list)


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    magic: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class ParsedEmail:
    headers: dict[str, list[str]] = field(default_factory=dict)
    from_name: str = ""
    from_addr: str = ""
    from_domain: str = ""
    reply_to_addrs: list[str] = field(default_factory=list)
    return_path: str = ""
    sender_hdr: str = ""
    message_id: str = ""
    subject: str = ""
    date: str = ""
    text: str = ""
    html_text: str = ""       # visible text extracted from HTML (never rendered)
    has_html: bool = False
    has_password_field: bool = False
    has_form: bool = False
    has_script: bool = False
    remote_image_count: int = 0
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    raw: bytes = b""
    parse_notes: list[str] = field(default_factory=list)  # non-fatal problems
    # attachment payloads kept in memory only for static inspection
    attachment_payloads: list[tuple[str, bytes]] = field(default_factory=list, repr=False)


@dataclass
class Assessment:
    verdict: str
    verdict_code: str          # phishing_likely | suspicious | spam_scam | minor | none | failed
    indicator: int
    indicator_band: str
    indicator_meaning: str
    origin_status: str
    origin_detail: str
    content_status: str
    reasons: list[Signal]
    signals: list[Signal]
    unknowns: list[str]
    checks_run: dict[str, str]
    actions: list[str]
    evidence_coverage: str
    parsed_summary: dict[str, Any] = field(default_factory=dict)
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    auth_claims: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
