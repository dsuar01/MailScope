"""A deliberately simple additive keyword scorer, used ONLY as a comparison point.

This is a reconstruction of the 'fixed indicator points' approach described in the
project brief, written for this evaluation. It is not the original MailScope code
(which was not available), so any before/after comparison against it is indicative
only.
"""
import email
import re
from email import policy

POINTS = [
    (r"\burgent|immediately|within 24 hours|final notice", 15),
    (r"\bverify|confirm your|validate", 15),
    (r"\bpassword", 15),
    (r"\bsuspend|locked|unauthori[sz]ed", 15),
    (r"click here", 10),
    (r"\bwinner|you have won|lottery|prize", 20),
    (r"\baccount", 5),
    (r"wire transfer|gift card", 15),
    (r"\bviagra|cialis|casino", 20),
]


def baseline_score(raw: bytes) -> int:
    msg = email.message_from_bytes(raw, policy=policy.default)
    text = (str(msg["subject"] or "") + " ").lower()
    attach = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_filename():
            attach += 1
            continue
        try:
            text += part.get_content().lower() + " "
        except Exception:
            pass
    score = sum(p for pat, p in POINTS if re.search(pat, text))
    score += 10 * min(attach, 1)
    score += 5 if re.search(r"https?://", text) else 0
    return min(100, score)
