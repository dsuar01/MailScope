"""Text-obfuscation checks on the sender's display name and the subject.

Criminals pad or disguise brand names so filters and people do not recognise them:
  * invisible characters inside a word: "Coin<zero-width>base";
  * look-alike letters from another alphabet inside a Latin word: "Соngrаtulаtіоns" (Cyrillic о, а, і).
Real senders have no reason to do either in the name that identifies them, so this is
language-independent structural evidence.

Not flagged on purpose: emoji (their joiners and selectors follow non-letters), Persian/Indic
joiners (they sit in non-Latin words), and body text (marketing mail pads its preview text with
invisible characters).
"""
from __future__ import annotations

import re
import unicodedata

from .domains import scripts_in
from .models import ParsedEmail, Signal


def _invisible(ch: str) -> bool:
    cp = ord(ch)
    return (unicodedata.category(ch) == "Cf" or 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF) and ch not in "‎‏"


def _findings(text: str) -> tuple[int, list[str]]:
    """Return (number of suspicious words, short descriptions)."""
    bad, notes = 0, []
    for tok in text.split():
        invis = [c for c in tok if _invisible(c)]
        letters = "".join(c for c in tok if c.isalpha())
        sc = scripts_in(letters)
        if invis and len(letters) >= 3 and sc == {"LATIN"}:
            # variation selector after an emoji-like symbol is normal; here they sit between Latin letters
            if any(_invisible(tok[i]) and i > 0 and tok[i - 1].isalpha() for i in range(len(tok))):
                bad += 1
                notes.append(f"{len(invis)} invisible character(s) inside the word '{''.join(c for c in tok if not _invisible(c))}'")
                continue
        if "LATIN" in sc and (sc & {"CYRILLIC", "GREEK"}):
            bad += 1
            notes.append(f"letters from different alphabets mixed inside the word '{letters}'")
    return bad, notes


def analyze_obfuscation(pe: ParsedEmail) -> list[Signal]:
    out: list[Signal] = []
    nbad, notes = _findings(pe.from_name or "")
    if nbad:
        out.append(Signal("name_obfuscation", "impersonation", "strong",
                          "Sender name is disguised with invisible or look-alike characters",
                          "A sender name that hides characters or swaps letters from another alphabet is trying to look like a "
                          "well-known name without matching it. Genuine senders do not do this.",
                          notes[:3]))
    sbad, snotes = _findings(pe.subject or "")
    if sbad:
        out.append(Signal("subject_obfuscation", "impersonation", "moderate",
                          "Subject line is disguised with invisible or look-alike characters",
                          "Mixing alphabets or hiding characters inside words is a way to slip past spam filters.",
                          snotes[:3]))
    return out
