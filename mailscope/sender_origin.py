"""Sender identity checks: what the message CLAIMS to be vs what the addresses say.

These are consistency checks on header text. A forged message can set every one of
these headers to anything, so a clean result here proves nothing about origin.
"""
from __future__ import annotations

import re

from .domains import (ABUSED_TLDS, FREE_HOSTING, normalize_display, BRAND_ALIASES, BRANDS, FREEMAIL, SERVICE_WORDS, brand_for_domain, suffix_of,
                      brand_lookalike, idn_findings, is_genuine_brand_domain,
                      registrable_domain, to_unicode_host)
from .models import ParsedEmail, Signal

ORG_WORDS = re.compile(r"\b(team|department|dept|support|help ?desk|hr|human resources|careers|billing|accounts?|accounting|payroll|admin(istrator)?|"
                       r"security|service|services|customer (care|service)|notices?|no-?reply|recruit\w*|alerts?|finance|claims?)\b", re.I)
EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def display_name_brands(display: str) -> list[str]:
    """Brands a display name claims to be. Everyday-word brands need a service word."""
    d = re.sub(r"[^a-z0-9 ]+", " ", normalize_display(display).lower())
    d = " ".join(d.split())
    found: list[str] = []
    for alias, brand in sorted(BRAND_ALIASES.items(), key=lambda kv: -len(kv[0])):
        if brand not in BRANDS or brand in found:
            continue
        if not re.search(rf"\b{re.escape(alias)}\b", d):
            continue
        if BRANDS[brand]["ambiguous"]:
            stripped = re.sub(rf"\b{re.escape(alias)}\b", "", d).strip()
            if stripped and not SERVICE_WORDS.search(stripped):
                continue  # "Apple Pie Recipes" is not Apple
        found.append(brand)
    return found


def analyze_sender(pe: ParsedEmail) -> tuple[list[Signal], dict]:
    sigs: list[Signal] = []
    info = {"from": pe.from_addr, "from_domain": pe.from_domain, "freemail": False,
            "brand_claimed": None, "brand_genuine": False}

    if not pe.from_addr or "@" not in pe.from_addr:
        sigs.append(Signal("no_from", "origin", "moderate", "No usable From address",
                           "The message has no parseable sender address, so its origin cannot be assessed.",
                           [f"From header: {pe.headers.get('from', ['(missing)'])[0][:120]}"]))
        return sigs, info

    fdom = registrable_domain(pe.from_domain)
    info["freemail"] = fdom in FREEMAIL
    if len(pe.headers.get("from", [])) > 1:
        sigs.append(Signal("multi_from", "origin", "moderate", "Multiple From headers",
                           "A message with more than one From header is malformed and sometimes used to confuse mail clients.",
                           [", ".join(pe.headers["from"])[:200]]))

    # Display name that embeds a different address: "support@paypal.com" <x@evil.test>
    for m in EMAIL_IN_TEXT.findall(pe.from_name):
        d = registrable_domain(m.split("@", 1)[1].lower())
        if d != fdom:
            sigs.append(Signal("display_address_mismatch", "impersonation", "strong",
                               "Display name shows a different email address than the real sender",
                               "The name shown in most mail apps contains an address on one domain while the message actually comes from another.",
                               [f"Display name: {pe.from_name!r}", f"Actual sender: {pe.from_addr}"]))
            break

    # Display name claims a known brand but the domain is not that brand's
    claimed = display_name_brands(pe.from_name)
    if claimed:
        brand = claimed[0]
        info["brand_claimed"] = brand
        if is_genuine_brand_domain(brand, fdom):
            info["brand_genuine"] = True
        else:
            sigs.append(Signal("brand_display_mismatch", "impersonation", "strong",
                               f"Sender name claims to be {brand}, but the domain is not {brand}'s",
                               "Display names are free text and are the first thing most people see. The sending domain is not one of this brand's known domains. "
                               "(Legitimate third-party services can send for a brand, so this is evidence, not proof.)",
                               [f"Display name: {pe.from_name!r}", f"Sending domain: {fdom}"]))

    # Organisational-sounding name on a free mailbox ("Careers Team <x@gmail.com>")
    if info["freemail"] and ORG_WORDS.search(pe.from_name):
        sigs.append(Signal("org_name_on_freemail", "origin", "moderate",
                           "Organisation-style sender name on a free mailbox",
                           "Names like 'Support Team' or 'HR Department' sent from a free mail account are a common way to look official without owning a domain.",
                           [f"Display name: {pe.from_name!r}", f"Sending domain: {fdom}"]))

    # Lookalike sending domain
    look = brand_lookalike(pe.from_domain)
    if look:
        sigs.append(Signal("lookalike_sender_domain", "impersonation", look["strength"],
                           f"Sending domain imitates {look['brand']}",
                           look["why"] + ".", [f"Sender domain: {to_unicode_host(pe.from_domain)}"]))
    mixed = idn_findings(pe.from_domain)
    if mixed:
        sigs.append(Signal("mixed_script_sender", "impersonation", "strong",
                           "Sending domain mixes alphabets",
                           "Mixing scripts (for example Cyrillic letters inside a Latin word) is a classic way to fake a familiar domain.",
                           mixed))

    if fdom in FREE_HOSTING:
        sigs.append(Signal("sender_on_free_hosting", "origin", "weak",
                           "Sender address sits on a free app-hosting platform",
                           "Anyone can create an address on these platforms in seconds, so it says nothing about who is behind the message. "
                           "Genuine apps do send from them, so this is only a hint.",
                           [f"Sending domain: {pe.from_domain}"]))
    if fdom and suffix_of(fdom).split(".")[-1] in ABUSED_TLDS:
        sigs.append(Signal("sender_abused_tld", "origin", "weak",
                           "Sending domain ends in a heavily abused domain ending",
                           "Many legitimate senders use these endings too; this only matters together with other evidence.",
                           [f"Sending domain: {fdom}"]))

    # Reply-To pointing somewhere else
    for rt in pe.reply_to_addrs:
        rdom = registrable_domain(rt.rsplit("@", 1)[-1])
        if rdom and rdom != fdom:
            if rdom in FREEMAIL and not info["freemail"]:
                sigs.append(Signal("reply_to_freemail", "origin", "moderate",
                                   "Replies would go to a free mail account, not the sender's domain",
                                   "The visible sender is on one domain, but replies are redirected to a free mailbox that anyone can create.",
                                   [f"From: {pe.from_addr}", f"Reply-To: {rt}"]))
            else:
                sigs.append(Signal("reply_to_diverges", "origin", "weak",
                                   "Reply-To domain differs from the sender's domain",
                                   "Common for mailing services and help desks, but also how fraudsters redirect replies.",
                                   [f"From: {pe.from_addr}", f"Reply-To: {rt}"]))
            break
    return sigs, info
