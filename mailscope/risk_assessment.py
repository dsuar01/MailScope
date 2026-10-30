"""Combine evidence into one coherent assessment.

How the number works (and what it is NOT)
-----------------------------------------
Every signal has a tier (weak / moderate / strong). The indicator combines tiers as
independent pieces of evidence:  indicator = 100 * (1 - product(1 - weight)).
Within one category each further signal counts half as much as the one before (1, 1/2, 1/4, ...), so ten near-identical hits do not
look like ten independent clues. Combination rules add explicit signals (for example
"deceptive sender + request for action"), so the verdict and the number come from the
SAME list of signals and cannot contradict each other.

The weights are expert judgement, not fitted to data. The result is therefore an
*evidence-strength indicator*, NOT the probability that the message is phishing.
A probability would need a large, representative labelled corpus, which this
project does not have. Missing evidence never lowers the number and never produces
a "safe" verdict: it is listed as unknown.
"""
from __future__ import annotations

from .attachment_analysis import analyze_attachments
from .authentication_checks import analyze_auth
from .content_analysis import analyze_content, looks_non_english
from .domains import FREEMAIL, TRACKING_DOMAINS, brand_for_domain, is_genuine_brand_domain, registrable_domain
from .email_analysis import parse_email, visible_body
from .link_analysis import analyze_links
from .obfuscation import analyze_obfuscation
from .models import (ORIGIN_CATEGORIES, PHISH_CATEGORIES, SPAM_CATEGORIES, STRENGTH_WEIGHT,
                     Assessment, ParsedEmail, Signal)
from .reputation_checks import check_reputation
from .sender_origin import analyze_sender

INDICATOR_MEANING = (
    "This number measures how much independent suspicious evidence MailScope found (0 = none found, 100 = overwhelming). "
    "It is NOT the probability that the message is phishing: the weights are expert judgement, not fitted to real-world data."
)
COMMON_LINK_DOMAINS = {"facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "youtube.com", "pinterest.com",
                       "tiktok.com", "apple.com", "google.com", "whatsapp.com"}
DECEPTION_CATS = {"impersonation", "deceptive_link"}
INTENT_CATS = {"credential", "payment", "scam", "attachment", "pressure"}


def band_for(score: int) -> str:
    return "High" if score >= 70 else "Medium" if score >= 40 else "Low" if score >= 15 else "Minimal"


def combine(signals: list[Signal]) -> int:
    by_cat: dict[str, list[float]] = {}
    for s in signals:
        by_cat.setdefault(s.category, []).append(s.weight)
    remaining = 1.0
    for ws in by_cat.values():
        for i, w in enumerate(sorted(ws, reverse=True)):
            remaining *= 1 - w * (0.5 ** i)
    return min(99, round(100 * (1 - remaining)))


def _link_context(pe: ParsedEmail, sender_reg: str, brand_genuine_of: str | None) -> dict:
    clickable = [l for l in pe.links if l.source in ("html-a", "html-form", "text", "pdf") and l.registrable]
    if not clickable or not sender_reg:
        return {"all_links_on_sender_domain": False, "unrelated": [], "clickable": clickable}
    def on_sender(l):
        return l.registrable == sender_reg
    tracked = [l for l in clickable if l.registrable in TRACKING_DOMAINS]
    unrelated = [l for l in clickable if not on_sender(l) and l not in tracked]
    return {"all_links_on_sender_domain": not unrelated and not tracked, "unrelated": unrelated, "tracked": tracked, "clickable": clickable}


def _combination_signals(signals: list[Signal], pe: ParsedEmail, ctx: dict, sender_info: dict, families: list[str]) -> list[Signal]:
    ids = {s.id for s in signals}
    cats = lambda *c: [s for s in signals if s.category in c]
    out: list[Signal] = []

    deception = [s for s in cats(*DECEPTION_CATS) if s.strength in ("strong", "moderate")]
    intent = [s for s in cats(*INTENT_CATS) if not (s.category == "attachment" and s.strength == "weak")]
    if deception and intent:
        out.append(Signal("combo_deception_intent", "combo", "combo",
                          "Deceptive identity or link combined with a request for action",
                          "Faking who the message is from or where a link goes, while also pushing you to log in, pay, open a file or hurry, is the core pattern of phishing and fraud.",
                          [f"Deception: {deception[0].title}", f"Action pressure: {intent[0].title}"]))

    pay = [s for s in signals if s.id in ("payment_request", "callback_scam")]
    redirect = {"reply_to_freemail", "reply_to_diverges"} & ids
    freemail_exec = sender_info.get("freemail") and "exec_request" in ids
    if pay and (redirect or freemail_exec or "display_address_mismatch" in ids):
        out.append(Signal("combo_payment_redirect", "combo", "combo",
                          "Payment or money request combined with diverted replies or a free-mail sender",
                          "A request to change or send money, with replies going to a different or free mailbox, is the typical business-email-compromise pattern.",
                          [pay[0].title, "Replies go elsewhere" if redirect else "Sender uses a free mailbox"]))

    cred = [s for s in signals if s.id in ("credential_request", "payment_request") and s.strength in ("moderate", "strong")]
    if cred and ctx.get("unrelated") and not sender_info.get("brand_genuine"):
        out.append(Signal("combo_credential_unrelated_link", "combo", "moderate",
                          "Login or payment-detail request sends you to a site unrelated to the sender",
                          "The message asks you to sign in, verify or change payment details, and its links lead to a domain that is not the sender's.",
                          [f"Sender domain: {sender_info.get('from_domain')}"] + [l.url[:120] for l in ctx["unrelated"][:3]]))

    # A well-known brand's own domain in From, yet none of the links go to that brand: either the From is forged
    # or the links are not the brand's. (Social-media and app-store links are common in genuine brand mail.)
    sender_brand = sender_info.get("sender_domain_brand")
    clickable = ctx.get("clickable") or []
    if sender_brand and clickable and not ctx.get("tracked"):
        sender_reg = sender_info.get("sender_reg", "")
        on_brand = [l for l in clickable if l.registrable == sender_reg or is_genuine_brand_domain(sender_brand, l.registrable)]
        foreign = [l for l in clickable if l not in on_brand and l.registrable not in COMMON_LINK_DOMAINS]
        if foreign and not on_brand:
            out.append(Signal("brand_sender_foreign_links", "deceptive_link", "moderate",
                              f"Message is from {sender_brand}'s domain, but none of its links go to {sender_brand}",
                              "Genuine mail from a brand links to the brand's own sites (or its mail-sending provider). Either the sender address is forged "
                              "or the links are not the brand's. A forged From address cannot be ruled out from a saved file.",
                              [f"Sender domain: {sender_reg}"] + [l.url[:120] for l in foreign[:3]]))

    risky_att = [s for s in signals if s.category == "attachment" and s.strength in ("moderate", "strong")]
    if risky_att and ({"invoice_lure", "doc_lure", "attach_ref"} & set(families)):
        out.append(Signal("combo_attachment_lure", "combo", "moderate",
                          "Risky attachment type that the message asks you to open",
                          "Macro-enabled, disk-image and similar attachment types introduced as an invoice, document, resume or simply 'see attached' are a standard malware-delivery pattern.",
                          [risky_att[0].title]))

    scam = [s for s in signals if s.category == "scam"]
    if scam and ("reply_to_freemail" in ids or (sender_info.get("freemail") and not pe.links)):
        out.append(Signal("combo_scam_freemail", "scam", "moderate",
                          "Windfall or fee request combined with a free-mail contact address",
                          "Advance-fee scams ask you to reply to an anonymous mailbox.", [scam[0].title]))
    return out


def _unknowns(pe: ParsedEmail, claims: list[str], dkim, rep_status: dict, ctx: dict, links, errors) -> list[str]:
    u = [
        "SPF and DMARC cannot be re-checked from a saved file: they depend on the connecting server's IP address and the DNS records at delivery time.",
        "The delivery path (Received headers) is only trustworthy for hops added by your own mail provider; earlier hops can be forged, so true origin is not established.",
        "Domain age and registration details were not looked up (no network lookups are made by default).",
    ]
    if claims:
        u.append("Authentication-Results headers in this file are recorded text, not verification; MailScope gives them no credit.")
    if dkim.status == "not_performed":
        u.append("DKIM signatures were not cryptographically verified (optional check not enabled).")
    elif dkim.status == "unavailable":
        u.append("DKIM verification could not run: " + dkim.detail)
    elif dkim.status == "error":
        u.append("DKIM verification hit errors: " + dkim.detail)
    elif dkim.status == "no_signature":
        u.append("No DKIM signature present, so the signing domain is unknown.")
    if rep_status.get("local_feed", "").startswith(("not", "unavail")) and not rep_status.get("urlhaus", "").startswith("queried"):
        u.append("Links were not compared with any threat-intelligence feed. A link that looks clean here may still be a known phishing site.")
    if pe.links and not ctx.get("all_links_on_sender_domain"):
        u.append("Where the links actually lead was not checked (MailScope never visits links); redirects and landing pages are unknown.")
    if ctx.get("tracked"):
        u.append("Some links go through bulk-mail click-tracking domains, so their final destination is hidden.")
    if pe.remote_image_count:
        u.append(f"{pe.remote_image_count} remote image(s) (possible tracking pixels) were found and deliberately not loaded.")
    for a, (name, payload) in zip(pe.attachments, pe.attachment_payloads):
        if name.lower().endswith(".pdf") and b"/FlateDecode" in payload[:2_000_000]:
            u.append(f"PDF '{name}' has compressed content that was not decompressed, so links hidden inside may be missed.")
    if not (pe.text.strip() or pe.html_text.strip()):
        u.append("No readable body text: image-only messages (including QR codes) cannot be read, so their content is unknown.")
    u.extend(pe.parse_notes)
    u.extend(errors)
    return u


def _actions(code: str, signals: list[Signal], has_attachment_risk: bool) -> list[str]:
    ids = {s.id.split(":")[0] for s in signals}
    base = {
        "phishing_likely": [
            "Do not click links, open attachments, scan QR codes or reply.",
        ] + ([
            "Do not sign in or enter any information through this message.",
            "If you need to check the claim, open the real company's site by typing its address yourself, or use its official app.",
        ] if ids & {"credential_request", "credential_disclosure", "html_password_form", "combo_deception_intent", "combo_credential_unrelated_link"}
             or any(s.category == "deceptive_link" for s in signals) else []) + [
            "Report it (your IT/security team or mail provider's 'report phishing'), then delete it.",
            "If you already clicked, opened a file or entered a password: change that password from a clean device, turn on multi-factor sign-in, and tell your IT team or the service.",
        ],
        "suspicious": [
            "Do not click links or open attachments yet.",
            "Verify through another channel: contact the supposed sender using a phone number or website you already trust, not one from this email.",
            "If it is from your workplace, forward it to your security team for a second opinion.",
        ],
        "spam_scam": [
            "Do not reply, call any number in it, or pay any fee.",
            "Mark it as spam/junk and delete it.",
            "Never share personal or financial details with someone who contacted you unexpectedly.",
        ],
        "minor": [
            "Treat the listed points as reasons to double-check before acting.",
            "If the message asks you to sign in or pay, go to the service directly instead of using its links.",
        ],
        "none": [
            "No strong signals were found, but this is not a safety clearance. MailScope cannot see everything (see 'What could not be verified').",
            "Before logging in, paying, or opening files, confirm unexpected requests through a channel you already trust.",
        ],
        "incomplete": [
            "Treat this message with caution: the analysis did not finish, and an incomplete analysis is not a safe result.",
            "Check the problems listed under 'What could not be verified'.",
        ],
    }[code]
    extra = []
    if has_attachment_risk:
        extra.append("Do not open or run the attachment. If you must examine it, use a dedicated isolated analysis environment, not your own computer.")
    if "combo_payment_redirect" in ids or "payment_request" in ids:
        extra.append("For any request to pay or change bank details: confirm by phone using a number you already have on file.")
    return base[:1] + extra + base[1:] if code in ("phishing_likely", "suspicious") else base + extra


def assess_parsed(pe: ParsedEmail, *, dkim_enabled=False, feed_path="", use_urlhaus=False,
                  urlhaus_key=None, errors: list[str] | None = None) -> Assessment:
    errors = list(errors or [])
    signals: list[Signal] = []
    sender_info: dict = {}
    families: list[str] = []
    claims: list[str] = []
    rep_status = {"local_feed": "not configured", "urlhaus": "not enabled"}
    dkim = None
    ctx: dict = {}

    def stage(name, fn, default=None):
        try:
            return fn()
        except Exception as exc:  # a failing stage must surface, never vanish
            errors.append(f"Analysis stage '{name}' failed ({exc.__class__.__name__}: {str(exc)[:100]}). Its evidence is missing from this result.")
            return default

    not_email = not any(h in pe.headers for h in ("from", "subject", "date", "message-id", "received", "to"))
    if not_email:
        errors.append("The file does not look like an email message (no recognisable headers). Export the message as .eml and try again.")

    body = visible_body(pe)
    sender_reg = registrable_domain(pe.from_domain) if pe.from_domain else ""

    r = stage("sender", lambda: analyze_sender(pe), ([], {}))
    signals += r[0]; sender_info = r[1]
    sender_info["sender_reg"] = sender_reg
    # Free-mail domains (outlook.com, gmail.com...) belong to a brand but are used by ordinary people, so they never count
    # as "the brand sending".
    sender_info["sender_domain_brand"] = brand_for_domain(sender_reg) if sender_reg and sender_reg not in FREEMAIL else None
    signals += stage("obfuscation", lambda: analyze_obfuscation(pe), [])
    signals += stage("attachments", lambda: analyze_attachments(pe, body), [])  # may add PDF links to pe.links
    signals += stage("links", lambda: analyze_links(pe, pe.from_domain), [])
    ctx = stage("link context", lambda: _link_context(pe, sender_reg, sender_info.get("brand_claimed")), {})
    non_english = looks_non_english(body)
    r = stage("content", lambda: analyze_content(pe, body, sender_reg, ctx), ([], {}))
    signals += r[0]; families = r[1].get("families", [])
    from .authentication_checks import DKIMResult
    r = stage("authentication", lambda: analyze_auth(pe, dkim_enabled), ([], [], DKIMResult("error", "stage failed")))
    signals += r[0]; claims = r[1]; dkim = r[2]
    r = stage("reputation", lambda: check_reputation(pe.links, feed_path, use_urlhaus, urlhaus_key), ([], rep_status))
    signals += r[0]; rep_status = r[1]

    # Scam wording: two or more distinct windfall/fee phrases is much stronger than one.
    for s in signals:
        if s.id == "prize_or_fee_scam":
            import re
            from .content_analysis import FAMILIES
            n = len({m.group(0).lower() for m in FAMILIES["prize_fee"].finditer(body)})
            if n >= 2:
                s.strength = "strong"

    signals += stage("combinations", lambda: _combination_signals(signals, pe, ctx, sender_info, families), [])

    # Drop duplicate ids, keep the strongest
    best: dict[str, Signal] = {}
    for s in signals:
        if s.id not in best or s.weight > best[s.id].weight:
            best[s.id] = s
    signals = sorted(best.values(), key=lambda s: -s.weight)

    score = combine(signals)
    band = band_for(score)
    phish_w = combine([s for s in signals if s.category in PHISH_CATEGORIES])
    spam_w = combine([s for s in signals if s.category in SPAM_CATEGORIES])
    kind = "phish" if phish_w >= spam_w and phish_w > 0 else "spam" if spam_w > 0 else "origin"

    if not_email:
        code, verdict = "incomplete", "Analysis incomplete: this does not look like an email file (no verdict)"
    elif errors and band == "Minimal":
        code, verdict = "incomplete", "Analysis incomplete: no verdict (a failed check is not a safe result)"
    elif band == "High":
        code = "phishing_likely" if kind == "phish" else "spam_scam"
        verdict = "Likely phishing or fraud" if kind == "phish" else "Likely scam or spam"
    elif band == "Medium":
        code = "suspicious" if kind != "spam" else "spam_scam"
        verdict = ("Suspicious: possible phishing or fraud" if kind == "phish" else
                   "Suspicious: likely spam or scam" if kind == "spam" else "Suspicious: unverified or inconsistent origin")
    elif band == "Low":
        code = "minor"
        verdict = ("Some suspicious signals (possible phishing)" if kind == "phish" else
                   "Some spam-like signals" if kind == "spam" else "Origin unverified, minor inconsistencies")
    else:
        code, verdict = "none", "No strong signals found (this is not a safety clearance)"

    # Origin and content panels
    origin_sigs = [s for s in signals if s.category in ORIGIN_CATEGORIES | {"impersonation"} and s.strength in ("moderate", "strong")]
    aligned = [r for r in (dkim.signers if dkim else []) if r.get("aligned")]
    if origin_sigs:
        origin_status = "Suspicious: the sender's identity looks inconsistent"
        origin_detail = "; ".join(s.title for s in origin_sigs[:3])
    elif aligned:
        origin_status = f"Signed by {aligned[0]['domain']} (DKIM verified)"
        origin_detail = "A valid signature shows that this domain signed these exact bytes. It does not show the content is safe or the sender is trustworthy."
    else:
        origin_status = "Unverified: this file cannot prove where the message really came from"
        origin_detail = "No cryptographic proof of origin was available. That is different from being fake."
    content_sigs = [s for s in signals if s.category in {"credential", "payment", "scam", "spam", "deceptive_link", "attachment", "reputation", "pressure"}]
    strong_c = [s for s in content_sigs if s.strength in ("strong", "moderate")]
    content_status = ("Dangerous signals found in content, links or attachments" if any(s.strength == "strong" for s in content_sigs)
                      else "Suspicious signals found in content, links or attachments" if strong_c
                      else "Minor signals only" if content_sigs
                      else "No strong signals found in the readable content (images, hidden destinations and unscanned files are unknown)")

    unknowns = _unknowns(pe, claims, dkim, rep_status, ctx, pe.links, errors) if dkim else []
    if non_english and dkim:
        unknowns.insert(0, "The message text does not look English. MailScope's wording rules are English-only, so wording gave no evidence either way; "
                           "only sender, link and attachment checks apply. Treat a low result on a non-English message with extra caution.")
    checks = {
        "Sender and header consistency": "performed",
        "Link analysis (strings only, never visited)": "performed" if pe.links else "no links found",
        "Attachment inspection (static, never opened)": "performed" if pe.attachments else "no attachments",
        "Message wording": ("limited: wording rules are English-only and this text does not look English" if non_english
                            else "performed" if body.strip() else "no readable text"),
        "Recorded authentication claims": "found (untrusted text)" if claims else "none recorded",
        "Cryptographic DKIM verification": {"not_performed": "not performed (opt-in)", "unavailable": "unavailable (dkimpy missing)",
                                           "no_signature": "no signature present"}.get(dkim.status if dkim else "", dkim.status if dkim else "failed"),
        "Local threat feed": rep_status.get("local_feed", ""),
        "URLhaus online lookup": rep_status.get("urlhaus", ""),
    }
    extra_checks = sum(1 for k in ("Cryptographic DKIM verification", "Local threat feed", "URLhaus online lookup")
                       if checks[k].startswith(("verified", "failed", "loaded", "queried")))
    coverage = "Limited" if extra_checks == 0 else "Moderate"
    if errors:
        coverage = "Partial (some checks failed)"

    has_att_risk = any(s.category == "attachment" and s.strength in ("moderate", "strong") for s in signals)
    summary = {
        "From": f"{pe.from_name} <{pe.from_addr}>" if pe.from_name else pe.from_addr,
        "Reply-To": ", ".join(pe.reply_to_addrs) or "(none)",
        "Return-Path": pe.return_path or "(none)",
        "Subject": pe.subject, "Date": pe.date,
        "Links found": len(pe.links), "Attachments": len(pe.attachments),
        "HTML body": "yes (shown as text only, never rendered)" if pe.has_html else "no",
    }
    return Assessment(
        verdict=verdict, verdict_code=code, indicator=score, indicator_band=band,
        indicator_meaning=INDICATOR_MEANING, origin_status=origin_status, origin_detail=origin_detail,
        content_status=content_status,
        reasons=[s for s in signals if s.strength in ("strong", "combo", "moderate")][:6] or signals[:3],
        signals=signals, unknowns=unknowns, checks_run=checks, actions=_actions(code, signals, has_att_risk),
        evidence_coverage=coverage, parsed_summary=summary, links=pe.links, attachments=pe.attachments,
        auth_claims=claims, errors=errors)


def analyze_bytes(raw: bytes, **opts) -> Assessment:
    """Entry point: raw .eml bytes -> Assessment. Never raises; failures become an 'incomplete' result."""
    try:
        pe = parse_email(raw)
    except Exception as exc:
        return Assessment(
            verdict="Analysis incomplete: the file could not be read as an email",
            verdict_code="incomplete", indicator=0, indicator_band="Minimal", indicator_meaning=INDICATOR_MEANING,
            origin_status="Unknown", origin_detail="The file could not be parsed.", content_status="Unknown",
            reasons=[], signals=[], unknowns=[f"Parsing failed: {exc.__class__.__name__}: {str(exc)[:120]}"],
            checks_run={}, actions=["Do not treat this as safe. Re-export the message as a .eml file and try again."],
            evidence_coverage="None", errors=[f"Parsing failed: {exc.__class__.__name__}"])
    return assess_parsed(pe, **opts)
