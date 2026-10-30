"""Message-intent analysis.

Design note: wording alone is a weak, easily-evaded signal, so phrase families are
only *intent* evidence. They never decide a verdict by themselves; risk_assessment
combines them with identity/link/attachment deception. Where all links stay on the
sender's own domain, credential wording is down-weighted (a genuine password reset
looks like this too).
"""
from __future__ import annotations

import re
from email.utils import getaddresses

from .domains import FREEMAIL, brand_for_domain, registrable_domain
from .models import ParsedEmail, Signal

F = re.IGNORECASE | re.DOTALL

FAMILIES: dict[str, re.Pattern] = {
    "cred_action": re.compile(
        r"\b(verify|confirm|validate|update|re-?activate|restore|unlock|re-?authenticate|review)\b.{0,40}"
        r"\b(account|password|log-?in|sign-?in|identity|credentials|billing (info|details)|payment method|mailbox|e-?mail account)\b"
        r"(?!\s*(preferences?|settings|profile|subscriptions?|notifications?))", F),
    "cred_disclosure": re.compile(
        r"\b(reply|respond)\b.{0,25}\b(with|using)\b.{0,25}\b(your )?(password|passcode|username and password|otp|pin|ssn|social security|card number|cvv)\b|"
        r"\b(send|provide|enter|submit|share|confirm)\b.{0,20}\byour (password|passcode|otp|one-time (code|password)|pin|ssn|social security( number)?|card number|cvv|security code|bank (login|credentials))\b", F),
    "cred_direct": re.compile(
        r"\b(sign|log)[ -]?in\b.{0,30}\b(to (view|access|review|download|keep|avoid|restore)|with your)\b|"
        r"\bpassword\b.{0,25}\b(expires?|expiring|will expire|has expired)\b", F),
    "doc_lure": re.compile(
        r"\b(shared|sent) (you )?(a |an )?(secure |important )?(document|file|invoice|voicemail|message|folder)\b|\bnew voicemail\b|"
        r"\b(review|view|open) (and sign )?(the )?(document|attachment|invoice|file)\b", F),
    "pressure": re.compile(
        r"\b(suspend(ed)?|locked|limited|disabled|terminated|deactivat\w+|unusual (sign-?in|activity)|unauthori[sz]ed|security alert|"
        r"will be (deleted|closed|suspended|terminated)|within (12|24|48|72) hours|final (notice|warning)|immediate(ly)?|act now|urgent|failure to (comply|respond|verify))\b", F),
    "payment_change": re.compile(
        r"\b(new|updated|changed|change of|different|revised) (bank|banking|account|payment|wire|remittance|iban|routing)\b.{0,50}\b(details|account|number|instructions|information)\b|"
        r"\b(update|change|switch|redirect)\b.{0,40}\b(bank|payment|direct deposit|salary)\b.{0,30}\b(details|account|information|instructions)\b|"
        r"\bwire (transfer|the funds?|payment)\b", F),
    "bank_moved": re.compile(
        r"\b(moved|switched|changed|moving|switching|changing) (over )?to (a |another |our |new |different )?bank(s|ing)?\b|"
        r"\bnew (bank )?account\b.{0,40}\b(pay|payments?|transfers?|deposits?|remit)\b", F),
    "payee_new": re.compile(
        r"\b(process|make|send|arrange|wire|release|issue)\b.{0,30}\b(an? |the )?(urgent |immediate |same[- ]day |quick )?(payment|transfer|wire)\b.{0,50}"
        r"\b(new|another|different|first[- ]time)\s+(supplier|vendor|payee|beneficiary|account|contractor)\b", F),
    "domain_fee": re.compile(
        r"\b(domain (name |listing |registration )?|search engine (listing|submission)|seo listing)\b.{0,80}\b(expire\w*|renew\w*|suspend\w*)\b.{0,160}[$€£]\s?\d{2,4}|"
        r"\bthis is not a (bill|invoice)\b", F),
    "extort_claim": re.compile(
        r"\b(i|we) (have )?(hacked|accessed|infected|recorded|filmed|captured|compromised)\b.{0,60}\b(you|your|webcam|camera|device|computer|phone|account)\b|"
        r"\b(i|we) (have|got|know)\b.{0,30}\b(video|footage|recording|photos?|pictures?|your password|your secrets?)\b.{0,40}\b(of you|you|your)\b|"
        r"\bi know your password\b", F),
    "extort_demand": re.compile(
        r"\b(bitcoin|btc|monero|ethereum|usdt|crypto(currency)?|wallet address)\b|"
        r"\b(bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,39}\b", F),
    "extort_threat": re.compile(
        r"\b(send|share|publish|release|leak|forward|post|expose|upload)\b.{0,50}\b(video|photos?|footage|recording|pictures?|it|this|everything)\b.{0,60}"
        r"\b(contacts|friends|family|colleagues|co-?workers|everyone|public|internet|social)\b", F),
    "alert_claim": re.compile(
        r"\b(detected|found|identified|discovered)\b.{0,40}\b(virus(es)?|malware|trojans?|spyware|threats?|infections?)\b|"
        r"\byour (pc|computer|device|system|mac|windows|browser)\b.{0,30}\b(is|has been|was|may be|might be)\b.{0,20}\b(infected|compromised|hacked|blocked|at risk)\b", F),
    "mailbox_admin": re.compile(
        r"\byour (mailbox|e-?mail (account|storage|quota)|webmail|inbox)\b.{0,80}\b(full|quota|storage|limit|suspend\w*|expir\w*|deactivat\w*|disabled|upgrade|verify|validate|update)\b|"
        r"\b(mailbox|e-?mail) (storage|quota)\b|"
        r"\bincoming (mail|messages?|e-?mails?) (will be|may be|are being) (rejected|blocked|delayed|returned)\b", F),
    "attach_ref": re.compile(r"\b(attached|attachment|enclosed|see (the )?attached|find attached)\b", F),
    "gift_cards": re.compile(r"\b(gift cards?|itunes cards?|google play cards?|steam cards?|prepaid cards?)\b", F),
    "exec_request": re.compile(
        r"\b(are you (available|at your desk|free)|need (a )?(quick )?favou?r|are you in the office)\b|"
        r"\b(kindly|please) (process|make|arrange|handle)\b.{0,40}\b(payment|transfer|wire|invoice)\b|"
        r"\b(do not|don'?t) (call|discuss|share|tell)\b|\bstrictly confidential\b|\bkeep (this )?(confidential|between us)\b", F),
    "callback": re.compile(
        r"\b(call|contact|phone|dial)\b.{0,60}\+?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b|"
        r"\b(call|contact)\b.{0,40}\b(support|billing|helpline|customer service)\b.{0,30}\b(cancel|dispute|refund|stop)\b", F),
    "dispute_phrase": re.compile(
        r"\b(did not|didn'?t|do not|don'?t|not)\b.{0,30}\b(authori[sz]e|make|place|recogni[sz]e|request)\b", F),
    "invoice_lure": re.compile(
        r"\b(invoice|overdue|remittance|payment (advice|due|slip)|purchase order|statement of account|receipt|voicemail|fax|scanned (document|copy)|remit payment)\b", F),
    "charge_notice": re.compile(
        r"\b(charged|charge of|your (subscription|membership|order|renewal)|auto-?renew\w*|invoice (no|number|#)|payment of)\b.{0,60}[$€£]\s?\d|"
        r"[$€£]\s?\d[\d,.]*.{0,60}\b(was|has been|will be) (charged|debited|deducted)\b", F),
    "prize_fee": re.compile(
        r"\b(you (have )?(won|been selected|are the winner)|claim your (prize|reward|gift|winnings)|lottery|unclaimed (funds|inheritance|package)|"
        r"beneficiary|next of kin|inheritance|processing fee|release (of )?(the )?funds|transfer fee|million (usd|dollars|pounds|euros))\b", F),
    "get_rich": re.compile(
        r"\b(guaranteed (returns?|profit|income)|double your (money|bitcoin|investment)|crypto (giveaway|airdrop)|risk[- ]free|"
        r"work from home|earn \$?\d+[\d,]*.{0,20}(per|a|each) (day|hour|week)|no experience (needed|necessary|required))\b", F),
    "promo_spam": re.compile(
        r"\b(100% (free|guaranteed)|miracle|weight[- ]loss|viagra|cialis|online casino|"
        r"limited[- ]time offer|exclusive deal|click here to (win|claim|order)|no prescription|lowest price|"
        r"pre-?approved|guaranteed approval|no credit check|payday loan|private photos|meet (local )?(singles|women|girls)|hot (singles|girls)|"
        r"free spins?|casino|jackpot|no deposit( required)?|welcome (bonus|package)|instant approval|cash advance|"
        r"(reverses?|erases?|melts?|eliminates?)\b.{0,30}\b(overnight|in (just )?(days|minutes|hours))|doctors? (hate|don'?t want)|"
        r"(one|1) (weird|odd|simple|strange) (trick|secret))\b", F),
    "template_leftover": re.compile(
        r"\*\|[A-Z_:]{3,}\|\*|\{\{\s*[a-z_.]{3,}\s*\}\}|\[\[[A-Z_]{3,}\]\]|%%[A-Za-z_]{3,}%%|customize this template", F),
}


_ENGLISH_WORDS = frozenset("the and you your for with this that are we have please from will can not by our has was been".split())


def looks_non_english(body: str) -> bool:
    """True when the text clearly is not English (so MailScope's wording rules, which are English-only, say nothing)."""
    toks = re.findall(r"[^\W\d_]+", body.lower())
    if len(toks) < 25:
        return False
    return sum(t in _ENGLISH_WORDS for t in toks) / len(toks) < 0.04


NEGATION = re.compile(r"\b(never|not|no one|nobody|don'?t|do not|won'?t|will not|cannot|can'?t|should not|shouldn'?t)\b", re.I)


def _first_unnegated(pat: re.Pattern, text: str):
    """First match that is not preceded (within 60 chars) by a negation such as 'we will never ask you to ...'."""
    for m in pat.finditer(text):
        if not NEGATION.search(text[max(0, m.start() - 60):m.start() + 20]):
            return m
    return None


def _snip(m: re.Match, text: str) -> str:
    s = max(0, m.start() - 20)
    return "…" + " ".join(text[s:m.end() + 40].split())[:130] + "…"


def analyze_content(pe: ParsedEmail, body: str, sender_domain_reg: str, link_context: dict) -> tuple[list[Signal], dict]:
    sigs: list[Signal] = []
    hits: dict[str, re.Match] = {}
    for name, pat in FAMILIES.items():
        m = _first_unnegated(pat, body) if name == "cred_disclosure" else pat.search(body)
        if m:
            hits[name] = m

    has_cta = bool(pe.links) or pe.has_form
    own_links_only = link_context.get("all_links_on_sender_domain", False)
    info = {"families": sorted(hits)}

    cred = [k for k in ("cred_disclosure", "cred_action", "cred_direct") if k in hits]
    if "cred_disclosure" in hits:
        sigs.append(Signal("credential_disclosure", "credential", "strong",
                           "Message asks you to send a password, code or card number",
                           "Genuine services never ask you to reply with or type a password, one-time code, PIN or card number into an email.",
                           [_snip(hits["cred_disclosure"], body)]))
    elif cred:
        strength = "moderate" if (has_cta or "cred_direct" in hits) else "weak"
        if own_links_only:
            strength = "weak"
        sigs.append(Signal("credential_request", "credential", strength,
                           "Message asks you to verify, sign in or update account details",
                           "Requests to log in or confirm credentials are how phishing starts, but genuine services send them too. "
                           "This is weighed together with where the links go and who the sender is."
                           + (" All links stay on the sender's own domain, which lowers this weight." if own_links_only else ""),
                           [_snip(hits[k], body) for k in cred]))
    elif "doc_lure" in hits and has_cta:
        sigs.append(Signal("document_lure", "credential", "weak", "Message invites you to open a shared document or message",
                           "'Shared document' lures are a common route to fake sign-in pages.", [_snip(hits["doc_lure"], body)]))

    if "pressure" in hits:
        sigs.append(Signal("pressure", "pressure", "weak", "Urgency or threat wording",
                           "Pressure to act quickly is common in fraud but also in genuine notices. It never decides a verdict alone.",
                           [_snip(hits["pressure"], body)]))

    pay = [k for k in ("payment_change", "bank_moved", "payee_new", "gift_cards") if k in hits]
    if pay:
        # A change of bank details that is NOT simply pointing you to the sender's own website is the
        # core business-email-compromise request, and the standard control is to confirm it by phone.
        # That is why it is rated higher than other wording signals.
        change = bool({"payment_change", "bank_moved", "payee_new"} & set(pay)) and not own_links_only
        strength = "strong" if change else ("weak" if own_links_only and "gift_cards" not in hits else "moderate")
        sigs.append(Signal("payment_request", "payment", strength,
                           "Message asks for a changed payment destination or gift cards",
                           "Changed bank details and gift-card requests are the two most common business email compromise patterns. "
                           "Even when the sender is genuine, bank-detail changes should be confirmed by phone using a number you already have.",
                           [_snip(hits[k], body) for k in pay]))
    if "exec_request" in hits:
        sigs.append(Signal("exec_request", "payment", "weak",
                           "Secrecy or 'are you available' style request",
                           "Openers like this are used to start executive-impersonation fraud.", [_snip(hits["exec_request"], body)]))
    if "callback" in hits and "charge_notice" in hits:
        sigs.append(Signal("callback_scam", "payment", "strong" if ("dispute_phrase" in hits and re.search(r"(?i)\b(cancel|refund)\b", body)) else "moderate",
                           "Unexpected charge notice that tells you to call a phone number",
                           "'Call to dispute' messages move the victim from email to a phone call with a scammer.",
                           [_snip(hits["charge_notice"], body), _snip(hits["callback"], body)]))

    # Extortion ("I recorded you, pay in bitcoin"): needs a claim of compromise AND a payment demand or a threat.
    if "extort_claim" in hits and ("extort_demand" in hits or "extort_threat" in hits):
        parts = [k for k in ("extort_claim", "extort_demand", "extort_threat") if k in hits]
        sigs.append(Signal("extortion_threat", "payment", "strong" if len(parts) >= 3 or "extort_demand" in hits else "moderate",
                           "Blackmail-style message: claims to have compromised you and demands payment",
                           "Sextortion and 'I hacked you' emails claim to hold a video or your password, demand cryptocurrency and threaten to expose you. "
                           "They are mass-mailed; the claims are almost always false.",
                           [_snip(hits[k], body) for k in parts]))

    # Fake security alert that moves the victim to a phone call
    if "alert_claim" in hits and "callback" in hits and "charge_notice" not in hits:
        sigs.append(Signal("tech_support_scam", "payment", "strong",
                           "Fake security alert that tells you to phone a number",
                           "Messages claiming your computer is infected and telling you to call 'support' lead to remote-access and payment scams.",
                           [_snip(hits["alert_claim"], body), _snip(hits["callback"], body)]))

    # Mailbox/quota notice from a domain that is neither the recipient's nor a known mail brand
    if "mailbox_admin" in hits and has_cta and sender_domain_reg and not brand_for_domain(sender_domain_reg):
        rcpt = {registrable_domain(a.rsplit("@", 1)[-1]) for _, a in getaddresses(pe.headers.get("to", []) + pe.headers.get("cc", [])) if "@" in a}
        if rcpt and sender_domain_reg not in rcpt and sender_domain_reg not in FREEMAIL:
            sigs.append(Signal("mailbox_admin_unrelated", "credential", "moderate",
                               "Mailbox or storage notice from a domain unrelated to your mailbox",
                               "Real quota or expiry notices for your mailbox come from your own organisation or mail provider. "
                               "(Web hosts also send such mail for domains they host, so this is evidence, not proof.)",
                               [_snip(hits["mailbox_admin"], body), f"Sender domain: {sender_domain_reg}; recipient domain: {', '.join(sorted(rcpt))}"]))

    if "domain_fee" in hits:
        sigs.append(Signal("domain_fee_scam", "scam", "strong" if re.search(r"(?i)this is not a (bill|invoice)", body) else "moderate",
                           "Domain or search-listing 'renewal' notice asking for a fee",
                           "Fake domain-registry notices look like invoices but are solicitations ('this is not a bill'). A genuine registrar bills you through your own account.",
                           [_snip(hits["domain_fee"], body)]))

    if "prize_fee" in hits:
        sigs.append(Signal("prize_or_fee_scam", "scam", "moderate", "Prize, inheritance or advance-fee wording",
                           "Winning something you did not enter, or paying a fee to receive money, is the signature of advance-fee fraud.",
                           [_snip(hits["prize_fee"], body)]))
    rich = sorted({m.group(0).lower() for m in FAMILIES["get_rich"].finditer(body)})
    if rich:
        sigs.append(Signal("get_rich_scheme", "scam", "strong" if len(rich) >= 2 else "weak",
                           "Get-rich or guaranteed-income promises",
                           "Guaranteed returns, doubling your money and effortless high pay are hallmarks of investment and job scams.",
                           [", ".join(rich[:6])]))
    promo_matches = [m.group(0) for m in FAMILIES["promo_spam"].finditer(body)]
    if promo_matches:
        distinct = sorted({p.lower() for p in promo_matches})
        sigs.append(Signal("promo_spam", "spam", "strong" if len(distinct) >= 3 else "moderate" if len(distinct) >= 2 else "weak",
                           "Spam or high-pressure marketing wording",
                           "Typical of unsolicited promotions (health, investment, casino, get-rich offers).", [", ".join(distinct[:6])]))

    if "template_leftover" in hits:
        sigs.append(Signal("template_placeholders", "spam", "weak", "Unfilled mail-merge or template placeholders",
                           "Text like *|MC:SUBJECT|* or 'Customize this template' means a mass-mailing template was sent without being finished, which is typical of "
                           "careless bulk or scam campaigns.", [_snip(hits["template_leftover"], body)]))

    sample = body[:50_000]  # statistics on the first 50k characters are enough and keep large messages fast
    n_letters = sum(map(str.isalpha, sample))
    if n_letters > 60:
        caps = sum(map(str.isupper, sample)) / n_letters
        if caps > 0.45 or body.count("!") >= 6:
            sigs.append(Signal("shouting", "spam", "weak", "Heavy capitals or exclamation marks", "Often seen in bulk spam.",
                               [f"{caps:.0%} capital letters, {body.count('!')} exclamation marks"]))
    return sigs, info
