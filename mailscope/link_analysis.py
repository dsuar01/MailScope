"""Link analysis. Links are only ever parsed as strings: nothing is requested."""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from .domains import (ABUSED_TLDS, TRACKING_DOMAINS, URL_SHORTENERS, brand_for_domain,
                      brand_lookalike, idn_findings, is_ip, registrable_domain, suffix_of,
                      to_ascii_host)
from .models import Link, ParsedEmail, Signal

TEXT_DOMAIN = re.compile(r"(?i)^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|$)")


def _short(urls: list[str], n: int = 4) -> list[str]:
    out = [u[:140] for u in urls[:n]]
    if len(urls) > n:
        out.append(f"... and {len(urls) - n} more")
    return out


def analyze_links(pe: ParsedEmail, sender_domain: str) -> list[Signal]:
    sender_reg = registrable_domain(sender_domain) if sender_domain else ""
    buckets: dict[str, list[tuple[Link, str]]] = {}

    def hit(key: str, link: Link, why: str = ""):
        link.flags.append(key)
        buckets.setdefault(key, []).append((link, why))

    for l in pe.links:
        if not l.host:
            continue
        host_ascii = to_ascii_host(l.host)
        reg = l.registrable
        if "userinfo" in l.flags:
            hit("userinfo", l)
        if is_ip(host_ascii):
            hit("ip_host", l)
            continue
        if reg in URL_SHORTENERS:
            hit("shortener", l)
        if reg in TRACKING_DOMAINS or any(host_ascii.endswith("." + t) for t in TRACKING_DOMAINS):
            hit("tracking_wrapper", l)
        elif l.text:
            m = TEXT_DOMAIN.match(l.text.strip())
            if m:
                shown = registrable_domain(m.group(1))
                if shown != reg and not (sender_reg and shown == sender_reg and reg == sender_reg):
                    hit("text_mismatch", l, f"text shows {shown}, link goes to {reg}")
        look = brand_lookalike(host_ascii)
        if look:
            hit("lookalike_" + look["strength"], l, look["why"])
        for f in idn_findings(host_ascii):
            hit("mixed_script", l, f)
        if suffix_of(reg).split(".")[-1] in ABUSED_TLDS:
            hit("abused_tld", l)
        # open-redirect style parameter pointing at a different domain
        try:
            q = parse_qs(urlsplit(l.url if "://" in l.url else "http://" + l.url).query)
            for vals in q.values():
                for v in vals:
                    mm = re.match(r"(?i)https?://([^/\s]+)", v)
                    if mm and registrable_domain(mm.group(1)) not in (reg, ""):
                        hit("redirect_param", l, f"parameter forwards to {registrable_domain(mm.group(1))}")
        except ValueError:
            pass

    sigs: list[Signal] = []

    def ev(key):
        return _short([f"{lk.url}" + (f"  ({w})" if w else "") for lk, w in buckets[key]])

    if "userinfo" in buckets:
        sigs.append(Signal("link_userinfo", "deceptive_link", "strong", "Link hides its real destination behind a fake login prefix",
                           "In a URL like http://paypal.com@evil.test/ everything before the @ is ignored; the browser goes to the part after it.", ev("userinfo")))
    if "mixed_script" in buckets:
        sigs.append(Signal("link_mixed_script", "deceptive_link", "strong", "Link domain mixes alphabets", "Mixed-script domains are used to imitate familiar names.", ev("mixed_script")))
    if "lookalike_strong" in buckets:
        sigs.append(Signal("link_lookalike_strong", "deceptive_link", "strong", "Link domain imitates a known brand", "The domain uses a well-known name without being that company's domain.", ev("lookalike_strong")))
    if "lookalike_moderate" in buckets:
        sigs.append(Signal("link_lookalike_moderate", "deceptive_link", "moderate", "Link domain resembles a known brand", "The domain is a close variation of a well-known name.", ev("lookalike_moderate")))
    if "text_mismatch" in buckets:
        brandish = any(brand_for_domain(registrable_domain(re.sub(r'^https?://', '', lk.text).split('/')[0])) for lk, _ in buckets["text_mismatch"])
        sigs.append(Signal("link_text_mismatch", "deceptive_link", "strong" if brandish else "moderate",
                           "Link text shows one website but the link goes to another",
                           "What you read and where you land differ. Legitimate mail rarely does this except through tracking services, which are handled separately.", ev("text_mismatch")))
    if "ip_host" in buckets:
        sigs.append(Signal("link_ip_host", "deceptive_link", "moderate", "Link points to a raw IP address",
                           "Legitimate services almost always use domain names.", ev("ip_host")))
    if "redirect_param" in buckets:
        sigs.append(Signal("link_redirect_param", "deceptive_link", "weak", "Link forwards visitors to a different site",
                           "Open-redirect parameters are used to launder a bad destination through a trusted-looking site.", ev("redirect_param")))
    if "shortener" in buckets:
        sigs.append(Signal("link_shortener", "deceptive_link", "weak", "Link uses a URL shortener",
                           "The real destination cannot be seen without visiting it.", ev("shortener")))
    if "abused_tld" in buckets:
        sigs.append(Signal("link_abused_tld", "deceptive_link", "weak", "Link uses a domain ending that is heavily abused",
                           "Many legitimate sites use these endings too; this is a weak hint only.", ev("abused_tld")))

    # Forms that harvest credentials
    if pe.has_password_field:
        sigs.append(Signal("html_password_form", "credential", "strong", "Email itself contains a password entry field",
                           "Real services do not collect passwords inside an email body.", ["HTML form with <input type=password>"]))
    for l in pe.links:
        if l.source == "html-form" and l.registrable and l.registrable != sender_reg and not is_ip(l.host):
            sigs.append(Signal("html_form_external", "credential", "moderate", "Email contains a form that submits to another domain",
                               "Forms inside email are unusual and this one sends data to a domain unrelated to the sender.", [l.url[:140]]))
            break
    return sigs
