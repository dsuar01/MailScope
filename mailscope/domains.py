"""Domain helpers and small curated reference lists.

The lists here are deliberately small and are NOT a substitute for a real
threat-intelligence feed. They exist so that the logic has something concrete to
compare against; every list is a known limitation (see README).
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata

# A few multi-part public suffixes. Without the full Public Suffix List this is a
# heuristic; unusual suffixes may be mis-split.
MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au",
    "edu.au", "co.nz", "co.jp", "ne.jp", "or.jp", "com.br", "com.mx", "com.ar",
    "com.tr", "co.in", "com.cn", "com.hk", "com.sg", "co.za", "com.ua", "com.pl",
    "co.kr", "com.my", "com.ph", "com.co", "com.pe", "com.vn", "co.id", "com.eg",
}

FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "proton.me", "protonmail.com",
    "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com", "yandex.ru", "mail.ru",
    "qq.com", "163.com", "126.com", "rediffmail.com", "tutanota.com", "fastmail.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "lnkd.in", "bl.ink",
}

# Bulk-mail / click-tracking infrastructure used by legitimate senders (and abusable
# by bad ones). A link through one of these hides its real destination: we report the
# destination as UNKNOWN rather than calling it good or bad.
TRACKING_DOMAINS = {
    "sendgrid.net", "mailchimp.com", "list-manage.com", "mandrillapp.com", "amazonses.com",
    "mcsv.net", "constantcontact.com", "hubspotlinks.com", "hs-sites.com", "sparkpostmail.com",
    "mailgun.org", "mgsend.net", "campaign-archive.com", "klclick.com", "klaviyomail.com",
    "exacttarget.com", "salesforce.com", "marketo.com", "mktoweb.com", "customeriomail.com",
    "awstrack.me", "sendinblue.com", "brevo.com", "convertkit-mail.com", "ct.sendgrid.net",
}

# Very common top-level domains with heavy abuse. Used only as a weak, supporting note.
ABUSED_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "icu", "click", "country", "zip",
               "mov", "work", "support", "rest", "buzz", "cyou", "cfd", "sbs"}
# Country-code TLDs we refuse to treat as "national site of a brand" because abuse is high.
NATIONAL_TLD_DENY = {"tk", "ml", "ga", "cf", "gq", "cc", "ws", "pw", "to", "su"}

# Brand -> (labels, genuine registrable domains, ambiguous word?, has national sites?)
# "ambiguous" brands are everyday words, so a display name only counts when it is
# exactly the brand or the brand plus a service word (e.g. "Apple Support").
BRANDS: dict[str, dict] = {
    "PayPal": {"labels": ["paypal"], "domains": {"paypal.com", "paypal.me", "paypalobjects.com", "paypal-communications.com"}, "ambiguous": False, "national": True},
    "Microsoft": {"labels": ["microsoft", "office365", "microsoft365", "outlook", "onedrive", "sharepoint"], "domains": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com", "msn.com", "azure.com", "sharepoint.com", "windows.com", "onedrive.com", "microsoft365.com", "hotmail.com", "bing.com", "skype.com", "xbox.com"}, "ambiguous": False, "national": True},
    "Apple": {"labels": ["apple", "icloud"], "domains": {"apple.com", "icloud.com", "me.com", "itunes.com", "appleid.com"}, "ambiguous": True, "national": False},
    "Google": {"labels": ["google", "gmail"], "domains": {"google.com", "gmail.com", "googlemail.com", "youtube.com", "gstatic.com", "googleusercontent.com", "withgoogle.com", "goo.gl", "accounts.google.com", "googlegroups.com", "google.org"}, "ambiguous": True, "national": True},
    "Amazon": {"labels": ["amazon"], "domains": {"amazon.com", "amazonaws.com", "amazon.jobs", "amazon.work", "a2z.com", "amazonses.com", "primevideo.com", "audible.com"}, "ambiguous": True, "national": True},
    "Netflix": {"labels": ["netflix"], "domains": {"netflix.com", "nflxext.com"}, "ambiguous": False, "national": False},
    "DocuSign": {"labels": ["docusign"], "domains": {"docusign.com", "docusign.net"}, "ambiguous": False, "national": False},
    "DHL": {"labels": ["dhl"], "domains": {"dhl.com"}, "ambiguous": False, "national": True},
    "FedEx": {"labels": ["fedex"], "domains": {"fedex.com"}, "ambiguous": False, "national": True},
    "UPS": {"labels": ["ups"], "domains": {"ups.com"}, "ambiguous": True, "national": True},
    "USPS": {"labels": ["usps"], "domains": {"usps.com", "usps.gov"}, "ambiguous": False, "national": False},
    "Chase": {"labels": ["chase"], "domains": {"chase.com", "jpmorgan.com", "jpmorganchase.com"}, "ambiguous": True, "national": False},
    "Bank of America": {"labels": ["bankofamerica", "bofa"], "domains": {"bankofamerica.com", "bofa.com", "ml.com"}, "ambiguous": False, "national": False},
    "Wells Fargo": {"labels": ["wellsfargo"], "domains": {"wellsfargo.com", "wf.com"}, "ambiguous": False, "national": False},
    "Citibank": {"labels": ["citibank", "citi"], "domains": {"citi.com", "citibank.com", "citigroup.com"}, "ambiguous": False, "national": False},
    "Dropbox": {"labels": ["dropbox"], "domains": {"dropbox.com", "dropboxmail.com"}, "ambiguous": False, "national": False},
    "LinkedIn": {"labels": ["linkedin"], "domains": {"linkedin.com", "licdn.com"}, "ambiguous": False, "national": False},
    "Facebook / Meta": {"labels": ["facebook", "instagram", "whatsapp"], "domains": {"facebook.com", "facebookmail.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com", "messenger.com"}, "ambiguous": False, "national": False},
    "IRS": {"labels": ["irs"], "domains": {"irs.gov"}, "ambiguous": True, "national": False},
    "Coinbase": {"labels": ["coinbase"], "domains": {"coinbase.com"}, "ambiguous": False, "national": False},
    "Binance": {"labels": ["binance"], "domains": {"binance.com", "binance.us"}, "ambiguous": False, "national": False},
    "Adobe": {"labels": ["adobe"], "domains": {"adobe.com", "adobesign.com", "echosign.com"}, "ambiguous": False, "national": False},
    "Zoom": {"labels": ["zoom"], "domains": {"zoom.us", "zoom.com"}, "ambiguous": True, "national": False},
    "Intuit / QuickBooks": {"labels": ["intuit", "quickbooks"], "domains": {"intuit.com", "quickbooks.com", "turbotax.com"}, "ambiguous": False, "national": False},
    "eBay": {"labels": ["ebay"], "domains": {"ebay.com"}, "ambiguous": False, "national": True},
    "Walmart": {"labels": ["walmart"], "domains": {"walmart.com"}, "ambiguous": False, "national": False},
    "Zelle": {"labels": ["zelle"], "domains": {"zellepay.com", "zelle.com"}, "ambiguous": False, "national": False},
    "Venmo": {"labels": ["venmo"], "domains": {"venmo.com"}, "ambiguous": False, "national": False},
    "Cash App": {"labels": ["cashapp"], "domains": {"cash.app", "cashapp.com", "square.com", "squareup.com"}, "ambiguous": False, "national": False},
    "Capital One": {"labels": ["capitalone"], "domains": {"capitalone.com"}, "ambiguous": False, "national": True},
    "American Express": {"labels": ["americanexpress", "amex"], "domains": {"americanexpress.com", "aexp.com", "amex.com"}, "ambiguous": False, "national": True},
    "Best Buy / Geek Squad": {"labels": ["bestbuy", "geeksquad"], "domains": {"bestbuy.com", "geeksquad.com"}, "ambiguous": False, "national": True},
    "Norton": {"labels": ["norton", "nortonlifelock"], "domains": {"norton.com", "nortonlifelock.com", "gen.digital"}, "ambiguous": True, "national": False},
    "McAfee": {"labels": ["mcafee"], "domains": {"mcafee.com"}, "ambiguous": False, "national": False},
    "Kraken": {"labels": ["kraken"], "domains": {"kraken.com"}, "ambiguous": True, "national": False},
    "Robinhood": {"labels": ["robinhood"], "domains": {"robinhood.com"}, "ambiguous": True, "national": False},
    "Spotify": {"labels": ["spotify"], "domains": {"spotify.com", "scdn.co"}, "ambiguous": False, "national": False},
    "Slack": {"labels": ["slack"], "domains": {"slack.com", "slack-edge.com"}, "ambiguous": True, "national": False},
    "Discord": {"labels": ["discord"], "domains": {"discord.com", "discordapp.com"}, "ambiguous": True, "national": False},
    "Stripe": {"labels": ["stripe"], "domains": {"stripe.com"}, "ambiguous": True, "national": False},
    "Uber": {"labels": ["uber"], "domains": {"uber.com"}, "ambiguous": True, "national": False},
    "Etsy": {"labels": ["etsy"], "domains": {"etsy.com"}, "ambiguous": False, "national": False},
    "Ledger": {"labels": ["ledger"], "domains": {"ledger.com"}, "ambiguous": True, "national": False},
    "Trezor": {"labels": ["trezor"], "domains": {"trezor.io"}, "ambiguous": False, "national": False},
    "MetaMask": {"labels": ["metamask"], "domains": {"metamask.io", "consensys.net", "consensys.io"}, "ambiguous": False, "national": False},
    "OpenSea": {"labels": ["opensea"], "domains": {"opensea.io"}, "ambiguous": False, "national": False},
    "Trust Wallet": {"labels": ["trustwallet"], "domains": {"trustwallet.com"}, "ambiguous": False, "national": False},
    "Royal Mail": {"labels": ["royalmail"], "domains": {"royalmail.com"}, "ambiguous": False, "national": False},
    "Evri": {"labels": ["evri"], "domains": {"evri.com"}, "ambiguous": False, "national": False},
    "Revolut": {"labels": ["revolut"], "domains": {"revolut.com"}, "ambiguous": False, "national": False},
    "Steam": {"labels": ["steampowered", "steamcommunity"], "domains": {"steampowered.com", "steamcommunity.com", "valvesoftware.com"}, "ambiguous": True, "national": False},
    "Roblox": {"labels": ["roblox"], "domains": {"roblox.com"}, "ambiguous": False, "national": False},
    "HSBC": {"labels": ["hsbc"], "domains": {"hsbc.com"}, "ambiguous": False, "national": True},
    "Barclays": {"labels": ["barclays"], "domains": {"barclays.com", "barclays.co.uk"}, "ambiguous": False, "national": True},
    "Santander": {"labels": ["santander"], "domains": {"santander.com"}, "ambiguous": False, "national": True},
    "Costco": {"labels": ["costco"], "domains": {"costco.com"}, "ambiguous": False, "national": True},
    "Lowe's": {"labels": ["lowes"], "domains": {"lowes.com"}, "ambiguous": False, "national": False},
    "Home Depot": {"labels": ["homedepot"], "domains": {"homedepot.com"}, "ambiguous": False, "national": False},
    "Target": {"labels": ["target"], "domains": {"target.com"}, "ambiguous": True, "national": False},
    "Temu": {"labels": ["temu"], "domains": {"temu.com"}, "ambiguous": False, "national": False},
    "AliExpress": {"labels": ["aliexpress"], "domains": {"aliexpress.com", "alibaba.com"}, "ambiguous": False, "national": True},
}

# Free app-hosting and site-builder platforms: anyone can create a sub-address there in seconds, so a sender on one
# says nothing about who is behind it. (Genuine apps do send from them, so this is only a weak hint.)
FREE_HOSTING = {"firebaseapp.com", "web.app", "pages.dev", "github.io", "herokuapp.com", "netlify.app", "vercel.app",
                "blogspot.com", "weebly.com", "wixsite.com", "000webhostapp.com", "glitch.me", "onrender.com",
                "azurewebsites.net", "appspot.com", "workers.dev", "cloudfunctions.net", "r2.dev"}

# Display-name aliases (lower-case) -> brand
BRAND_ALIASES: dict[str, str] = {}
for _b, _d in BRANDS.items():
    BRAND_ALIASES[_b.lower()] = _b
    for _l in _d["labels"]:
        BRAND_ALIASES[_l] = _b
BRAND_ALIASES.update({
    "office 365": "Microsoft", "microsoft 365": "Microsoft", "apple id": "Apple",
    "amazon prime": "Amazon", "bank of america": "Bank of America", "wells fargo": "Wells Fargo",
    "internal revenue service": "IRS", "quick books": "Intuit / QuickBooks", "docu sign": "DocuSign",
    "meta": "Facebook / Meta", "paypal inc": "PayPal", "cash app": "Cash App",
    "american express": "American Express", "best buy": "Best Buy / Geek Squad", "geek squad": "Best Buy / Geek Squad",
    "capital one": "Capital One", "trust wallet": "Trust Wallet", "royal mail": "Royal Mail", "steam": "Steam", "home depot": "Home Depot",
    "lowe's": "Lowe's", "ali express": "AliExpress",
})

SERVICE_WORDS = re.compile(
    r"\b(security|support|billing|account|accounts|team|service|services|alert|alerts|notification|"
    r"notifications|verification|verify|order|orders|payment|payments|id|prime|helpdesk|help desk|admin|"
    r"no-?reply|noreply|customer|care|fraud|login|sign-?in|delivery|shipping|refund|tax|"
    r"drive|docs|sheets|slides|meet|meeting|meetings|video|recording|recordings|calendar|cloud|wallet|pay|store|play|photos|maps|workspace|storage|music|receipts?)\b", re.I)

# Lookalike characters (Cyrillic/Greek/other) -> Latin skeleton, plus digit lookalikes.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "ѕ": "s", "і": "i",
    "ј": "j", "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u", "ν": "v", "ο": "o", "α": "a", "ρ": "p",
    "τ": "t", "ɑ": "a", "ӏ": "l", "ɩ": "i", "ℓ": "l", "ʟ": "l", "ο": "o", "Ι": "i", "Ο": "o",
}
DIGIT_LOOKALIKE = {"0": "o", "1": "l", "5": "s", "3": "e", "$": "s"}


def normalize_host(host: str) -> str:
    host = (host or "").strip().strip("[]").lower().rstrip(".")
    host = host.split(":")[0] if host.count(":") == 1 else host  # drop :port (not IPv6)
    return host


def is_ip(host: str) -> bool:
    h = normalize_host(host)
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    # Decimal / hex / octal-style IPv4 obfuscation: http://3232235777/ or 0xC0A80001
    return bool(re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", h))


def to_ascii_host(host: str) -> str:
    host = normalize_host(host)
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def to_unicode_host(host: str) -> str:
    host = normalize_host(host)
    out = []
    for lab in host.split("."):
        if lab.startswith("xn--"):
            try:
                lab = lab.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        out.append(lab)
    return ".".join(out)


def registrable_domain(host: str) -> str:
    host = to_ascii_host(host)
    if not host or is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in MULTI_SUFFIX and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def label_of(registrable: str) -> str:
    return registrable.split(".")[0]


def suffix_of(registrable: str) -> str:
    return registrable[len(label_of(registrable)) + 1:]


def scripts_in(text: str) -> set[str]:
    out = set()
    for ch in text:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            if name.startswith("LATIN"):
                out.add("LATIN")
            elif name.startswith("CYRILLIC"):
                out.add("CYRILLIC")
            elif name.startswith("GREEK"):
                out.add("GREEK")
            elif name.startswith(("CJK", "IDEOGRAPHIC")):
                out.add("HAN")
            elif name.startswith(("HIRAGANA", "KATAKANA")):
                out.add(name.split()[0].split("-")[0])
            elif name:
                out.add(name.split()[0])
    return out


# Script combinations that are ordinary in real writing systems (Unicode UTS #39, "highly restrictive").
# Latin mixed with Cyrillic or Greek is NOT in this list, because that is the classic homograph trick.
_NORMAL_COMBINATIONS = (
    {"LATIN", "HAN", "HIRAGANA", "KATAKANA"},   # Japanese
    {"LATIN", "HAN", "BOPOMOFO"},                # Chinese (Taiwan)
    {"LATIN", "HAN", "HANGUL"},                  # Korean
)


def mixed_script_is_suspicious(scripts: set[str]) -> bool:
    if len(scripts) <= 1:
        return False
    return not any(scripts <= combo for combo in _NORMAL_COMBINATIONS)


def normalize_display(text: str) -> str:
    """Display-name text with invisible characters removed and look-alike letters mapped to Latin,
    so 'C<zero-width>oinbase' and Cyrillic-letter names still match the brand they imitate."""
    out = []
    for ch in unicodedata.normalize("NFKC", text):
        cp = ord(ch)
        if unicodedata.category(ch) == "Cf" or 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
            continue
        out.append(CONFUSABLES.get(ch, CONFUSABLES.get(ch.lower(), ch)))
    return "".join(out)


def skeleton(label: str) -> str:
    s = unicodedata.normalize("NFKC", label).lower()
    s = "".join(CONFUSABLES.get(c, c) for c in s)
    s = s.replace("rn", "m").replace("vv", "w").replace("-", "")
    s = "".join(DIGIT_LOOKALIKE.get(c, c) for c in s)
    return s


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def is_genuine_brand_domain(brand: str, registrable: str) -> bool:
    info = BRANDS.get(brand)
    if not info:
        return False
    if registrable in info["domains"]:
        return True
    if info.get("national"):
        lab, suf = label_of(registrable), suffix_of(registrable)
        if lab in info["labels"]:
            last = suf.split(".")[-1]
            if (len(last) == 2 or suf in MULTI_SUFFIX) and last not in NATIONAL_TLD_DENY:
                return True
    return False


def brand_for_domain(registrable: str) -> str | None:
    for b in BRANDS:
        if is_genuine_brand_domain(b, registrable):
            return b
    return None


def brand_lookalike(host: str) -> dict | None:
    """Does this host imitate a known brand's domain without being it?

    Returns {brand, kind, strength, why} or None. Never fires for a genuine brand
    domain, and never fires merely because a domain is unfamiliar.
    """
    ascii_host = to_ascii_host(host)
    if is_ip(ascii_host):
        return None
    reg = registrable_domain(ascii_host)
    uni_host = to_unicode_host(ascii_host)
    uni_reg_label = label_of(to_unicode_host(reg))
    label = label_of(reg)
    sub = ascii_host[: -len(reg)].rstrip(".") if ascii_host.endswith(reg) else ""

    for brand, info in BRANDS.items():
        if is_genuine_brand_domain(brand, reg):
            continue
        for bl in info["labels"]:
            # 1. brand used as a subdomain of someone else's domain
            if len(bl) >= 4 and re.search(rf"(^|[.\-]){re.escape(bl)}([.\-]|$)", sub):
                # The brand's real domain written out inside someone else's domain
                # (drive.google.com.evil.test) is never an accident, even for everyday-word brands.
                embeds_real = any(re.search(rf"(^|\.){re.escape(d)}(\.|$)", sub) for d in info["domains"])
                return dict(brand=brand, kind="brand_in_subdomain",
                            strength="strong" if (embeds_real or not info["ambiguous"]) else "moderate",
                            why=f"'{bl}' appears in the subdomain of {reg}, which is not a {brand} domain")
            # 2. confusable / homoglyph skeleton equals brand label
            sk = skeleton(uni_reg_label)
            if sk == bl and uni_reg_label != bl:
                return dict(brand=brand, kind="homoglyph", strength="strong",
                            why=f"'{uni_host}' is visually confusable with {bl}")
            # 3. brand as a hyphen-separated token ("paypal-secure-login.com")
            toks = re.split(r"[-_]", label)
            if len(bl) >= 4 and bl in toks and len(toks) > 1:
                return dict(brand=brand, kind="brand_token", strength="strong",
                            why=f"{reg} embeds '{bl}' as a word but is not a {brand} domain")
            # 4. brand string contained in a longer label (paypalsecure.com)
            if len(bl) >= 6 and bl in label and label != bl:
                return dict(brand=brand, kind="brand_contained", strength="moderate",
                            why=f"{reg} contains '{bl}' but is not a {brand} domain")
            # 5. one-edit typo of a long brand label (paypall, microsfot)
            if len(bl) >= 6 and label != bl and edit_distance(skeleton(label), bl) == 1:
                return dict(brand=brand, kind="typosquat", strength="moderate",
                            why=f"{reg} is one character away from '{bl}'")
            # 6. brand label under a different suffix (paypal.co, microsoft.support)
            if len(bl) >= 5 and label == bl and not is_genuine_brand_domain(brand, reg):
                return dict(brand=brand, kind="wrong_suffix", strength="strong",
                            why=f"{reg} uses the {brand} name under a different domain")
    return None


def idn_findings(host: str) -> list[str]:
    """Findings about internationalized hostnames. Single-script IDNs are NOT suspicious."""
    out = []
    uni = to_unicode_host(host)
    for lab in uni.split("."):
        sc = scripts_in(lab)
        if mixed_script_is_suspicious(sc):
            out.append(f"mixed scripts ({', '.join(sorted(sc))}) in label '{lab}'")
    return out
