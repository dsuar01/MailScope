"""Optional reputation checks. Both providers are OFF by default.

1. Local feed (offline): a plain-text file the user supplies, one domain or URL per
   line ('#' comments allowed), e.g. a list exported from OpenPhish, URLhaus or
   PhishTank. Comparison happens entirely on this computer.
2. URLhaus lookup (online, opt-in): sends each link's URL to abuse.ch's URLhaus
   API (https://urlhaus-api.abuse.ch/v1/url/). Needs a free Auth-Key from
   https://auth.abuse.ch/ in the MAILSCOPE_URLHAUS_KEY environment variable.
   Data leaving the computer: the link URLs found in the email (not the message
   text, sender, or attachments). This provider was written against the public API
   documentation but was NOT exercised in the build environment (no network
   access), so treat its first live run as a test.

A listing is strong evidence. NOT being listed means "unknown": phishing sites are
often live for hours before any feed learns of them.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from .domains import registrable_domain
from .models import Link, Signal

URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
MAX_ONLINE_LOOKUPS = 10


def load_feed(path: str) -> tuple[set[str], set[str], str]:
    """Return (domains, urls, status). Never raises."""
    if not path:
        return set(), set(), "not configured"
    try:
        with open(os.path.expanduser(path), encoding="utf-8", errors="replace") as fh:
            lines = [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError as exc:
        return set(), set(), f"unavailable: cannot read feed file ({exc.__class__.__name__})"
    domains, urls = set(), set()
    for ln in lines:
        if "/" in ln or "://" in ln:
            urls.add(ln.rstrip("/").lower())
            host = urllib.parse.urlsplit(ln if "://" in ln else "http://" + ln).hostname
            if host and "/" not in ln.split("://")[-1].rstrip("/"):
                domains.add(registrable_domain(host))
        else:
            domains.add(registrable_domain(ln.lower()))
    return domains, urls, f"loaded {len(lines)} entries"


def check_reputation(links: list[Link], feed_path: str = "", use_urlhaus: bool = False,
                     urlhaus_key: str | None = None, opener=None) -> tuple[list[Signal], dict[str, str]]:
    status = {"local_feed": "not configured", "urlhaus": "not enabled"}
    sigs: list[Signal] = []
    listed: list[str] = []

    if feed_path:
        domains, urls, st = load_feed(feed_path)
        status["local_feed"] = st
        for l in links:
            if l.url.rstrip("/").lower() in urls or (l.registrable and l.registrable in domains):
                listed.append(f"{l.url[:120]}  (matched local feed)")

    if use_urlhaus:
        key = urlhaus_key or os.environ.get("MAILSCOPE_URLHAUS_KEY", "")
        if not key:
            status["urlhaus"] = "unavailable: set the MAILSCOPE_URLHAUS_KEY environment variable (free key from auth.abuse.ch)"
        else:
            opener = opener or urllib.request.urlopen
            checked, errors = 0, 0
            for l in links[:MAX_ONLINE_LOOKUPS]:
                data = urllib.parse.urlencode({"url": l.url}).encode()
                req = urllib.request.Request(URLHAUS_ENDPOINT, data=data, headers={"Auth-Key": key})
                try:
                    with opener(req, timeout=8) as resp:
                        body = json.loads(resp.read().decode("utf-8", "replace"))
                    checked += 1
                    if body.get("query_status") == "ok":
                        listed.append(f"{l.url[:120]}  (URLhaus: {body.get('url_status', 'listed')}, threat: {body.get('threat', 'n/a')})")
                except (urllib.error.URLError, TimeoutError, ValueError, OSError):
                    errors += 1
            status["urlhaus"] = f"queried {checked} of {min(len(links), MAX_ONLINE_LOOKUPS)} links" + (f"; {errors} failed" if errors else "")
            if len(links) > MAX_ONLINE_LOOKUPS:
                status["urlhaus"] += f" (limit {MAX_ONLINE_LOOKUPS}; {len(links) - MAX_ONLINE_LOOKUPS} not checked)"

    if listed:
        sigs.append(Signal("reputation_listed", "reputation", "strong", "A link appears in a threat feed",
                           "A feed you configured lists this destination as malicious or phishing.", listed[:5]))
    return sigs, status
