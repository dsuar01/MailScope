"""Authentication evidence: recorded CLAIMS versus real cryptographic checks.

Important limits (shown to the user too):
* An Authentication-Results header inside an uploaded .eml is text. Anyone who
  built the file can write "dkim=pass" in it. We report it as a claim and give it
  no credit; a recorded *failure* is mildly informative because forgers rarely
  add failures.
* SPF cannot be re-checked from a file: it depends on the IP address that
  connected to the receiving server at delivery time and on the DNS records of
  that moment. DMARC needs SPF or DKIM results to evaluate.
* DKIM can be re-verified from the file if the message bytes are unmodified and
  the signer's public key can still be fetched from DNS. That lookup is a network
  request (it reveals only the signer's domain and selector, never the message),
  so it is OFF unless the user opts in.
* A valid DKIM signature proves a domain signed these bytes. It does not make
  the content safe: criminals own domains and send validly signed mail.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .domains import registrable_domain
from .models import ParsedEmail, Signal

CLAIM_RE = re.compile(r"(?i)\b(spf|dkim|dmarc|arc|compauth)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy|bestguesspass)")
BAD = {"fail", "softfail", "permerror"}


@dataclass
class DKIMResult:
    status: str                     # not_performed | unavailable | no_signature | verified | failed | error
    detail: str = ""
    signers: list[dict] = field(default_factory=list)   # {"domain","selector","verified","aligned"}


def recorded_claims(pe: ParsedEmail) -> list[str]:
    claims = []
    for hdr in ("authentication-results", "received-spf", "arc-authentication-results"):
        for v in pe.headers.get(hdr, []):
            for m in CLAIM_RE.finditer(" ".join(v.split())):
                claims.append(f"{hdr}: {m.group(1).lower()}={m.group(2).lower()}")
    return claims


def dkim_signature_domains(pe: ParsedEmail) -> list[dict]:
    out = []
    for v in pe.headers.get("dkim-signature", []):
        d = re.search(r"(?i)\bd=\s*([^;\s]+)", v)
        s = re.search(r"(?i)\bs=\s*([^;\s]+)", v)
        if d:
            out.append({"domain": d.group(1).lower(), "selector": s.group(1) if s else ""})
    return out


def verify_dkim(pe: ParsedEmail, enabled: bool) -> DKIMResult:
    sigs = dkim_signature_domains(pe)
    if not enabled:
        return DKIMResult("not_performed",
                          "Cryptographic DKIM verification was not requested. Enable it in the sidebar to check signatures (one DNS lookup per signer).",
                          [dict(s, verified=None, aligned=None) for s in sigs])
    if not sigs:
        return DKIMResult("no_signature", "The message carries no DKIM-Signature header, so there is nothing to verify.")
    try:
        import dkim  # type: ignore  (dkimpy)
    except ImportError:
        return DKIMResult("unavailable", "The optional 'dkimpy' package is not installed (pip install dkimpy).",
                          [dict(s, verified=None, aligned=None) for s in sigs])
    results, errors = [], []
    from_reg = registrable_domain(pe.from_domain) if pe.from_domain else ""
    for i, s in enumerate(sigs):
        ok = False
        try:
            ok = bool(dkim.DKIM(pe.raw).verify(idx=i))
        except Exception as exc:  # DNS failure, malformed signature, etc.
            errors.append(f"{s['domain']}: {exc.__class__.__name__}: {str(exc)[:80]}")
        results.append(dict(s, verified=ok, aligned=ok and registrable_domain(s["domain"]) == from_reg))
    if any(r["verified"] for r in results):
        return DKIMResult("verified", "At least one signature verified against the signer's published key.", results)
    return DKIMResult("failed" if not errors else "error",
                      "No signature verified." + (" Problems: " + "; ".join(errors) if errors else ""), results)


def analyze_auth(pe: ParsedEmail, dkim_enabled: bool) -> tuple[list[Signal], list[str], DKIMResult]:
    sigs: list[Signal] = []
    claims = recorded_claims(pe)
    failed = [c for c in claims if c.split("=")[-1] in BAD]
    if failed:
        sigs.append(Signal("recorded_auth_fail", "auth", "weak",
                           "Recorded authentication result reports a failure",
                           "This is text stored in the file (not re-verified). Failures can also come from forwarding or mailing lists, so the weight is small.",
                           failed[:4]))
    res = verify_dkim(pe, dkim_enabled)
    if res.status == "failed":
        sigs.append(Signal("dkim_failed", "auth", "weak", "DKIM signature present but did not verify",
                           "The signed content may have been altered or forged; forwarding and list software also break signatures, so the weight is small.",
                           [f"{r['domain']} (selector {r['selector']})" for r in res.signers][:3]))
    return sigs, claims, res
