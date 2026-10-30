# Audit: why the earlier MailScope fell short

**What this audit is based on.** The original MailScope source files were never attached to this
conversation, so I could not read them. This audit therefore rests on (1) the symptoms and design
you described, and (2) what building and testing a replacement showed. Where a point below is
about your original code, it is a *consequence of the described design*, not something I read in
the code. If you find the original files, compare them against this list.

## The path from email to verdict, and where it breaks

```
.eml file -> parse -> fixed indicator points -> contextual rules -> verdict + score -> report
```

| # | Weakness (as described) | Why it matters | What the rebuilt version does |
|---|---|---|---|
| 1 | **Two scoring systems.** Legacy points plus separate contextual rules were added together or shown side by side. | Produces "warning" next to a near-zero score. The reader cannot tell which to believe. | One list of findings. The verdict **and** the number are computed from that same list (`risk_assessment.py`), and a test fails if they disagree. |
| 2 | **Unexplained number.** Arbitrary points looked like a probability. | People read "30" as "30 % chance". Nothing supports that. | The number is labelled an *evidence-strength indicator*; its meaning is printed beside it and in every report. |
| 3 | **"No strong signals detected" read as "safe".** | Silence from a limited tool is not evidence of safety. | The "none" verdict says "this is not a safety clearance"; unknowns are listed; failed stages give "analysis incomplete", never a quiet pass. |
| 4 | **Wording-driven detection.** Fixed points for phrases. | Easy to evade, easy to over-fit to your own examples, and says nothing about *who* is writing. | Wording is only *intent* evidence. Verdicts are driven by deception (sender identity, link structure, attachment bytes) **combined with** a request for action. |
| 5 | **Authentication claims.** Authentication-Results text in a file is writable by anyone. | Treating "dkim=pass" text as proof is a classic mistake. | Recorded claims get **no credit** and are shown as untrusted text. Only the optional real DKIM check counts, and even then it proves a signature, not safety. |
| 6 | **Missing evidence treated as neutral or good.** | Absence of data ≠ absence of risk. | Every unchecked thing (SPF/DMARC, redirects, domain age, images, QR codes, compressed PDF content) is listed under "What could not be verified". |
| 7 | **Impersonation depends on a brand list.** | Unknown brands are invisible; ambiguous words ("Apple", "Google") need care. | A brand table with genuine-domain lists and "everyday word" handling. Two gaps found and fixed this round: the real brand domain written inside a foreign subdomain, and product names ("Google Drive") as display names. About 60 brands; extendable. |
| 8 | **Internationalised domains.** | Flagging every non-ASCII domain would wrongly condemn real Japanese, Chinese, Korean or accented-Latin businesses. | Mixed-script detection follows the Unicode security rule: Latin+Cyrillic or Latin+Greek is suspicious; standard Japanese/Chinese/Korean combinations are not. A real false alarm on a Japanese shop was found by the untouched test set and fixed. |
| 9 | **Validation measured the wrong thing.** 178 passing tests show the code does what the author expects, not that it catches real phishing. | Tests written by the same person as the rules share the same blind spots. | Separate evaluation sets with first-run results kept unedited, hash-frozen case files, false positives/negatives reported by name, plus a run over 12,271 real-world messages written by others. |
| 10 | **No threat intelligence.** | A brand-new look of a known-bad URL is invisible to heuristics. | Optional offline feed file and opt-in URLhaus lookup, both clearly labelled with what leaves the computer. |

## Weaknesses found *while rebuilding* (all fixed, each with a regression test)

| Found by | Weakness | Fix |
|---|---|---|
| heldout2 / p09 | Plaintext sextortion ("I recorded you, send bitcoin") scored 10 | New `extortion_threat` finding: a claim of compromise **plus** a payment demand or threat. Articles about bitcoin do not trigger it (test). |
| heldout2 / p05 | Macro-enabled "resume" with no invoice wording scored 30 | Risky attachment + "see attached"-style reference is now a combination finding. |
| heldout2 / p10 | "Our accounting moved to another bank, use the new account" scored 0 | Bank-move phrasing recognised; a bank-detail change that does not point to the sender's own site is rated strong (confirm by phone). A supplier that points to its own portal stays low (test). |
| heldout3 / p08 | `drive.google.com.share-docs.top` rated only "moderate" because Google is an everyday word | A brand's real domain written inside someone else's domain is always strong. |
| heldout3 / p14 | "Virus detected, call 1-888…" scored 10 | New `tech_support_scam` finding (fake alert + phone call). |
| heldout3 / p02 | Mailbox-full lure whose link sat on the sender's own lookalike domain scored 19 | New `mailbox_admin_unrelated` finding: a mailbox notice from a domain unrelated to the recipient's mailbox or a known mail brand. |
| heldout4 / n22 | Genuine Japanese shop domain flagged "Likely phishing" (84) | Script-mixing rule corrected (see #8). |
| heldout4 / n09 | `googlegroups.com` treated as a Google lookalike | Added to Google's genuine domains. |
| heldout4 / p06 | "Process an urgent payment to a new supplier", replies diverted, scored 27 | New-payee payment instruction recognised; combines with diverted replies. |
| heldout4 / p17 | Fake domain-renewal "this is not a bill" notice scored 0 | New `domain_fee_scam` finding. |
| heldout4 / p16, p20 | Loan and dating spam under 40 | A few more spam phrases plus a weak "abused domain ending" hint on the sender. |
| real-world run | Three messages with a bogus charset name (`charset="U"`) crashed parsing; the fallback itself raised | Safe decoding that can never raise. A regression test covers it. |
| real-world run | A sender name padded with invisible characters (`C·o·i·n·b·a·s·e`) or a subject spelled with Cyrillic look-alike letters (`Соngrаtulаtіоns`) slipped past brand matching | New `obfuscation.py` flags invisible/look-alike characters inside words in the sender name (strong) and subject (moderate); display names are normalised before brand matching. Emoji joiners, Persian/Indic joiners and body-text padding are deliberately ignored (tests). |
| real-world run | Most undetected real phishing was **not in English** (Portuguese, French, Dutch, German, Spanish...). The wording rules are English-only, so they said nothing, and the result read "No strong signals found". | Not solved: translating the rules would be a keyword treadmill. Instead the result now **says so** ("the text does not look English; wording gave no evidence either way") and the report lists it under what could not be verified. Structural checks (sender, links, attachments, obfuscation) still apply to any language. |
| real-world run | Genuine brand domain in From, but every link goes to an unrelated site (typical forged From) | New `brand_sender_foreign_links` finding (moderate). Social-media links and the brand's own links are exempt (tests). |
| real-world run | Brands such as Ledger, OpenSea, MetaMask, Trust Wallet, Royal Mail, Revolut, HSBC were not in the table | More commonly impersonated brands added (61 in total). |
| performance | Large messages took 0.4 s; capital-letter statistics scanned every character | Statistics now use the first 50,000 characters; results unchanged (verified). |
