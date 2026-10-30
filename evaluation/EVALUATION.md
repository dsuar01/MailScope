# Evaluation protocol and results

**Read this first.** Every labelled set below is synthetic: written by one author (the same one who wrote the rules) who knew what the engine looks for. They are small. They are
useful for finding weaknesses and catching regressions. **They do not measure production
accuracy**, and nothing here should be quoted as "MailScope is X % accurate".

## Protocol

1. Labels are `phishing`, `scam_spam` or `legit`. "Flagged" means indicator ≥ 40 (Medium or High).
   A second, lower threshold of 15 ("any signal at all") is also reported.
2. **Labels are never changed to improve results.** Disagreements stay in the result files.
3. Each set is written **before** the engine is run on it. Its **first run** is saved unedited.
4. Once a set's failures lead to an engine change, that set becomes a development set and can no
   longer judge the engine; a new set is written.
5. Analysis failures (exceptions, "incomplete" verdicts) are counted separately, never as correct.
   There were none in any set.
6. `heldout3.sha256` and `heldout4.sha256` fingerprint the case files as frozen. Verify with
   `cd evaluation/heldout4 && sha256sum -c ../heldout4.sha256`.
7. Hard cases (a hijacked genuine mailbox, a wrong-number opener, an image-only QR message) are
   included **on purpose** to show misses.

## Sets

| Set | Messages (suspicious / legit) | Written | Role now |
|---|---|---|---|
| `dev` | 16 (9 / 7) | first | development |
| `heldout` | 35 (19 / 16) | after round 1 fixes | development (its failures drove fixes) |
| `heldout2` | 25 (13 / 12) | after round 2 fixes | development |
| `heldout3` | 38 (18 / 20) | before round 3 fixes | development (3 of its failures drove fixes) |
| `heldout4` | 44 (22 / 22) | after round 3 fixes, before first run | **first run = unbiased figure; development after the n22 fix** |

## Results (flagged = indicator ≥ 40)

"First run" is on the engine as it stood when the set was first scored (earlier sets on earlier
engine versions). "Current" is the final engine. Files: `results_*_BEFORE*`, `*_FIRST_RUN*`, `*_FINAL.txt`.

| Set | Suspicious caught, first run | Legit flagged, first run | Suspicious caught, current | Legit flagged, current |
|---|---|---|---|---|
| dev | n/a | n/a | 9 / 9 | 0 / 7 |
| heldout | 11 / 19 | 0 / 16 | 17 / 19 | 0 / 16 |
| heldout2 | 9 / 13 | 2 / 12 | 13 / 13 | 0 / 12 |
| heldout3 | 14 / 18 | 0 / 20 | 17 / 18 | 0 / 20 |
| heldout4 | 14 / 22 | 1 / 22 | 19 / 22 | 0 / 22 |

Totals, current engine, over all five sets: 75 of 81 suspicious messages at or above 40 and 0 of 77
legitimate messages at or above 40. **The current figures are optimistic** because the same
messages guided the fixes. The honest generalisation figures are the first-run columns.

### First run of the untouched set (heldout4), unedited
Caught 14 of 22. Missed: `p06` (executive request with diverted replies), `p09` (PDF link
invoice), `p14` (Zelle lure, brand not in table), `p16` (loan spam), `p17` (domain-renewal
notice), `p18` (wrong-number opener), `p19` (hijacked thread), `p20` (dating spam).
Wrongly flagged: `n22`, a genuine Japanese shop (flagged "Likely phishing", 84). That was a real
bug: standard Japanese script combinations were treated as a homograph attack.

### What is still missed, current engine
| Case | Why |
|---|---|
| `heldout/h13_compromised_vendor_clean` | clean wording from a real-looking vendor with one file-share link |
| `heldout/h18_seo_cold_spam` | polite cold marketing, not deceptive |
| `heldout3/p15_hijacked_account_link` | one-line message with a link from a hijacked account |
| `heldout4/p09_pdf_link_invoice` (score 19) | throwaway domain invoice; only abused-ending hints fire |
| `heldout4/p18_wrong_number_lure` | no link, no request: nothing to detect |
| `heldout4/p19_hijacked_vendor_thread` | link to an unfamiliar domain from a real account |

### Legitimate messages that still get a "Low" (15–39) score
`heldout/l13_saas_promo` (19), `heldout2/n01_small_biz_gmail_support` (30, organisation-style name
on a free mailbox), `heldout2/n03_store_receipt_call_us` (30, receipt that says to phone if you
did not order), `heldout2/n10_forwarded_to_security` (19), `heldout3/n16_retail_promo` (19),
`heldout4/n04_linkedin_real` (19), `heldout4/n19_retail_sale_caps` (23). At threshold 15 these
would be false alarms. Low means "double-check", not "dangerous".

### Baseline
`baseline_keyword.py` is a simple additive keyword scorer, written because
no published baseline was available. It catches almost nothing at threshold 50 (2 of 9 on `dev`, 0 on the four other sets). Treat it as a weak reference point, not a fair comparison with a tuned scorer:
a different threshold or weights would score differently.

## Real-world run (messages written by other people)

Corpus: **Phishing Pot** (<https://github.com/rf-peixoto/phishing_pot>, CC BY-NC 4.0), 12,271
real messages collected by someone else. It is **not copied into this project**; the runner
(`run_realworld.py`) reads a folder you point it at and writes only aggregate numbers. Network
access is disabled while it runs (0 attempts were made). The collection mixes phishing, fraud,
spam and malware-delivery mail, individual messages are not labelled by type, and it contains
**no legitimate mail**, so this measures only *how much of the bad mail gets flagged*. It cannot
show false alarms, and a rate like this can always be raised by flagging more, so read it together
with the synthetic false-alarm results, not instead of them.

| | First run (engine before round 4) | Final run (final engine) |
|---|---|---|
| Messages scored | 12,266 | 12,269 |
| Flagged, indicator ≥ 40 (Medium/High) | **5,035 (41.1 %)** | **5,617 (45.8 %)** |
| Any signal, indicator ≥ 15 | 8,382 (68.3 %) | 8,846 (72.1 %) |
| "No strong signals found" (under 15) | 3,884 (31.7 %) | 3,423 (27.9 %) |
| Analysis failures | 5 (3 were a real crash on a bogus charset name; 2 were not emails) | 2 (both files are not emails and are correctly reported "incomplete") |
| Network attempts | 0 | 0 |

The **first-run column is the unbiased figure**; the final run is a development figure because
the first run's findings guided the round-4 fixes. Files: `results_realworld_FIRST_RUN.json`,
`results_realworld_FINAL.json`.

**What this says, plainly.** On real mail written by other people, MailScope flags fewer than half
of the messages at Medium or above, and about three in ten get no signal at all. That is much lower
than the 86 %+ on my synthetic sets, which is exactly why the synthetic numbers must not be quoted
as accuracy: they were written by someone who knew what the engine looks for.

**What the misses are** (from reading summaries of samples, not from a labelled breakdown):
- **Commercial spam and scam promotions** (casino "free spins", instant loans, miracle-health ads,
  dating bait) that carry no deception about identity. Round 4 added wording and structure for the
  most common kinds, which accounts for much of the gain.
- **Brand lures for brands outside the built-in table** (the table now has 61 brands).
- **Non-English mail**: 57.7 % of the corpus (7,075 messages) does not look English. The wording
  rules are English-only. Flag rate: 50.1 % for non-English, 39.9 % for English-looking messages
  (5,194). So language is not the whole story: the structural checks work in any language, and
  English-looking spam in this corpus is mostly promotional rather than deceptive. Every such
  result now carries a notice that wording was not assessed.
- **Clean-looking messages** with no deceptive structure (see the failure-mode list above).
- A large number of messages (2,108 in the first run) have **no usable From address**, which the
  engine reports as an origin problem but which carries little other evidence.

**What was fixed because of this run:** the charset crash, invisible/look-alike-letter disguises
in sender names and subjects, a spoofed-brand-sender rule, free-hosting senders, unfilled template
placeholders, gambling/loan/miracle-health promotion wording, 19 more brands, and the non-English
notice. Each has a regression test (`Round4RealWorldRegressionTests`). One of the new rules
immediately produced a false alarm on a synthetic legitimate message (a person on outlook.com
sharing a news link); that was fixed and tested.

**What was deliberately not done:** a "display name does not match the sender domain" rule for
every sender. It would catch many more of these, but with no real legitimate mail to measure its
false alarms on, it would inflate the detection rate without anyone being able to see the cost.

## What is NOT measured
- Accuracy on **real legitimate mail**. No independently labelled legitimate corpus was available in
  the build environment (network access was limited to a few sites), so false-alarm rates rest only
  on the 77 synthetic legitimate messages above.
- Phishing-vs-spam typing on real mail (the real-world corpus is not labelled by type).
- DKIM verification on real signatures and the URLhaus lookup (needed packages or network access
  that the build environment did not allow).
- The Streamlit page in a real browser. `tests/test_app_smoke.py` drives `app.py` with a stand-in
  for Streamlit; start the app yourself and look at it.
