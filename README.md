# MailScope

A local first-pass check of a suspicious email. You give it a saved message (`.eml`); it tells you
whether the **sender/origin** looks inconsistent, whether the **content, links or attachments**
carry dangerous signals, **what evidence** supports that, **what could not be verified**, and
**what to do next**.

It is a triage aid for a person, not a verdict machine. It never says a message is safe.

## Install and start

You need Python 3.10 or newer (free). Everything else is installed for you on first run.
Nothing is sent anywhere while MailScope runs.

### Windows (easiest)
1. **Install Python** if you do not have it: <https://www.python.org/downloads/>. On the first
   installer screen tick **"Add python.exe to PATH"**, then click *Install Now*.
2. **Extract the zip** (right-click it, *Extract All...*). Do not run anything from inside the zip window.
3. Open the extracted folder that contains `app.py` and **double-click `start_mailscope.bat`**.
   The first run creates a private environment and installs what it needs (a few minutes, needs
   internet). Then your browser opens at <http://127.0.0.1:8501> (if it does not, type that address).
4. To stop MailScope, close the black window.

### macOS / Linux
```
bash start_mailscope.sh
```

### By hand (any system), no "activate" step needed
```
# Windows (Command Prompt or PowerShell)
py -3 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m streamlit run app.py

# macOS / Linux
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m streamlit run app.py
```
Then open <http://127.0.0.1:8501/>. The settings in `.streamlit/config.toml` keep the page reachable
only from your own computer and switch off usage statistics.

Use it: upload a `.eml` file, or pick one of the six synthetic examples in the dropdown.
The sidebar explains how to export a `.eml` from Gmail, Outlook, Apple Mail and Thunderbird.

### If it does not start
Run the self-check from the folder that contains `app.py` and read or send the whole output:
```
py -3 -m mailscope.doctor        (Windows)
python3 -m mailscope.doctor      (macOS / Linux)
```
It tells you the Python version, whether Streamlit is installed, whether the files are where they
should be, and proves the analysis engine itself runs (that part needs nothing but Python).

| What you see | Cause | Fix |
|---|---|---|
| `'py' is not recognized`, or Python opens the Microsoft Store | Python is not installed (or not on PATH) | Install it from python.org and tick **Add python.exe to PATH** |
| `running scripts is disabled on this system` | PowerShell blocks `activate` | Use `start_mailscope.bat` or the "no activate" commands above |
| `app.py not found`, or `requirements.txt not found` | wrong folder (often a doubled `mailscope_project\mailscope_project`) | Go into the folder that directly contains `app.py` |
| pip prints red errors or times out | no internet, or a company/school network or antivirus blocking pip | Try another network; send the text to Claude |
| `Port 8501 is already in use` | MailScope is already running in another window | Close the other window, or open <http://127.0.0.1:8501> |

The Windows launcher could not be tested on Windows when it was written; if it misbehaves, the
"by hand" commands above are the fallback, and the output of the self-check helps find the cause.

**Command line (no Streamlit needed)**

```
python3 -m mailscope message.eml                 # text report
python3 -m mailscope message.eml --format json   # machine-readable
python3 -m mailscope message.eml --format html > report.html
```

**Run the automated tests (standard library only, no extra packages)**

```
python3 -m unittest discover -s tests -v
```

**Run the labelled evaluation sets**

```
python3 evaluation/run_eval.py evaluation/heldout4 --verbose
```

## What leaves your computer

By default, nothing. Messages are parsed locally; attachments are never opened, HTML is never
rendered, images are never loaded, links are never visited.

Three optional checks exist, all **off by default**:

| Check | What it needs | What is sent, and where | Status in this build |
|---|---|---|---|
| DKIM signature verification (sidebar tick box or `--dkim`) | the `dkimpy` package (in `requirements.txt`) | DNS lookups for each signer's public key: only the signing domain and selector name leave your computer, via your normal DNS resolver. The message is not sent. | Code present. **Not exercised end-to-end here** (the package could not be installed in the build environment). Try it on a real message and treat the first run as a test. |
| Local threat-feed file (sidebar, or `MAILSCOPE_BLOCKLIST`) | a text file you supply, one domain or URL per line (for example an export from OpenPhish, URLhaus or PhishTank) | nothing; compared locally | Works, covered by tests. |
| URLhaus online lookup (sidebar tick box) | a free key from <https://auth.abuse.ch/> in the `MAILSCOPE_URLHAUS_KEY` environment variable | the link URLs found in the message (at most 10) go to `urlhaus-api.abuse.ch`. Not the message text, sender or attachments. Free; subject to their terms. | Code written to the public API description. **Never run against the live service.** If the key is missing the app says so and the check stays off. |

A threat-feed hit is strong evidence. A **non-hit means "unknown"**, never "safe": phishing sites
are often live for hours before any feed learns of them.

## What it can and cannot determine

**It can**
- Spot identity inconsistencies in the text of a message: a display name claiming a brand the
  domain does not own, lookalike and homograph domains, a real brand domain buried inside someone
  else's domain (`drive.google.com.evil.test`), link text that shows one site while the link goes
  to another, replies diverted to a free mailbox, raw-IP links, shorteners.
- Recognise dangerous *structures* in attachments by looking at bytes only: executables, double
  extensions, disguised types, macro-enabled Office files, disk images, HTML attachments with a
  login form or script, password-protected archives with the password in the body, PDFs with
  active content or links.
- Recognise common fraud intents: credential theft, payment diversion (changed bank details,
  executive requests, gift cards), blackmail/extortion, fake security alerts that tell you to
  phone, advance-fee and prize scams, spam.
- Keep **phishing**, **scam/spam** and **unverified origin** separate in the verdict.

**It cannot**
- Prove a message is genuine. A low score means little suspicious evidence was found, nothing more.
- Re-check SPF or DMARC from a saved file: those depend on the connecting server's IP address and
  DNS at delivery time. Early `Received` hops can be forged. "Authentication-Results" lines inside
  an uploaded file are only text anyone can write, so they earn **no credit**. Only the optional
  DKIM check is a real cryptographic test, and even a valid signature shows only that a domain
  signed those bytes, not that the content is safe.
- See what images, QR codes, compressed PDF content, redirect chains or landing pages contain.
- Detect a clean-looking message from a hijacked genuine mailbox when it has no tell-tale
  structure (see "Remaining failure modes").
- Replace your organisation's mail security or common sense.

Missing evidence stays **unknown** and is listed under "What could not be verified". It is never
turned into a safe verdict. A failed analysis stage produces an "analysis incomplete" result,
not a quiet pass.

## What the number means

The indicator (0–100) measures **how much independent suspicious evidence was found**. It is
**not** the probability that the message is phishing. The weights are expert judgement, not fitted
to data, and a real probability would need a large, representative, labelled collection of both
phishing and legitimate mail that this project does not have.

Every finding has a strength (weak 0.10, moderate 0.30, strong 0.60, combination 0.75). Findings
combine as independent clues, `100 × (1 − ∏(1 − weight))`, and repeated findings in one category
count half as much each time. The verdict and the number come from the **same list of findings**,
so a warning can no longer sit beside a near-zero score. Bands: 70+ High, 40–69 Medium, 15–39 Low,
under 15 Minimal.

## Design choices and trade-offs

| Approach | Used? | Why |
|---|---|---|
| More keywords / bigger weights for known examples | Only as *intent* evidence, never decisive on their own | Easy to evade, and tuning to examples measures nothing. |
| Structural analysis (sender identity, link structure, attachment bytes, combination of deception + request) | **Main driver** | Works without knowing the campaign; explainable; needs no external data. |
| Threat intelligence (known-bad URL feeds) | Opt-in, offline file or URLhaus | Strong when it hits, blind to new campaigns, and an online lookup shares link URLs. |
| Machine-learning model | **Not implemented** | The only large independent corpus available here (Phishing Pot) has no legitimate mail. A model trained on it would learn "looks like that collection", not "is phishing", and would likely over-flag real newsletters. It needs a matching, licensed, representative legitimate corpus plus calibration first. |

## Validation summary

Full details, protocol and per-message tables are in [`evaluation/EVALUATION.md`](evaluation/EVALUATION.md).
Short version, **flagged = indicator ≥ 40**:

| Set (messages) | Status | Suspicious caught (first run, unedited) | Legitimate wrongly flagged (first run) | Suspicious caught (current) | Legit wrongly flagged (current) |
|---|---|---|---|---|---|
| heldout (35) | used for fixes | 11 / 19 | 0 / 16 | 17 / 19 | 0 / 16 |
| heldout2 (25) | used for fixes | 9 / 13 | 2 / 12 | 13 / 13 | 0 / 12 |
| heldout3 (38) | used for fixes | 14 / 18 | 0 / 20 | 17 / 18 | 0 / 20 |
| **heldout4 (44)** | **first run is the only unbiased figure** | **14 / 22** | **1 / 22** | 19 / 22 | 0 / 22 |

How to read this: the **"first run" columns are the honest estimate** of how the engine behaves
on messages it has not been tuned for, and they are modest (58–78 % of suspicious messages caught, and 0 to 2 false
alarms among the 12–22 legitimate messages in each set; note the earlier sets' first runs were made on
earlier versions of the engine). The "current" columns are what you get
after fixing the weaknesses those runs exposed; they are **optimistic**, because the same
messages guided the fixes. All sets are small, synthetic and written by one author who knew what
the engine looks for. **None of this is production accuracy.**

### Real-world mail written by other people

Run over 12,271 real phishing/spam/fraud emails from the public Phishing Pot collection (not
included in this project; CC BY-NC 4.0):

| | Medium or High (≥ 40) | Any signal (≥ 15) | "No strong signals" |
|---|---|---|---|
| First run (**the unbiased figure**) | 41.1 % | 68.3 % | 31.7 % |
| Final engine (development figure) | 45.8 % | 72.1 % | 27.9 % |

**This is the number to believe, not the synthetic one.** On real mail MailScope flags fewer than
half of the messages at Medium or above, and roughly three in ten get no signal at all. The
collection has no legitimate mail, so it cannot show false alarms. What is missed is largely
commercial spam with no identity deception, lures for brands outside the table, non-English mail
(58 % of the collection; wording rules are English-only, and every such result now says so), and
clean-looking messages. Details in `evaluation/EVALUATION.md`.

### Remaining failure modes (known, not hidden)

- **Hijacked genuine mailbox, clean message** (`heldout/h13`, `heldout3/p15`, `heldout4/p19`): a
  one-line note with a link from a real account has no deceptive structure. Only a threat feed or
  link reputation could help.
- **Wrong-number / rapport openers** (`heldout4/p18`): no link, no request, nothing to detect.
- **Polite cold marketing** (`heldout/h18`): not deceptive enough to call spam without a label rule
  the project owner would have to choose.
- **Throwaway-domain invoice whose only content is a PDF link** (`heldout4/p09`): scores 19 ("Low").
- **Image-only or QR-code messages**: the content cannot be read. They are reported as unknown;
  one test message was still caught only because its sender name imitated Microsoft.
- **Brands not in the built-in table** are not recognised as impersonation targets (the table has
  61 well-known brands; add more in `mailscope/domains.py`).
- **False alarms to expect in real life**: genuine bulk marketing with "limited-time offer" and
  capitals scores "Low" (15–39); a web host's mailbox-quota notice for a hosted domain can look
  like a mailbox-admin lure (Medium); a genuine supplier's "our bank details changed" notice that
  does not point to its own site is rated Medium on purpose, because confirming such changes by
  phone is the standard control even when the sender is genuine.

## Project layout

```
app.py                       Streamlit interface
mailscope/
  email_analysis.py          parse .eml (MIME, headers, links, attachments); never executes anything
  sender_origin.py           sender identity checks (display name vs domain, lookalikes, Reply-To)
  domains.py                 brand table, lookalike/homograph logic, registrable-domain helper
  link_analysis.py           link structure checks (strings only, never visited)
  attachment_analysis.py     static attachment checks (names, magic bytes, archives, Office, PDF)
  content_analysis.py        message-intent wording families (evidence of intent, never decisive)
  authentication_checks.py   recorded claims (no credit) and optional real DKIM verification
  reputation_checks.py       optional offline feed and opt-in URLhaus
  risk_assessment.py         combines all signals into ONE verdict + indicator + unknowns + actions
  report_tools.py            HTML / JSON / text reports (links defanged)
  doctor.py                  self-check: python -m mailscope.doctor
start_mailscope.bat / .sh    one-step launchers (create the private environment, install, start)
.streamlit/config.toml       keeps the page local to your computer
tests/                       85 tests (unit, regression named after real weaknesses, evaluation guards)
evaluation/                  labelled sets (dev, heldout…heldout4), runners, results, protocol
samples/                     six synthetic messages for the app dropdown
docs/AUDIT.md                why the earlier application fell short
docs/HOW_IT_WORKS.md         step-by-step explanation for a beginner
```
