# How MailScope works, step by step

You do not need to program to follow this. Read it once, then open the files named in each step.

## The big idea

A suspicious email is a **bundle of clues**. No single clue decides anything: urgent wording is
common in real bank mail, and a new sender is not automatically a crook. What is suspicious is
*deception plus a request*: a message that **fakes who it is from or where a link goes**, and then
**asks you to log in, pay, or open a file**. MailScope collects clues, shows each one with its
evidence, combines them in one place, and tells you what it could *not* check.

## What happens when you upload a file

### 1. Reading the file safely (`email_analysis.py`)
An `.eml` file is just text: headers (From, To, Subject...) and a body, sometimes with attachments
inside as encoded text. MailScope reads that text with Python's standard `email` library. It
pulls out the sender, Reply-To, links (from the visible text, from HTML, from forms, from inside
PDFs), and attachment names and bytes.
It never runs anything: attachments are not opened, HTML is turned into plain text and never
displayed, images are never fetched, links are never visited.

### 2. Who does the message say it is? (`sender_origin.py`, `domains.py`)
Checks, each producing a clue if it fails:
- **Display name vs real address.** `"PayPal" <help@random-site.top>`: the name is free text.
- **Lookalike domains.** `paypa1-secure.com`, `netfliix.com`, or Cyrillic letters that look Latin.
- **Reply-To trick.** Replies silently go to a free mailbox instead of the sender.
- **Free mailbox with an "official" name** ("Payroll Team" on gmail.com).

- **Disguised names** (`obfuscation.py`). Invisible characters or look-alike letters from another
  alphabet inside a word of the sender's name or the subject. Real senders have no reason to do that.

A note on "domain": MailScope reduces `drive.google.com.share-docs.top` to its *registrable domain*
(`share-docs.top`), because the part just before the ending is who actually owns the address.
Everything to the left is decoration the owner can write freely.

### 3. Where do the links really go? (`link_analysis.py`)
It compares what you *read* with where the link *goes* (`zoom.us` shown, `zoom-recordings-share.com`
opened), spots raw IP addresses, shorteners, hidden `user@` prefixes, a real brand name buried in
someone else's address, and forms in the email that ask for a password. Bulk-mail tracking domains
(Mailchimp, SendGrid) are recognised as normal wrappers so a newsletter is not punished for using
them, but their final destination is listed as unknown.

### 4. What is attached? (`attachment_analysis.py`)
Looks only at names and raw bytes: `.exe`/`.js`, `invoice.pdf.exe` (double extension), a file
whose bytes say "program" while its name says "PDF", macro-enabled Office files (`.docm`), disk
images, HTML attachments with a login form or script, password-protected archives where the
password is given in the email body, PDFs with active content.

### 5. What is the message trying to get you to do? (`content_analysis.py`)
Wording patterns are grouped by *intent*: verify/sign in, send a password, change bank details,
gift cards, "call this number", prizes and fees, blackmail, spam. A pattern alone is a **weak**
clue. It gains weight only when combined with deception, and it is **down-weighted** when every
link stays on the sender's own domain (a genuine password reset looks like that) or when the text
is a reassurance ("we will never ask for your password").

**Language limit.** These wording patterns are English-only. If the text clearly is not English,
MailScope says so under "What could not be verified" because wording then contributes nothing,
and a low score on such a message deserves extra caution. In real-world testing most of the
phishing it missed was in other languages.

### 6. What can be trusted about authentication? (`authentication_checks.py`)
Lines like `Authentication-Results: dkim=pass` inside a file are *text*; anyone can type them. They
are shown but earn **no credit**. The only real test is the optional DKIM check, which verifies
the cryptographic signature using the signer's public key from DNS. A valid signature only proves
that a domain signed those exact bytes; a criminal can sign mail from their own domain.

### 7. Optional threat intelligence (`reputation_checks.py`)
Off by default. A downloaded list of known-bad URLs can be compared locally; an online URLhaus
lookup is available if you add a key and tick the box. Not being on a list means "unknown".

### 8. One place that decides (`risk_assessment.py`)
Every clue is a `Signal` with a strength: weak 0.10, moderate 0.30, strong 0.60, combination 0.75.
First, **combination rules** add clues such as "deceptive identity or link **and** a request for
action". Then the clues are merged like independent pieces of evidence:

```
indicator = 100 x (1 - (1-w1) x (1-w2) x (1-w3) ...)
```

Two moderate clues give 100 x (1 - 0.7 x 0.7) = 51. Clues of the same kind count half each time
(1, 1/2, 1/4...), so ten near-identical hits do not look like ten independent ones. The same list
produces the **verdict**, so the number and the words cannot disagree.

**Why the number is not a probability:** the weights are my judgement, not measured from thousands
of real emails. The number says "how much suspicious evidence was found", nothing more.

The verdict also separates three kinds of problem: *phishing or fraud* (identity/credential/
payment/attachment evidence), *scam or spam* (prizes, get-rich, promotions), and *unverified or
inconsistent origin*.

### 9. Saying what is missing
`_unknowns` lists everything not checked (SPF/DMARC, redirects, domain age, images, QR codes,
compressed PDF content, optional checks that were off). If a stage crashes, the result becomes
"analysis incomplete" instead of looking safe.

### 10. Reports (`report_tools.py`)
HTML, JSON and text reports. Links are *defanged* (`hxxps://evil[.]test`) so they cannot be
clicked by accident.

## A worked example

`evaluation/heldout3/p08_gdrive_subdomain_trick.eml` claims to be "Google Drive" sharing a spreadsheet.

1. Sender: display name says Google Drive, domain is `share-docs.top`, so **brand mismatch (strong)**.
2. Links: `https://drive.google.com.share-docs.top/...` contains Google's real domain inside someone
   else's, so **brand imitation (strong)**.
3. Two weak hints: both the sender's and the link's domain end in `.top`, a heavily abused ending.
4. No wording clue fired (the text only says a spreadsheet was shared), so no "deception **plus**
   request" combination was added. The score comes from the two strong clues alone: 1 - (0.4 x 0.4)
   = 0.84, nudged up by the two weak hints to 86.
5. Result: **Likely phishing or fraud, 86/100 (High)**. Under "What could not be verified" it lists SPF/DMARC,
   the delivery path, domain age, threat feeds, and where the links lead. It also says
   "Do not click... open the real company's site by typing its address yourself."

Run it yourself: `python3 -m mailscope evaluation/heldout3/p08_gdrive_subdomain_trick.eml`

## How to know whether it is any good (`evaluation/`)

Tests on your own examples only prove you remembered your own examples. So:
- **Development sets** (`dev`, `heldout`, `heldout2`, `heldout3`) guided the rules. Once you fix a
  rule because a message failed, that message can no longer judge the result.
- **A set nobody has tuned against** (`heldout4`) was written *before* it was run; its **first
  run** is saved unedited as `results_heldout4_FIRST_RUN_unedited.txt`. Case files are
  fingerprinted (`heldout3.sha256`, `heldout4.sha256`) so you can see no message was edited or relabelled.
- **Real-world mail written by other people** (12,271 phishing-type emails from Phishing Pot) shows
  the detection rate on mail the author never saw. It contains no legitimate mail, so it says
  nothing about false alarms.
- **False alarms matter as much as misses.** Each set has genuine bank notices, shipping updates,
  newsletters, calendar invites, a legal notice, a Japanese shop and so on.

The honest conclusion is in the README: decent on obvious deception, weak on clean-looking
messages from hijacked accounts and on content it cannot read.

## Where to extend it
- Add brands: `BRANDS` in `domains.py` (name, labels, genuine domains).
- Add a wording family: `FAMILIES` in `content_analysis.py`, then a `Signal` in `analyze_content`.
- Add a test first (`tests/test_mailscope.py`, `Round3RegressionTests` shows the pattern), then
  re-run the sets and look at **both** misses and false alarms.
