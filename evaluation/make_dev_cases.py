"""DEVELOPMENT cases: the ones used while building and tuning the rules.

They are synthetic (hand-written by the developer) and are labelled by construction.
Results on this set say the rules do what they were written to do; they are NOT an
estimate of real-world accuracy. See evaluation/heldout for the separate set.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from emlbuilder import mk, write_cases

P, S, L = "phishing", "scam_spam", "legit"
cases = []

cases.append(("d01_paypal_homoglyph", P, "Cyrillic 'a' in paypal sender domain, login link to lookalike",
    mk("PayPal Security <service@pаypal.com>", "Action required: confirm your account",
       "Dear customer, we noticed unusual activity. Please verify your account within 24 hours or it will be suspended.\nhttps://paypa1-secure-login.com/verify",
       html='<p>Dear customer, we noticed unusual activity. <a href="https://paypa1-secure-login.com/verify">Verify your account</a> within 24 hours or it will be suspended.</p>')))

cases.append(("d02_microsoft_gmail_password", P, "Brand display name on gmail, password-expiry lure",
    mk("Microsoft 365 Support <ms.support.team@gmail.com>", "Your password expires today",
       "Your password will expire today. Sign in to keep your access: https://office-login.example-portal.xyz/auth",
       html='<p>Your password will expire today. <a href="https://office-login.example-portal.xyz/auth">Sign in to keep your access</a></p>')))

cases.append(("d03_text_href_mismatch", P, "Anchor text shows the bank but href goes elsewhere",
    mk("Chase Alerts <alerts@chasealerts-mail.net>", "Security alert on your account",
       "We detected unauthorized access. Please confirm your account details immediately.",
       html='<p>We detected unauthorized access. <a href="http://203.0.113.9/chase/login">www.chase.com/secure</a> to confirm your account details immediately.</p>')))

cases.append(("d04_ceo_giftcards", P, "Executive impersonation from free mail, gift cards",
    mk("Michael Torres <michael.torres.ceo@gmail.com>", "Quick favor",
       "Are you available? I am in a meeting and need you to purchase 5 gift cards for clients. Keep this confidential, I will reimburse you. Reply when ready.")))

cases.append(("d05_bank_change_replyto", P, "Vendor bank-detail change with diverted replies",
    mk("Accounts <accounts@brightsupply.com>", "Updated bank details for invoice 4471",
       "Please note our new bank account details for all future payments. Kindly process the wire transfer for the outstanding invoice to the new account. Please do not call, reply by email.",
       reply_to="accounts.brightsupply@outlook.com")))

cases.append(("d06_exe_invoice", P, "Executable disguised as invoice",
    mk("Billing <billing@fastfreight-co.com>", "Invoice attached", "Please see the attached invoice.",
       attachments=[("Invoice_2291.pdf.exe", "application/octet-stream", b"MZ\x90\x00" + b"\x00" * 200)])))

cases.append(("d07_html_attachment_form", P, "HTML attachment containing a password form",
    mk("Shared Files <noreply@docs-share.example.net>", "Voicemail received", "You have a new voicemail. Open the attachment to listen.",
       attachments=[("voicemail.html", "text/html", b"<html><form action='https://x.example.net/g'><input type='password'></form><script>eval(atob('AAAA'))</script></html>")])))

cases.append(("d08_lottery", S, "Advance-fee lottery",
    mk("Mrs Grace Williams <grace.williams.claims@yahoo.com>", "YOU HAVE WON $2,500,000.00",
       "Congratulations! You have won the international lottery. As the beneficiary of the unclaimed funds you must pay a small processing fee to release the funds. Reply with your full name.",
       reply_to="claims.dept2020@gmail.com")))

cases.append(("d09_pharma_spam", S, "Bulk pharma spam",
    mk("Health Deals <deals@cheap-meds-online.top>", "LOWEST PRICE!!! no prescription needed",
       "BUY NOW!!! Viagra Cialis lowest price, 100% guaranteed, limited time offer! Click here to order. Miracle weight loss pills too!!!")))

cases.append(("d10_newsletter_sendgrid", L, "Marketing newsletter via click-tracking domain",
    mk("Bluebird Books <news@bluebirdbooks.com>", "New arrivals this week",
       "Hi there, here are this week's new arrivals. Visit bluebirdbooks.com to browse. Unsubscribe any time.",
       html='<p>New arrivals! <a href="https://u1234.ct.sendgrid.net/ls/click?upn=abc">bluebirdbooks.com</a></p><p><a href="https://u1234.ct.sendgrid.net/unsub">Unsubscribe</a></p>',
       headers={"List-Unsubscribe": "<mailto:unsub@bluebirdbooks.com>"})))

cases.append(("d11_github_notification", L, "Developer notification, links on own domain",
    mk("GitHub <notifications@github.com>", "[repo] Pull request #12 merged",
       "Merged #12 into main. View it on GitHub: https://github.com/org/repo/pull/12",
       html='<p>Merged #12. <a href="https://github.com/org/repo/pull/12">View it on GitHub</a></p>')))

cases.append(("d12_real_password_reset", L, "Genuine-style password reset, all links on sender domain",
    mk("Acme Cloud <no-reply@acmecloud.io>", "Reset your Acme Cloud password",
       "You asked to reset your password. Use this link within 24 hours: https://app.acmecloud.io/reset?token=abc123. If you did not request this, ignore this message.",
       html='<p>You asked to reset your password. <a href="https://app.acmecloud.io/reset?token=abc123">Reset password</a>. If you did not request this, ignore this message.</p>')))

cases.append(("d13_idn_shop", L, "Legitimate internationalized (single-script) domain",
    mk("Bücher Müller <info@bücher-müller.de>", "Ihre Bestellung / Your order",
       "Thank you for your order. Details: https://www.bücher-müller.de/bestellung/812")))

cases.append(("d14_personal_gmail", L, "Ordinary personal message from free mail",
    mk("Sam Rivera <sam.rivera84@gmail.com>", "Dinner Saturday?", "Hey, are you free Saturday evening? Thinking of trying the new Thai place. Let me know!")))

cases.append(("d15_legal_notice_pdf", L, "Law-firm notice with benign PDF attachment",
    mk("Harlan & Pierce LLP <notices@harlanpierce.com>", "Notice of hearing date change",
       "Please find attached the notice regarding the new hearing date. Contact our office during business hours.",
       attachments=[("Notice.pdf", "application/pdf", b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF")])))

cases.append(("d16_mailing_list", L, "Mailing list post: Reply-To is the list address",
    mk("Dana Lee <dana@univ.example.edu>", "[cs-club] Meeting moved to Thursday",
       "Meeting moved to Thursday 5pm in room 204. See you there.",
       reply_to="cs-club@lists.univ.example.edu")))

if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "dev")
    write_cases(out, cases)
    print(f"wrote {len(cases)} dev cases to {out}")
