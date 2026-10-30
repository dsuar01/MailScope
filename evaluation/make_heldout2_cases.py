"""HELD-OUT SET 2. Written AFTER the fixes made following held-out set 1, and BEFORE the engine was
run on it. Includes hard negatives aimed at the newly added rules (reassurance wording, order-receipt
call-us text, free-mail small businesses) and hard positives with little structure.

Same honest limits as set 1: synthetic, one author, small (26 messages).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from emlbuilder import mk, write_cases

P, S, L = "phishing", "scam_spam", "legit"
c = []

# ---------------------------------------------------------------- legitimate (some hard)
c.append(("n01_small_biz_gmail_support", L, "Small business that really uses a gmail address with a 'Support' style name",
    mk("Lakeside Cafe Support <lakesidecafe.support@gmail.com>", "Re: your catering question",
       "Thanks for reaching out! We can do 40 guests on Saturday. Let us know the time and we will confirm the menu.")))
c.append(("n02_bank_security_reassurance", L, "Genuine bank mail that tells customers never to share passwords",
    mk("Wells Fargo <alerts@notify.wellsfargo.com>", "Security tips for your account",
       "Reminder: Wells Fargo will never ask you to share your password, PIN or one-time code by email, text or phone. Learn more at https://www.wellsfargo.com/security.",
       html='<p>Reminder: we will never ask you to share your password, PIN or one-time code by email. <a href="https://www.wellsfargo.com/security">Learn more</a>.</p>')))
c.append(("n03_store_receipt_call_us", L, "Genuine store receipt that says to call if you did not place the order",
    mk("Orders <orders@thekitchenstore.com>", "Your order receipt #55812",
       "Thank you for your order. Your card was charged $84.50. If you did not place this order, please call our customer service team at 800-555-0199 right away.")))
c.append(("n04_finance_newsletter_risk_free", L, "Finance newsletter that mentions the risk-free rate",
    mk("Market Weekly <editor@marketweekly.com>", "Why the risk-free rate matters",
       "This week we explain how the risk-free rate affects bond prices and equity valuations. Past performance is not a guarantee of future results.")))
c.append(("n05_hr_wfh_policy", L, "Company HR announcing a work-from-home policy",
    mk("HR Team <hr@acmecorp.com>", "Updated work from home policy",
       "Starting next month employees may work from home up to two days per week. See the intranet policy page https://intranet.acmecorp.com/wfh for details.")))
c.append(("n06_teams_notification", L, "Microsoft Teams notification on a Microsoft subdomain",
    mk("Microsoft Teams <noreply@teams.microsoft.com>", "You have a new message in Teams",
       "Jordan sent you a message. Open Teams: https://teams.microsoft.com/l/message/1",
       html='<p>Jordan sent you a message. <a href="https://teams.microsoft.com/l/message/1">Open Teams</a></p>')))
c.append(("n07_netflix_marketing_subdomain", L, "Brand marketing from a brand mailer subdomain",
    mk("Netflix <info@mailer.netflix.com>", "New this month on Netflix",
       "Here is what is new this month. Browse at https://www.netflix.com/browse.",
       html='<p>Here is what is new. <a href="https://www.netflix.com/browse">Browse</a></p>')))
c.append(("n08_support_reply_confirm_address", L, "Real support reply asking to confirm a shipping address",
    mk("Acme Support <support@acmeco.com>", "Re: order 1182",
       "Hi Sam, please confirm your shipping address by replying to this email. We ship Monday.")))
c.append(("n09_dropbox_reset", L, "Genuine Dropbox password reset",
    mk("Dropbox <no-reply@dropbox.com>", "Reset your Dropbox password",
       "Click the link to reset your password: https://www.dropbox.com/forgot_finish?t=abc. If you did not ask for this, ignore this email.",
       html='<p><a href="https://www.dropbox.com/forgot_finish?t=abc">Reset your password</a>. If you did not ask for this, ignore this email.</p>')))
c.append(("n10_forwarded_to_security", L, "Employee forwards a suspicious message to the security team (quoted phishing text)",
    mk("Riley Chen <riley.chen@acmecorp.com>", "FW: is this real?",
       "Hi security team, I got this and it looks odd, can you check?\n\n> Please verify your account within 24 hours or it will be suspended.\n> hxxp://paypa1-login[.]example/verify\n\nThanks, Riley")))
c.append(("n11_ride_receipt_pdf", L, "Ride-share receipt with PDF",
    mk("Uber Receipts <receipts@uber.com>", "Your Tuesday evening trip with Uber",
       "Thanks for riding. Your total was $18.40. Receipt attached.",
       attachments=[("receipt.pdf", "application/pdf", b"%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF")])))
c.append(("n12_munich_city", L, "German city email on an IDN domain",
    mk("Stadt München <info@münchen.de>", "Terminbestätigung", "Ihr Termin am Montag um 10 Uhr ist bestätigt. Details: https://www.münchen.de/termine/771")))

# ---------------------------------------------------------------- phishing
c.append(("p01_spoofed_ceo_replyto", P, "Own-company executive name, replies diverted to gmail, gift cards",
    mk("Dana Whitfield <dana.whitfield@acmecorp.com>", "Quick task", "Are you at your desk? I need you to buy Google Play gift cards for a client event. Keep this between us and reply with the codes.",
       reply_to="dana.whitfield.acme@gmail.com")))
c.append(("p02_sharepoint_subdomain_trick", P, "Brand-laden subdomain on unrelated domain",
    mk("SharePoint <no-reply@sharepoint-notify.com>", "A file was shared with you",
       "Open the file: https://sharepoint.com.docs-view.ru/f/771",
       html='<p>A file was shared with you. <a href="https://sharepoint.com.docs-view.ru/f/771">Open the file</a></p>')))
c.append(("p03_wells_ip_link", P, "Lookalike bank domain with raw IP link",
    mk("Wells Fargo Alerts <alerts@wellsfargo-secure.com>", "Your account is limited", "We limited your account. Confirm your identity: http://198.51.100.23/wf/login")))
c.append(("p04_pdf_javascript", P, "PDF with JavaScript, invoice lure",
    mk("Accounts <billing@vendor-pay.net>", "Invoice attached", "Please find the overdue invoice attached. Remit payment today.",
       attachments=[("INV-7731.pdf", "application/pdf", b"%PDF-1.4\n1 0 obj<</Type/Catalog/OpenAction<</S/JavaScript/JS(app.alert(1))>>>>endobj\n%%EOF")])))
c.append(("p05_docm_resume", P, "Macro-enabled 'resume' from a free mailbox",
    mk("Job Applicant <emma.hayes.cv@gmail.com>", "Application for the open position", "Hello, my resume is attached for your review.",
       attachments=[("Resume_Emma_Hayes.docm", "application/vnd.ms-word.document.macroEnabled.12", b"PK\x03\x04" + b"\x00" * 60)])))
c.append(("p06_punycode_link", P, "Punycode lookalike link (Cyrillic apple) in a generic message",
    mk("Account Security <security@acct-verify.com>", "Verify your account to avoid suspension",
       "Please verify your account within 24 hours: https://xn--80ak6aa92e.com/id",
       html='<p>Please verify your account within 24 hours: <a href="https://xn--80ak6aa92e.com/id">Verify now</a></p>')))
c.append(("p07_prof_giftcards", P, "Professor-style display name on gmail asking for gift cards",
    mk("Dr. Lena Park <lena.park.prof@gmail.com>", "Are you available?", "Are you available? I need Google Play gift cards for a student award. I cannot call now, reply here.")))
c.append(("p08_binance_tld_subdomain", P, "Brand as subdomain of an abused TLD domain",
    mk("Binance <support@binance.com.verify-wallet.top>", "Verify your wallet now",
       "Your wallet is suspended. Verify here: https://binance.com.verify-wallet.top/login",
       html='<p>Your wallet is suspended. <a href="https://binance.com.verify-wallet.top/login">Verify here</a></p>')))
c.append(("p09_sextortion_plain", P, "Hard: plaintext sextortion with no links, little structure",
    mk("Anonymous <b7x1k@proton.me>", "I know your password",
       "I hacked your webcam and recorded you. Send $1500 in bitcoin to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa within 48 hours or I will send the video to all your contacts.")))
c.append(("p10_quiet_bec", P, "Hard: low-keyword bank-change request from a lookalike partner domain",
    mk("Marcus Webb <marcus@brightsupply-ltd.com>", "Next month's transfer",
       "Hi, our accounting moved to another bank so please use the attached sheet for the account to pay from now on. Thanks, Marcus.")))
c.append(("p11_netflix_payment_failed", P, "Brand-token domain, payment-failed lure",
    mk("Netflix <billing@netflix-payments-update.com>", "Payment failed: update your payment method",
       "We could not process your payment. Update your payment method within 24 hours to avoid cancellation: https://netflix-payments-update.com/billing")))

# ---------------------------------------------------------------- spam / scam
c.append(("s01_widow_charity", S, "Charity-widow fund scam",
    mk("Mrs. Amina Yusuf <amina.yusuf.fund@gmail.com>", "Dear beloved friend",
       "I am a widow with a late husband's estate of 4.5 million dollars. As my beneficiary you will help distribute it to charity; a processing fee is required to release the funds. Reply privately.")))
c.append(("s02_pharma_shop", S, "Pharma spam",
    mk("Online Pharmacy <orders@med-direct.shop>", "No prescription needed - lowest price", "Viagra and Cialis at the lowest price, no prescription needed. 100% guaranteed delivery. Limited-time offer!")))

if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "heldout2")
    write_cases(out, c)
    print(f"wrote {len(c)} held-out-2 cases to {out}")
