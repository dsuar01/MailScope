"""HELD-OUT SET 3. Written BEFORE any engine change in the third improvement round and run on the
unchanged engine first (results_heldout3_BEFORE.txt), then run again after the round-3 fixes.

The round-3 fixes were derived ONLY from the remaining failures of sets 1 and 2 (extortion wording,
macro attachment + 'see attached', payment-detail-change phrasing). No fix was derived from a set-3
failure; set-3 misses are reported as remaining weaknesses. If that ever changes, set 3 must be
re-labelled as a development set.

Honest limits: synthetic messages written by one author (an AI assistant working with the project
owner), small (38 messages), and written with knowledge of the kinds of things the engine looks
for. Results here estimate nothing about real-world accuracy.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from emlbuilder import mk, write_cases

P, S, L = "phishing", "scam_spam", "legit"
c = []
ZIPISH = b"PK\x03\x04" + b"\x00" * 64

# ======================================================================= suspicious
c.append(("p01_zoom_recording_lookalike", P, "Fake 'missed meeting recording' with link text zoom.us but href on a lookalike",
    mk("Zoom Video <no-reply@zoom-recordings-share.com>", "Your meeting recording is ready to view",
       "Your cloud recording from Monday is ready. Sign in to view it: https://zoom.us/rec/share/a1b2c3",
       html='<p>Your cloud recording from Monday is ready.</p><p><a href="https://zoom-recordings-share.com/login?id=a1b2c3">https://zoom.us/rec/share/a1b2c3</a></p>')))
c.append(("p02_it_helpdesk_quota", P, "Mailbox-full lure from a lookalike of the company's own helpdesk domain",
    mk("IT Helpdesk <helpdesk@acmecorp-support.net>", "Action required: mailbox storage 98% full",
       "Your mailbox is almost full and incoming mail will be rejected. Verify your account to increase your quota: https://acmecorp-support.net/quota/verify",
       html='<p>Your mailbox is almost full and incoming mail will be rejected.</p><p><a href="https://acmecorp-support.net/quota/verify">Verify your account</a> within 24 hours.</p>')))
c.append(("p03_usps_missed_delivery", P, "Parcel lure from a free mailbox with a shortener link",
    mk("USPS Delivery <usps.tracking.desk@outlook.com>", "Delivery attempt failed - action required",
       "We could not deliver your parcel. Reschedule and pay the $1.95 redelivery fee: https://tinyurl.com/uspsredeliver24")))
c.append(("p04_iso_invoice", P, "Invoice lure carrying a disk-image attachment",
    mk("Accounts <billing@globex-invoices.xyz>", "Invoice 88213 overdue",
       "Please find the overdue invoice attached. Kindly remit payment today.",
       attachments=[("Invoice_88213.iso", "application/octet-stream", b"\x00" * 32768 + b"CD001" + b"\x00" * 64)])))
c.append(("p05_cfo_wire_gmail", P, "Executive impersonation from a free mailbox, wire request",
    mk("Sarah Klein (CFO) <sarah.klein.cfo@gmail.com>", "Quick favor",
       "Are you at your desk? I need you to handle a confidential wire transfer today. Please keep this between us and reply as soon as you see this.")))
c.append(("p06_vendor_bank_reply_to", P, "Bank-detail change with replies diverted to a free mailbox",
    mk("Northwind Billing <billing@northwind-traders.com>", "Updated bank details",
       "Please note our bank details have changed. Use the new account for all payments starting this week. Reply to this message with confirmation.",
       reply_to="northwind.billing.dept@gmail.com")))
c.append(("p07_coinbase_wallet", P, "Wallet verification lure, display text and href disagree",
    mk("Coinbase Support <support@coinbase-verify.help>", "Unusual sign-in detected - verify your wallet",
       "We detected a sign-in from a new device. Verify your wallet now to avoid suspension: https://www.coinbase.com/verify",
       html='<p>We detected a sign-in from a new device.</p><p><a href="https://coinbase-verify.help/wallet">https://www.coinbase.com/verify</a></p>')))
c.append(("p08_gdrive_subdomain_trick", P, "Google Drive share where the real registrable domain is share-docs.top",
    mk("Google Drive <drive-shares-noreply@share-docs.top>", "Priya Shah shared 'Salary Review 2024.xlsx' with you",
       "Priya Shah shared a spreadsheet with you. Open: https://drive.google.com.share-docs.top/file/d/1xYz/view",
       html='<p>Priya Shah shared a spreadsheet with you.</p><p><a href="https://drive.google.com.share-docs.top/file/d/1xYz/view">Open in Drive</a></p>')))
c.append(("p09_html_attachment_login", P, "Password-expiry lure with an HTML attachment containing a login form",
    mk("Payroll <payroll@hr-benefits-portal.org>", "Your password expires today",
       "Open the attached page to keep your password and access your pay slip.",
       attachments=[("PaySlip_Login.html", "text/html",
                     b'<html><body><form action="https://hr-benefits-portal.org/collect" method="post"><input name="u"><input type="password" name="p"><button>Sign in</button></form></body></html>')])))
c.append(("p10_irs_refund", P, "Tax refund lure from a lookalike government domain",
    mk("Internal Revenue Service <refunds@irs-refund-gov.com>", "You are eligible for a tax refund of $1,284.00",
       "After the last annual calculation we determined you are eligible for a refund. Claim it here: https://irs-refund-gov.com/claim",
       html='<p>You are eligible for a refund of $1,284.00.</p><p><a href="https://irs-refund-gov.com/claim">Claim your refund</a></p>')))
c.append(("p11_mystery_shopper_check", S, "Fake job: mystery shopper, send a cheque and keep part of it",
    mk("Recruitment Office <jobs.recruit.office@gmail.com>", "Paid mystery shopper position - $300 per assignment",
       "You have been selected as a mystery shopper. We will mail you a cheque for $2,450. Deposit it, keep $300 as your pay, and wire the rest to our evaluation partner. No experience needed.")))
c.append(("p12_advance_fee_barrister", S, "Classic advance-fee scam",
    mk("Barrister James Okoro <jokoro.chambers@yahoo.com>", "Business proposal - confidential",
       "Dear friend, I am a barrister and I have an unclaimed inheritance of 8.5 million USD left by a client who died without next of kin. I need a trusted foreign partner. You will receive 40 percent after you pay the release fee. Reply urgently.")))
c.append(("p13_crypto_giveaway", S, "Crypto giveaway scam",
    mk("BTC Giveaway <promo@btc-double-now.top>", "Double your bitcoin today - risk-free",
       "Our crypto giveaway doubles your bitcoin guaranteed returns in 24 hours. Send any amount to the address on our site and get twice back. Limited time offer.",
       html='<p>Our <b>crypto giveaway</b> doubles your bitcoin. Guaranteed returns. <a href="https://btc-double-now.top/start">Start now</a></p>')))
c.append(("p14_tech_support_scam", P, "Fake virus alert telling the reader to call a number",
    mk("Windows Security <alert@win-defender-support.info>", "Your PC is infected - call now",
       "Windows Defender detected 5 viruses on your computer. Your files will be deleted. Call certified support immediately at 1-888-555-0142 to remove the threat.")))
c.append(("p15_hijacked_account_link", P, "Hard: hijacked real mailbox, one-line message with a file link (expected miss)",
    mk("Daniel Brooks <daniel.brooks@brooks-architects.com>", "docs",
       "Hi, take a look at this when you get a chance https://storage-share-files.cc/d/84721")))
c.append(("p16_docusign_lookalike_button", P, "DocuSign lookalike with polished text and a button to the lookalike domain",
    mk("DocuSign <dse@docusign-secure.net>", "Completed: Please review and sign Agreement-2291",
       "Your document is ready for review and signature. REVIEW DOCUMENT: https://docusign-secure.net/sign/2291",
       html='<p>Your document is ready for review and signature.</p><p><a href="https://docusign-secure.net/sign/2291">REVIEW DOCUMENT</a></p>')))
c.append(("p17_pharma_spam", S, "Pharmacy spam",
    mk("Canadian Pharmacy <sales@cheap-meds-24.shop>", "No prescription needed - lowest price",
       "Order Viagra and Cialis online. 100% guaranteed delivery, no prescription, lowest price. Limited-time offer, order today!",
       html='<p>Order Viagra and Cialis online. <a href="https://cheap-meds-24.shop/order">Click here to order</a></p>')))
c.append(("p18_xlsm_invoice", P, "Plain invoice note with a macro-enabled workbook from an unknown vendor",
    mk("Accounts Receivable <ar@lumen-parts.co>", "Statement of account",
       "Please see attached statement of account for September.",
       attachments=[("Statement_Sep.xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", ZIPISH)])))

# ======================================================================= legitimate
c.append(("n01_slack_digest", L, "Slack notification digest",
    mk("Slack <feedback@slack.com>", "You have 3 unread messages in Acme Workspace",
       "Maya mentioned you in #design. Read it: https://acme.slack.com/archives/C0123/p1",
       html='<p>Maya mentioned you in #design. <a href="https://acme.slack.com/archives/C0123/p1">Read it</a></p>')))
c.append(("n02_airline_itinerary", L, "Airline itinerary from the airline's own mail subdomain",
    mk("Delta Air Lines <DeltaAirLines@t.delta.com>", "Your trip confirmation: JFK to LAX",
       "Thanks for booking. Your confirmation number is HJK29L. Manage your trip at https://www.delta.com/mytrips.",
       html='<p>Your confirmation number is HJK29L. <a href="https://www.delta.com/mytrips">Manage your trip</a></p>')))
c.append(("n03_bank_alert_never_ask", L, "Bank alert that says it will never ask for the full PIN",
    mk("Capital One <capitalone@email.capitalone.com>", "A new payment posted to your account",
       "A payment of $212.40 posted to your account ending 4417. We will never ask for your full PIN or password by email. View activity: https://www.capitalone.com/activity",
       html='<p>A payment of $212.40 posted. We will never ask for your password by email. <a href="https://www.capitalone.com/activity">View activity</a></p>')))
c.append(("n04_google_security_alert", L, "Genuine Google security alert (urgent wording, own-domain link)",
    mk("Google <no-reply@accounts.google.com>", "Security alert for your linked account",
       "A new sign-in on Windows. If this was you, no action is needed. If not, secure your account: https://myaccount.google.com/notifications",
       html='<p>A new sign-in on Windows. If this was not you, <a href="https://myaccount.google.com/notifications">review activity</a>.</p>')))
c.append(("n05_uber_receipt", L, "Ride receipt",
    mk("Uber Receipts <noreply@uber.com>", "Your Tuesday evening trip with Mehmet",
       "Total $18.20. Thanks for riding with Uber. View your receipt: https://www.uber.com/receipt/8812",
       html='<p>Total $18.20. <a href="https://www.uber.com/receipt/8812">View receipt</a></p>')))
c.append(("n06_university_password_expiry", L, "University IT password-expiry notice, own-domain link (hard negative)",
    mk("Northfield IT Service Desk <servicedesk@northfield.edu>", "Your NetID password expires in 3 days",
       "Your NetID password will expire in 3 days. To update it, sign in at https://netid.northfield.edu and follow the prompts. Questions? Visit the service desk.",
       html='<p>Your NetID password will expire in 3 days. <a href="https://netid.northfield.edu">Update your password</a>.</p>')))
c.append(("n07_colleague_pdf", L, "Colleague sending meeting notes as a PDF",
    mk("Rina Patel <rina.patel@acmecorp.com>", "Notes from Thursday",
       "Hi, notes from Thursday's sync are attached. Let me know if I missed anything.",
       attachments=[("Notes_Thursday.pdf", "application/pdf", b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF")])))
c.append(("n08_mailchimp_small_brand", L, "Small brand newsletter via Mailchimp tracking links",
    mk("Fern & Fig Plants <hello@fernandfig.com>", "New arrivals + 10% off this weekend",
       "Our newest plants are in. Shop: https://fernandfig.us4.list-manage.com/track/click?u=1&id=2",
       html='<p>Our newest plants are in. <a href="https://fernandfig.us4.list-manage.com/track/click?u=1&id=2">Shop now</a></p><p>You are receiving this because you subscribed. <a href="https://fernandfig.us4.list-manage.com/unsubscribe?u=1">Unsubscribe</a></p>',
       headers={"List-Unsubscribe": "<https://fernandfig.us4.list-manage.com/unsubscribe?u=1>"})))
c.append(("n09_substack", L, "Substack post",
    mk("The Weekly Read <theweeklyread@substack.com>", "Issue 41: what I read this month",
       "This month's reading list, with notes. Read online: https://theweeklyread.substack.com/p/issue-41",
       html='<p>This month\'s reading list. <a href="https://theweeklyread.substack.com/p/issue-41">Read online</a></p>')))
c.append(("n10_friend_gmail", L, "Short personal note from a friend on gmail",
    mk("Alex Moreno <alex.moreno84@gmail.com>", "Saturday?",
       "Hey, are we still on for the climbing gym on Saturday? I can drive if you want. Let me know!")))
c.append(("n11_docusign_genuine", L, "Genuine DocuSign envelope (sender and links on docusign.net)",
    mk("DocuSign System <dse@docusign.net>", "Please review and sign: Lease Renewal",
       "Taylor Nguyen sent you a document to review and sign. REVIEW DOCUMENT: https://na4.docusign.net/Signing/EmailStart.aspx?a=1",
       html='<p>Taylor Nguyen sent you a document to sign.</p><p><a href="https://na4.docusign.net/Signing/EmailStart.aspx?a=1">REVIEW DOCUMENT</a></p>')))
c.append(("n12_stripe_invoice", L, "Stripe invoice email",
    mk("Acme Studio via Stripe <invoice+statements@stripe.com>", "Your receipt from Acme Studio #1429-0031",
       "Amount paid: $45.00. View receipt: https://invoice.stripe.com/i/acct_1/test_abc",
       html='<p>Amount paid: $45.00. <a href="https://invoice.stripe.com/i/acct_1/test_abc">View receipt</a></p>')))
c.append(("n13_calendar_invite", L, "Calendar invitation from Google Calendar",
    mk("Google Calendar <calendar-notification@google.com>", "Invitation: Project kickoff @ Wed 10am",
       "You have been invited to Project kickoff. View all details: https://calendar.google.com/calendar/event?eid=abc",
       html='<p>You have been invited to Project kickoff. <a href="https://calendar.google.com/calendar/event?eid=abc">View details</a></p>')))
c.append(("n14_law_firm_notice", L, "Law-firm notice with a PDF, urgent legal wording",
    mk("Harlow & Pike LLP <notices@harlowpike.com>", "Notice of hearing - response required within 14 days",
       "Please find attached the notice of hearing in your matter. A response is required within 14 days. Contact our office on 020 7946 0958 with any questions.",
       attachments=[("Notice_of_Hearing.pdf", "application/pdf", b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF")])))
c.append(("n15_etsy_shipped", L, "Order shipped notice",
    mk("Etsy <transaction@etsy.com>", "Your order from PaperPine has shipped",
       "Good news: your order shipped. Track it: https://www.etsy.com/your/purchases/9912",
       html='<p>Your order shipped. <a href="https://www.etsy.com/your/purchases/9912">Track it</a></p>')))
c.append(("n16_retail_promo", L, "Big-brand marketing with 'limited-time offer' wording",
    mk("Nike <nike@official.nike.com>", "Limited-time offer: 30% off select styles",
       "Limited-time offer: 30% off select styles through Sunday. Shop now at https://www.nike.com/sale. Unsubscribe: https://www.nike.com/unsubscribe",
       html='<p>Limited-time offer: 30% off select styles. <a href="https://www.nike.com/sale">Shop now</a></p><p><a href="https://www.nike.com/unsubscribe">Unsubscribe</a></p>',
       headers={"List-Unsubscribe": "<https://www.nike.com/unsubscribe>"})))
c.append(("n17_german_shipping", L, "German-language shipping notice from a German retailer",
    mk("Otto Versand <service@otto.de>", "Ihre Bestellung wurde versendet",
       "Hallo, Ihre Bestellung wurde heute versendet. Sendungsverfolgung: https://www.otto.de/mein-konto/sendung/123",
       html='<p>Hallo, Ihre Bestellung wurde versendet. <a href="https://www.otto.de/mein-konto/sendung/123">Sendung verfolgen</a></p>')))
c.append(("n18_idn_shop_order", L, "Order confirmation from a legitimate internationalised domain",
    mk("Bücherstube <service@bücherstube.de>", "Ihre Bestellung 20931",
       "Vielen Dank für Ihre Bestellung. Details: https://bücherstube.de/konto/bestellung/20931")))
c.append(("n19_vendor_bank_notice_own_domain", L, "Genuine supplier telling customers about new bank details, pointing to its own portal (ambiguous; verification by phone is still good practice)",
    mk("Vendorco Accounts <accounts@vendorco.com>", "Notice: our bank details are changing on 1 December",
       "From 1 December our bank details will change. The new details are published in your account portal: https://portal.vendorco.com/billing. Please do not rely on emailed details; log in to the portal.",
       html='<p>From 1 December our bank details will change. See your portal: <a href="https://portal.vendorco.com/billing">portal.vendorco.com/billing</a>.</p>')))
c.append(("n20_spotify_confirm_email", L, "Confirm-email request from a service, own-domain link",
    mk("Spotify <no-reply@spotify.com>", "Confirm your email address",
       "Confirm your email address to finish setting up your account: https://www.spotify.com/confirm/abc123",
       html='<p>Confirm your email address to finish setting up your account.</p><p><a href="https://www.spotify.com/confirm/abc123">Confirm email</a></p>')))

if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "heldout3")
    write_cases(out, c)
    print(f"wrote {len(c)} cases to {out}")
