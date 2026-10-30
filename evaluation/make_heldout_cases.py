"""HELD-OUT cases. Written BEFORE the engine was run on them and labelled by the author
at writing time. They deliberately include hard positives (well-crafted attacks that
rule-based analysis is expected to miss) and hard negatives (legitimate mail that
looks risky).

Honest limits: the same person wrote the engine and these messages, so they are
not independent in the way a third-party corpus would be, and they are synthetic.
35 messages is far too few for precise accuracy estimates. Do not read results on
this set as production accuracy.
"""
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(__file__))
from emlbuilder import mk, write_cases

P, S, L = "phishing", "scam_spam", "legit"
c = []


def zipbytes(files, password_hint=False):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, d in files.items():
            z.writestr(n, d)
    return b.getvalue()


# ---------------------------------------------------------------- phishing
c.append(("h01_docusign_lookalike", P, "DocuSign lookalike domain, document-review lure",
    mk("DocuSign <dse@docusign-review.net>", "Completed: Please review and sign the agreement",
       "A document has been shared with you. Review the document: https://docusign-review.net/d/9921",
       html='<p>A document has been shared with you.</p><p><a href="https://docusign-review.net/d/9921">REVIEW DOCUMENT</a></p>')))
c.append(("h02_amazon_orders", P, "Brand token in domain, order problem lure",
    mk("Amazon Support <support@amazon-orders-help.com>", "Problem with your order #112-4455",
       "We were unable to process your payment. Please update your payment method to avoid cancellation: http://amazon-orders-help.com/billing")))
c.append(("h03_dhl_parcel_short", P, "Parcel fee via shortener from throwaway domain",
    mk("DHL Express <tracking@dhl-parcels-notice.top>", "Your parcel is on hold - fee required",
       "Your parcel could not be delivered. Pay the redelivery fee within 48 hours: https://bit.ly/3xYzAbC",
       html='<p>Your parcel could not be delivered. <a href="https://bit.ly/3xYzAbC">Pay the redelivery fee</a> within 48 hours.</p>')))
c.append(("h04_payroll_portal", P, "Payroll lure, no brand, unrelated portal domain",
    mk("HR Department <hr@northwind-payroll.com>", "Action required: update your direct deposit details",
       "Our payroll provider has changed. All employees must update their direct deposit information today at https://northwind-hrportal.com/login so your next salary is not delayed.",
       html='<p>Our payroll provider has changed. All employees must update their direct deposit information today: <a href="https://northwind-hrportal.com/login">HR portal</a></p>')))
c.append(("h05_onenote_invoice", P, "OneNote attachment lure",
    mk("Accounts Payable <accounts@sup-pliers.net>", "Overdue invoice 88231", "See the attached invoice and remit payment today.",
       attachments=[("Invoice-88231.one", "application/octet-stream", b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d" + b"\x00" * 64)])))
c.append(("h06_callback_scam", P, "Callback phishing: fake subscription charge",
    mk("Billing Dept <billing@services-notice.com>", "Receipt: your annual subscription renewal",
       "Thank you. Your subscription renewal of $499.99 was charged to your card today. If you did not authorize this charge, call our support team at 1-888-555-0142 to cancel and get a refund.")))
c.append(("h07_mailbox_quota_gsites", P, "Mailbox-quota lure pointing at free hosting",
    mk("IT Helpdesk <helpdesk@company-itdesk.example>", "Your mailbox is almost full",
       "Your mailbox has exceeded its storage limit. Verify your mailbox to avoid losing incoming messages: https://sites.google.com/view/mailbox-verify-9912",
       html='<p>Your mailbox has exceeded its storage limit. <a href="https://sites.google.com/view/mailbox-verify-9912">Verify your mailbox</a> to avoid losing incoming messages.</p>')))
c.append(("h08_zip_with_exe", P, "ZIP containing a script, password in body",
    mk("Logistics <ops@global-cargo.example>", "Shipping documents", "Documents attached. Password: 7731",
       attachments=[("docs.zip", "application/zip", zipbytes({"scan_0412.js": "var x=1;"}))])))
c.append(("h09_cfo_wire", P, "Executive impersonation, wire request, free mail",
    mk("Jonathan Pierce <j.pierce.cfo@outlook.com>", "Urgent wire today",
       "I need you to process a wire transfer to a new vendor today. Please keep this confidential and reply once it is done. I am in meetings all day and cannot take calls.")))
c.append(("h10_coinbase_subdomain", P, "Brand in subdomain of an unrelated domain",
    mk("Coinbase <no-reply@coinbase.account-center.live>", "Confirm your wallet withdrawal",
       "A withdrawal was requested. If this was not you, verify your account now: https://coinbase.account-center.live/secure",
       html='<p>A withdrawal was requested. If this was not you, <a href="https://coinbase.account-center.live/secure">verify your account</a> now.</p>')))
c.append(("h11_apple_id_locked", P, "Apple ID lookalike domain",
    mk("Apple ID <noreply@appleid-locked.com>", "Your Apple ID has been locked",
       "Your Apple ID was locked for security reasons. Unlock it here: https://appleid-locked.com/unlock",
       html='<p>Your Apple ID was locked for security reasons. <a href="https://appleid-locked.com/unlock">Unlock it here</a>.</p>')))
c.append(("h12_plaintext_reply_password", P, "No links, asks for password by reply (hard: little structure)",
    mk("Mail Administrator <mailadmin@webservices-center.org>", "Your email account will be closed",
       "Dear user, your email account will be closed within 24 hours due to inactivity. To retain it, reply with your password and username.")))
c.append(("h13_compromised_vendor_clean", P, "Hard: clean wording from real-looking vendor domain; only a file-share link (expected miss)",
    mk("Priya Nair <priya.nair@lakeshorepartners.com>", "Contract for review",
       "Hi, as discussed, the contract is available here: https://files.sharehub-docs.net/c/84f2a. Let me know if you have questions.",
       html='<p>Hi, as discussed, the contract is available <a href="https://files.sharehub-docs.net/c/84f2a">here</a>. Let me know if you have questions.</p>')))
c.append(("h14_qr_microsoft", P, "Image-only QR lure with brand display name on non-brand domain",
    mk("Microsoft Security <security@microsoft-notice.net>", "Re-authenticate your account", "Scan the attached code with your phone.",
       attachments=[("qr.png", "image/png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)])))

# ---------------------------------------------------------------- scam / spam
c.append(("h15_inheritance", S, "Advance-fee inheritance from barrister",
    mk("Barrister David Okoro <d.okoro.law@gmail.com>", "Next of kin - inheritance of $8.5 million",
       "I am a barrister and you have been identified as next of kin to a deceased client. The inheritance of 8.5 million dollars will be released after a small transfer fee. Reply urgently.")))
c.append(("h16_crypto_spam", S, "Investment spam with guaranteed returns",
    mk("Crypto Alpha <promo@alpha-signals.xyz>", "Double your bitcoin in 7 days",
       "Join our private group. Guaranteed returns, risk-free, double your bitcoin! Limited-time offer, only 20 spots left. Click here to claim.")))
c.append(("h17_fake_job", S, "Work-from-home fake job",
    mk("Careers Team <hiring.dept.hr@gmail.com>", "Earn $500 per day working from home",
       "No experience needed! Work from home and earn $500 per day. Reply with your phone number to start today.")))
c.append(("h18_seo_cold_spam", S, "Hard: polite cold SEO spam (expected miss)",
    mk("Kevin <kevin@rankboost-seo.com>", "Quick question about your website",
       "Hello, I looked at your website and I can help it get more visitors. We offer affordable SEO packages. Would you like a free report?")))
c.append(("h19_casino", S, "Casino promotion",
    mk("VIP Club <vip@luckyspins-promo.click>", "You are our VIP: 200 free spins",
       "Join our online casino today. 100% free spins, lowest deposit, limited time offer!!! CLICK HERE TO CLAIM!!!")))

# ---------------------------------------------------------------- legitimate
c.append(("l01_chase_alert_real", L, "Genuine bank-style alert, links on brand domain",
    mk("Chase <no-reply@alertsp.chase.com>", "Your Chase account: verify recent activity",
       "We want to confirm recent activity on your account. Review it by signing in at https://www.chase.com/login. We will never ask for your password by email.",
       html='<p>We want to confirm recent activity. <a href="https://www.chase.com/login">Sign in at chase.com</a>. We will never ask for your password by email.</p>')))
c.append(("l02_mailchimp_newsletter", L, "Newsletter via Mailchimp with account-preferences wording",
    mk("Riverside Cafe <hello@riversidecafe.com>", "October menu and events",
       "Fall menu is here! Update your account preferences or unsubscribe at any time.",
       html='<p>Fall menu is here!</p><p><a href="https://riversidecafe.us5.list-manage.com/profile?u=1">Update your account preferences</a> | <a href="https://riversidecafe.us5.list-manage.com/unsubscribe?u=1">Unsubscribe</a></p>')))
c.append(("l03_amazon_shipping", L, "Amazon shipping notice, brand domain",
    mk("Amazon.com <shipment-tracking@amazon.com>", "Your package has shipped",
       "Your order has shipped. Track it at https://www.amazon.com/progress-tracker/package/123.",
       html='<p>Your order has shipped. <a href="https://www.amazon.com/progress-tracker/package/123">Track package</a></p>')))
c.append(("l04_amazon_uk", L, "Amazon national domain",
    mk("Amazon <order-update@amazon.co.uk>", "Your order has been delivered",
       "Your parcel was delivered. View your order: https://www.amazon.co.uk/your-orders")))
c.append(("l05_recruiter_ats", L, "Recruiter email through an ATS: Reply-To on another domain",
    mk("Taylor Brooks <taylor@talentcorp.com>", "Interview invitation - Data Analyst",
       "Hi, we would love to schedule an interview. Please pick a time here: https://boards.greenhouse.io/talentcorp/schedule/77",
       reply_to="jobs+77@greenhouse-mail.io")))
c.append(("l06_apple_pie_bakery", L, "Ambiguous brand word in display name (not Apple Inc.)",
    mk("Apple Pie Bakery <hello@applepiebakery.com>", "Pie of the month", "This month's pie is cinnamon apple. Order by Friday: https://applepiebakery.com/order")))
c.append(("l07_university_password_expiry", L, "University IT notice, password expiring, own-domain links",
    mk("IT Services <itservices@fiu.edu>", "Your password expires in 14 days",
       "Your network password will expire in 14 days. Change it at https://pwreset.fiu.edu. If you need help, call the Help Desk.",
       html='<p>Your network password will expire in 14 days. <a href="https://pwreset.fiu.edu">Change it here</a>.</p>')))
c.append(("l08_vendor_invoice_pdf", L, "Genuine invoice with PDF and payment amount",
    mk("Billing <billing@lakeshorepartners.com>", "Invoice 2024-118 due Nov 15",
       "Attached is invoice 2024-118 for $1,200. Payment is due Nov 15. Thank you for your business.",
       attachments=[("Invoice-2024-118.pdf", "application/pdf", b"%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF")])))
c.append(("l09_small_biz_bitly", L, "Small business uses a shortened tracking link",
    mk("Jo's Pottery <jo@jospottery.com>", "Studio open house Saturday", "Come visit! RSVP: https://bit.ly/jos-open-house")))
c.append(("l10_google_docs_share", L, "Genuine Google Docs share notification",
    mk("Alex Kim (via Google Docs) <drive-shares-noreply@google.com>", "Alex Kim shared a document with you",
       "Alex Kim has shared a document with you. Open it: https://docs.google.com/document/d/1AbC/edit",
       html='<p>Alex Kim has shared a document with you.</p><p><a href="https://docs.google.com/document/d/1AbC/edit">Open</a></p>')))
c.append(("l11_event_ticket_html", L, "Event ticket as HTML attachment (static)",
    mk("Tickets <tickets@citytheatre.org>", "Your tickets for Friday", "Your tickets are attached.",
       attachments=[("tickets.html", "text/html", b"<html><body><h1>Admit two</h1><p>Row F seats 4-5</p></body></html>")])))
c.append(("l12_friend_zip_photos", L, "Friend sends zip of photos",
    mk("Maria Lopez <maria.lopez77@gmail.com>", "Photos from the trip", "Here are the photos from the weekend!",
       attachments=[("photos.zip", "application/zip", zipbytes({"IMG_001.jpg": "x", "IMG_002.jpg": "y"}))])))
c.append(("l13_saas_promo", L, "SaaS promotional email with limited-time offer",
    mk("Notion Labs Team <hello@mail.notionlabs.example>", "Limited-time offer: 30% off annual plans",
       "Upgrade this week and save. Limited-time offer ends Friday. Manage your subscription or unsubscribe: https://mail.notionlabs.example/prefs",
       html='<p>Upgrade this week and save. Limited-time offer ends Friday.</p><p><a href="https://mail.notionlabs.example/prefs">Manage subscription</a></p><img src="https://mail.notionlabs.example/px.gif">')))
c.append(("l14_japanese_shop", L, "Japanese single-script domain and text",
    mk("日本の本屋 <info@本屋.jp>", "ご注文ありがとうございます", "ご注文ありがとうございます。詳細: https://www.本屋.jp/order/55")))
c.append(("l15_payroll_reminder", L, "Genuine HR reminder mentioning direct deposit, own-domain links",
    mk("HR Team <hr@acmecorp.com>", "Reminder: benefits enrollment closes Friday",
       "To update your direct deposit information or benefits elections, log in to the HR portal at https://hr.acmecorp.com before Friday.",
       html='<p>To update your direct deposit information or benefits elections, log in to the <a href="https://hr.acmecorp.com">HR portal</a> before Friday.</p>')))
c.append(("l16_forwarding_list_digest", L, "Mailing-list digest with Return-Path and Reply-To on list host",
    mk("Chess Club <board@chessclub.example.org>", "Weekly digest", "Here is this week's digest. Tournament on the 14th. See the wiki for pairings: https://chessclub.example.org/wiki",
       reply_to="digest@lists.chessclub.example.org", headers={"Return-Path": "<bounce-77@lists.chessclub.example.org>"})))

if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "heldout")
    write_cases(out, c)
    print(f"wrote {len(c)} held-out cases to {out}")
