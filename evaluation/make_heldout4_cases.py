"""HELD-OUT SET 4 (the only set untouched by development as of the third improvement round).

Written AFTER the round-3 engine changes and BEFORE the engine was run on it. Rules for this set:
  * no engine, rule, weight or label change may be made because of how this set scores;
  * if that ever happens, this set becomes a development set and a new held-out set must be written.

It deliberately includes things the engine cannot do (image-only/QR phishing, a hijacked-account
message with no tell-tale wording, a wrong-number lure) so the report shows real misses.

Honest limits: synthetic messages written by one author (an AI assistant working with the project
owner); 44 messages; the author knew the kinds of signals the engine uses. This estimates
nothing about real-world accuracy and says nothing about bulk mail the author did not think of.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from emlbuilder import mk, write_cases

P, S, L = "phishing", "scam_spam", "legit"
c = []
ZIPISH = b"PK\x03\x04" + b"\x00" * 64
PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"

# ======================================================================= suspicious
c.append(("p01_dropbox_lookalike", P, "Fake Dropbox share on a brand-token domain",
    mk("Dropbox <share@dropbox-secure-files.org>", "Marta Lopez shared 'Q3 contracts' with you",
       "Marta Lopez shared a folder with you. View it: https://dropbox-secure-files.org/s/q3contracts",
       html='<p>Marta Lopez shared a folder with you.</p><p><a href="https://dropbox-secure-files.org/s/q3contracts">View folder</a></p>')))
c.append(("p02_netflix_typosquat", P, "Billing-failure lure from a one-letter typo of Netflix",
    mk("Netflix Billing <billing@netfliix.com>", "Payment declined - update your billing information",
       "We could not process your last payment. Update your payment method within 24 hours to avoid losing access: https://netfliix.com/billing",
       html='<p>We could not process your payment.</p><p><a href="https://netfliix.com/billing">Update payment method</a></p>')))
c.append(("p03_apple_id_locked_ip", P, "Apple ID lock lure with a raw-IP link",
    mk("Apple Support <support@appleid-notice.com>", "Your Apple ID has been locked",
       "For your security your Apple ID has been locked. Verify your identity to unlock it: http://203.0.113.45/appleid/unlock")))
c.append(("p04_linkedin_lookalike", P, "Fake LinkedIn notification",
    mk("LinkedIn <notifications@linkedin-mail-center.co>", "Your profile appeared in 9 searches this week",
       "See who is looking at your profile. Sign in to view: https://linkedin-mail-center.co/login",
       html='<p>See who is looking at your profile. <a href="https://linkedin-mail-center.co/login">Sign in to view</a></p>')))
c.append(("p05_zip_password_in_body", P, "Encrypted archive with the password supplied in the message body",
    mk("Operations <ops@trans-freight-co.biz>", "Shipping documents",
       "Documents for your shipment are in the attached archive. Password: 4471. Please open today.",
       attachments=[("Shipping_Docs.zip", "application/zip", ZIPISH)])))
c.append(("p06_ceo_reply_to_other_corp", P, "Executive name with reply-to pointing to an unrelated corporate-looking domain",
    mk("Michael Torres <michael.torres@brightpath-solutions.com>", "Urgent - need your help today",
       "Are you available? I need you to process an urgent payment to a new supplier before 3pm. I am in meetings so reply here rather than calling. Keep this confidential.",
       reply_to="m.torres.office@ceo-desk.net")))
c.append(("p07_direct_deposit_change", P, "Fake employee asking HR to change direct deposit",
    mk("Jessica Wu <jessica.wu.acme@gmail.com>", "Update to my direct deposit",
       "Hi HR, I changed banks and need to update my direct deposit details before the next payroll. Please change my account information. My new account number is 004418229. Thanks!")))
c.append(("p08_prize_iphone", S, "Fake loyalty-prize message",
    mk("Amazon Rewards <winner@amzn-prizes-center.top>", "Congratulations! You have been selected to win an iPhone",
       "Dear customer, you have been selected as the winner of our loyalty prize. Claim your reward within 24 hours by paying the small shipping fee: https://amzn-prizes-center.top/claim",
       html='<p>Dear customer, you have been selected as a <b>winner</b>. <a href="https://amzn-prizes-center.top/claim">Claim your reward</a> after the shipping fee.</p>')))
c.append(("p09_pdf_link_invoice", P, "Invoice PDF whose only content is a link to a throwaway domain",
    mk("Billing <billing@acct-docs-portal.xyz>", "Invoice available",
       "Your invoice is attached. Open the PDF and click the button to view payment options.",
       attachments=[("Invoice_1182.pdf", "application/pdf",
                     b"%PDF-1.4\n1 0 obj<</Type/Annot/Subtype/Link/A<</S/URI/URI(https://acct-docs-portal.xyz/pay/1182)>>>>endobj\ntrailer<<>>\n%%EOF")])))
c.append(("p10_qr_only_microsoft", P, "Image-only message (QR phishing); body text is empty. Expected miss: content cannot be read",
    mk("Microsoft Security <security@ms-account-verify.com>", "Multi-factor authentication update required",
       " ",
       html='<img src="cid:qr1" alt="">')))
c.append(("p11_sextortion_password", P, "Sextortion variant that quotes a password",
    mk("Unknown <v4rk1@protonmail.com>", "Your account is compromised",
       "I have your password and I recorded you through your camera. Transfer 0.05 BTC to my wallet address bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh within 48 hours or I will send the video to everyone in your contacts.")))
c.append(("p12_geeksquad_callback", P, "Fake subscription charge that tells you to phone",
    mk("Geek Squad <billing@gs-subscriptions.info>", "Your annual protection plan has been charged $399.99",
       "Your Geek Squad subscription renewed and $399.99 was charged to your card. If you did not authorize this charge, call 1-855-555-0188 immediately to cancel and get a refund.")))
c.append(("p13_chase_lookalike", P, "Bank alert on a lookalike domain",
    mk("Chase Alerts <alerts@chase-secure-alerts.com>", "Unusual activity on your Chase account",
       "We noticed unusual activity. Confirm your identity to restore access: https://chase-secure-alerts.com/verify",
       html='<p>We noticed unusual activity.</p><p><a href="https://chase-secure-alerts.com/verify">Confirm your identity</a></p>')))
c.append(("p14_zelle_accept", P, "Fake Zelle payment-received lure",
    mk("Zelle Payments <noreply@zelle-pay-accept.net>", "You received $450.00 - accept now",
       "A payment of $450.00 is waiting for you. Sign in with your bank credentials to accept it within 24 hours: https://zelle-pay-accept.net/accept",
       html='<p>A payment of $450.00 is waiting. <a href="https://zelle-pay-accept.net/accept">Accept payment</a></p>')))
c.append(("p15_html_voicemail_redirect", P, "Voicemail lure with an HTML attachment that runs a redirect script",
    mk("Voicemail <vm@voice-notify.cc>", "New voicemail (0:32)",
       "You have a new voicemail. Open the attachment to listen.",
       attachments=[("VM_0032.html", "text/html",
                     b"<html><body><script>window.location='https://voice-notify.cc/login';</script></body></html>")])))
c.append(("p16_loan_spam", S, "Loan spam",
    mk("Fast Cash <offers@quickloan-now.shop>", "Pre-approved: $50,000 loan, no credit check",
       "You are pre-approved for a $50,000 loan. No credit check, 100% guaranteed approval, lowest rates. Limited-time offer, apply now!",
       html='<p>You are <b>pre-approved</b>. 100% guaranteed approval, no credit check. <a href="https://quickloan-now.shop/apply">Apply now</a></p>')))
c.append(("p17_domain_renewal_scam", S, "Fake domain-registry renewal notice",
    mk("Domain Registry <notice@domain-registry-renewal.net>", "Domain Service Notice: your domain listing expires",
       "This is not a bill. Your domain listing will expire. To keep your search listing you must pay the renewal fee of $289 within 5 days. Pay at https://domain-registry-renewal.net/pay")))
c.append(("p18_wrong_number_lure", P, "Hard: wrong-number conversation starter with no link or request (expected miss)",
    mk("Laura Kim <laura.kim.8821@gmail.com>", "Hi",
       "Hi, is this Daniel? We met at the conference last month. How have you been?")))
c.append(("p19_hijacked_vendor_thread", P, "Hard: reply inside an existing thread from a hijacked real mailbox, one link (expected miss)",
    mk("Priya Raman <priya.raman@dalton-partners.com>", "Re: contract draft",
       "Thanks for the update. The revised version is here: https://dalton-contract-share.com/files/draft_v3",
       headers={"In-Reply-To": "<prev@dalton-partners.com>"})))
c.append(("p20_dating_spam", S, "Dating spam with abused-TLD link",
    mk("Anna <anna.s@meet-local-singles.top>", "I want to meet you tonight",
       "Hi handsome, I am nearby and lonely. See my private photos here: https://meet-local-singles.top/anna 100% free!!!")))
c.append(("p21_dhl_shortener_payment", P, "Parcel fee via shortener from a free mailbox",
    mk("DHL Express <dhl.express.parcel@gmail.com>", "Your package is on hold - customs fee",
       "Your parcel is held at customs. Pay the $2.99 fee to release it: https://bit.ly/3xParcelFee")))
c.append(("p22_voucher_credentials_form", P, "Gift voucher lure with an inline sign-in form",
    mk("Rewards <rewards@bonus-voucher-club.com>", "Claim your $100 voucher",
       "Enter your email and password below to claim your voucher.",
       html='<form action="https://bonus-voucher-club.com/collect" method="post"><input name="email"><input type="password" name="pw"><button>Claim</button></form>')))

# ======================================================================= legitimate
c.append(("n01_microsoft_real_signin", L, "Genuine Microsoft unusual sign-in alert",
    mk("Microsoft account team <account-security-noreply@accountprotection.microsoft.com>", "Microsoft account security alert",
       "Unusual sign-in activity on your Microsoft account. If this wasn't you, secure your account: https://account.live.com/activity",
       html='<p>Unusual sign-in activity. <a href="https://account.live.com/activity">Review recent activity</a></p>')))
c.append(("n02_paypal_receipt", L, "Genuine PayPal receipt",
    mk("PayPal <service@paypal.com>", "Receipt for your payment to Green Valley Books",
       "You sent a payment of $23.40 USD to Green Valley Books. View details: https://www.paypal.com/activity/payment/5RX",
       html='<p>You sent $23.40 USD to Green Valley Books. <a href="https://www.paypal.com/activity/payment/5RX">View details</a></p>')))
c.append(("n03_amazon_shipment", L, "Genuine Amazon shipping notice",
    mk("Amazon.com <shipment-tracking@amazon.com>", "Your package has shipped",
       "Your package will arrive Thursday. Track your package: https://www.amazon.com/progress-tracker/package/123",
       html='<p>Your package will arrive Thursday. <a href="https://www.amazon.com/progress-tracker/package/123">Track your package</a></p>')))
c.append(("n04_linkedin_real", L, "Genuine LinkedIn digest with tracking links on linkedin.com",
    mk("LinkedIn <messages-noreply@linkedin.com>", "Ravi Menon sent you a message",
       "Ravi Menon: Are you free for a quick chat next week? View message: https://www.linkedin.com/comm/messaging/thread/123?trk=email",
       html='<p>Ravi Menon sent you a message. <a href="https://www.linkedin.com/comm/messaging/thread/123?trk=email">View message</a></p>')))
c.append(("n05_zoom_invite", L, "Genuine Zoom meeting invitation",
    mk("Zoom <no-reply@zoom.us>", "Invitation: Weekly standup",
       "You are invited to a Zoom meeting. Join: https://us02web.zoom.us/j/81234567890",
       html='<p>You are invited to a Zoom meeting. <a href="https://us02web.zoom.us/j/81234567890">Join</a></p>')))
c.append(("n06_dropbox_share_real", L, "Genuine Dropbox share",
    mk("Dropbox <no-reply@dropbox.com>", "Marta shared 'Q3 contracts' with you",
       "Marta shared a folder with you. View folder: https://www.dropbox.com/scl/fo/abc/xyz",
       html='<p>Marta shared a folder with you. <a href="https://www.dropbox.com/scl/fo/abc/xyz">View folder</a></p>')))
c.append(("n07_internal_invoice_approval", L, "Internal colleague asking for invoice approval, PDF attached, mentions payment",
    mk("Greg Hall <greg.hall@acmecorp.com>", "Invoice 4471 for approval",
       "Hi, invoice 4471 from our regular supplier is attached for your approval. Payment is due on the 30th. Thanks.",
       to="finance@acmecorp.com",
       attachments=[("Invoice_4471.pdf", "application/pdf", PDF)])))
c.append(("n08_wellsfargo_statement", L, "Bank statement-ready notice with attached PDF-free body",
    mk("Wells Fargo <alerts@notify.wellsfargo.com>", "Your statement is ready",
       "Your statement is ready to view. Sign in at https://www.wellsfargo.com to see it.",
       html='<p>Your statement is ready. <a href="https://www.wellsfargo.com">Sign in to view</a></p>')))
c.append(("n09_google_groups_digest", L, "Mailing-list digest with a different Reply-To list address",
    mk("Garden Club <gardenclub@googlegroups.com>", "[gardenclub] Weekly digest",
       "Seeds swap on Saturday at the community hall. Reply to the list to RSVP.",
       reply_to="gardenclub@googlegroups.com",
       headers={"List-Id": "<gardenclub.googlegroups.com>", "List-Unsubscribe": "<mailto:gardenclub+unsubscribe@googlegroups.com>"})))
c.append(("n10_sendgrid_brand_news", L, "Brand newsletter sent through SendGrid",
    mk("Atlas Outdoor <news@atlasoutdoor.com>", "Spring trail guide is here",
       "Our spring trail guide is out. Read it: https://u123.ct.sendgrid.net/ls/click?upn=abc",
       html='<p>Our spring trail guide is out. <a href="https://u123.ct.sendgrid.net/ls/click?upn=abc">Read it</a></p><p><a href="https://u123.ct.sendgrid.net/unsub">Unsubscribe</a></p>',
       headers={"List-Unsubscribe": "<https://u123.ct.sendgrid.net/unsub>"})))
c.append(("n11_adobe_sign_real", L, "Genuine Adobe Acrobat Sign request",
    mk("Adobe Acrobat Sign <adobesign@adobesign.com>", "Please sign: Vendor Agreement",
       "Jonah Reid requested your signature on Vendor Agreement. Review and sign: https://secure.na1.adobesign.com/public/esignWidget?wid=1",
       html='<p>Jonah Reid requested your signature. <a href="https://secure.na1.adobesign.com/public/esignWidget?wid=1">Review and sign</a></p>')))
c.append(("n12_ups_update", L, "Genuine UPS delivery update",
    mk("UPS <pkginfo@ups.com>", "UPS Update: Package Scheduled for Delivery Tomorrow",
       "Your package is scheduled for delivery tomorrow. Track: https://www.ups.com/track?loc=en_US&tracknum=1Z999",
       html='<p>Your package is scheduled for delivery. <a href="https://www.ups.com/track?loc=en_US&tracknum=1Z999">Track</a></p>')))
c.append(("n13_clinic_portal", L, "Clinic appointment reminder with identity-verification wording on its own domain",
    mk("Riverside Clinic <noreply@riversideclinic.org>", "Appointment reminder for Tuesday 9:30",
       "This is a reminder of your appointment on Tuesday at 9:30. To check in online, please verify your identity at https://portal.riversideclinic.org/checkin. If you can't attend, call us on 020 7946 0321.",
       html='<p>Reminder of your appointment on Tuesday at 9:30. <a href="https://portal.riversideclinic.org/checkin">Verify your identity and check in</a>.</p>')))
c.append(("n14_portuguese_bank", L, "Portuguese-language bank notice, own-domain link",
    mk("Banco Meridional <avisos@bancomeridional.pt>", "Extrato mensal disponível",
       "O seu extrato mensal está disponível. Consulte em https://www.bancomeridional.pt/extratos. Nunca lhe pediremos a sua palavra-passe por email.",
       html='<p>O seu extrato mensal está disponível. <a href="https://www.bancomeridional.pt/extratos">Consultar</a></p>')))
c.append(("n15_loan_servicer", L, "Student-loan servicer payment reminder, own domain",
    mk("Northbridge Loan Servicing <notices@northbridgeloans.com>", "Your payment of $142.18 is due on the 15th",
       "Your monthly payment of $142.18 is due on the 15th. Pay or review your account at https://www.northbridgeloans.com/account.",
       html='<p>Your monthly payment of $142.18 is due on the 15th. <a href="https://www.northbridgeloans.com/account">Pay or review your account</a></p>')))
c.append(("n16_kraken_withdrawal", L, "Crypto exchange withdrawal confirmation with a 'did not request' warning",
    mk("Kraken <no-reply@kraken.com>", "Withdrawal confirmation",
       "You requested a withdrawal of 0.02 BTC. If you did not request this, contact support immediately and secure your account: https://support.kraken.com/hc/en-us",
       html='<p>You requested a withdrawal of 0.02 BTC. If you did not request this, <a href="https://support.kraken.com/hc/en-us">contact support</a>.</p>')))
c.append(("n17_boss_gmail_availability", L, "Manager on a personal gmail account asking about a call (hard negative)",
    mk("Helen Ortiz <helen.ortiz.work@gmail.com>", "Quick call?",
       "Are you available for a call at 3 today to go over the Q4 plan? Let me know.")))
c.append(("n18_charity_receipt", L, "Charity donation receipt",
    mk("Hope Foundation <giving@hopefoundation.org>", "Thank you for your gift of $50",
       "Thank you for your gift of $50. Your tax receipt is available at https://www.hopefoundation.org/receipts/9921.",
       html='<p>Thank you for your gift. <a href="https://www.hopefoundation.org/receipts/9921">Tax receipt</a></p>')))
c.append(("n19_retail_sale_caps", L, "Big retailer sale email with capitals and exclamation marks",
    mk("Best Buy <BestBuyInfo@emailinfo.bestbuy.com>", "SALE ENDS TONIGHT!!! SAVE BIG ON TVS",
       "SALE ENDS TONIGHT! SAVE UP TO 40% ON TVS! SHOP NOW! LIMITED-TIME OFFER ON SELECT MODELS! DON'T MISS OUT! https://www.bestbuy.com/tvs Unsubscribe: https://www.bestbuy.com/unsub",
       html='<p><b>SALE ENDS TONIGHT!</b> Limited-time offer. <a href="https://www.bestbuy.com/tvs">Shop now</a>!!!</p><p><a href="https://www.bestbuy.com/unsub">Unsubscribe</a></p>',
       headers={"List-Unsubscribe": "<https://www.bestbuy.com/unsub>"})))
c.append(("n20_friend_forward_news", L, "Friend sharing a news article link",
    mk("Sam Okafor <sam.okafor@outlook.com>", "Thought you'd like this",
       "Saw this and thought of you: https://www.bbc.com/news/technology-1234567. Coffee next week?")))
c.append(("n21_supplier_first_remittance", L, "Supplier with a new customer sending remittance info for a first payment (ambiguous: not a change request)",
    mk("Accounts <accounts@tidewater-packaging.com>", "Welcome - how to pay your first invoice",
       "Welcome as a customer. Our remittance details for invoice TW-1001 are on the invoice itself (attached). Please let us know if anything is unclear.",
       attachments=[("TW-1001.pdf", "application/pdf", PDF)])))
c.append(("n22_idn_japanese_shop", L, "Order confirmation from an internationalised .jp domain",
    mk("カフェ山田 <info@カフェ山田.jp>", "ご注文ありがとうございます",
       "ご注文ありがとうございました。詳細は https://カフェ山田.jp/order/551 をご覧ください。")))

if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "heldout4")
    write_cases(out, c)
    print(f"wrote {len(c)} cases to {out}")
