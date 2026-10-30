"""Unit and regression tests. Run:  python -m unittest discover -s tests -v

Regression tests are named after the real weakness they pin down (found during
held-out evaluation); the docstring says which one.
"""
import json
import os
import socket
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "evaluation"))

from emlbuilder import mk  # noqa: E402
from mailscope import analyze_bytes  # noqa: E402
from mailscope.domains import (brand_lookalike, idn_findings, is_ip, registrable_domain,  # noqa: E402
                               edit_distance)
from mailscope.email_analysis import parse_email  # noqa: E402
from mailscope.report_tools import defang, to_html, to_json, to_text  # noqa: E402
from mailscope.reputation_checks import check_reputation, load_feed  # noqa: E402
from mailscope.authentication_checks import verify_dkim, recorded_claims  # noqa: E402


def ids(a):
    return {s.id.split(":")[0] for s in a.signals}


class DomainTests(unittest.TestCase):
    def test_registrable(self):
        self.assertEqual(registrable_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable_domain("login.paypal.com"), "paypal.com")

    def test_genuine_brand_domains_never_flagged(self):
        for h in ["www.paypal.com", "login.microsoftonline.com", "amazon.co.uk", "amazon.de", "outlook.fr", "docs.google.com"]:
            self.assertIsNone(brand_lookalike(h), h)

    def test_lookalikes_flagged(self):
        for h in ["paypa1.com", "paypal.com.evil.tld", "secure-paypal-login.com", "microsoft.support",
                  "xn--pypal-4ve.com", "amazon.tk"]:
            self.assertIsNotNone(brand_lookalike(h), h)

    def test_unfamiliar_domain_is_not_a_lookalike(self):
        for h in ["example.com", "bluebirdbooks.com", "acmecloud.io", "northwind-hrportal.com"]:
            self.assertIsNone(brand_lookalike(h), h)

    def test_idn_single_script_not_suspicious(self):
        self.assertEqual(idn_findings("bücher-müller.de"), [])
        self.assertEqual(idn_findings("本屋.jp"), [])
        self.assertTrue(idn_findings("xn--pypal-4ve.com"))  # Cyrillic a inside Latin

    def test_ip_obfuscation(self):
        self.assertTrue(is_ip("192.168.0.1"))
        self.assertTrue(is_ip("3232235777"))
        self.assertFalse(is_ip("example.com"))

    def test_edit_distance(self):
        self.assertEqual(edit_distance("paypal", "paypall"), 1)
        self.assertEqual(edit_distance("paypal", "paypla"), 1)


class ParsingTests(unittest.TestCase):
    def test_html_never_rendered_links_extracted(self):
        raw = mk("A <a@example.com>", "s", "plain",
                 html='<p><a href="https://x.example.net/a">www.example.com</a><script>alert(1)</script><img src="https://t.example.net/p.gif"></p>')
        pe = parse_email(raw)
        self.assertTrue(pe.has_script)
        self.assertEqual(pe.remote_image_count, 1)
        self.assertTrue(any(l.host == "x.example.net" and l.text == "www.example.com" for l in pe.links))
        self.assertNotIn("alert(1)", pe.html_text)  # script body is not treated as visible text

    def test_garbage_input_is_incomplete_not_safe(self):
        """Regression: junk bytes were once scored 'minor signals' (30) because the missing From header counted as evidence."""
        a = analyze_bytes(b"\x00\x01 not an email at all \xff\xfe")
        self.assertEqual(a.verdict_code, "incomplete")
        self.assertIn("does not look like an email", " ".join(a.unknowns))

    def test_empty_body_reported_unknown(self):
        a = analyze_bytes(mk("Sam <sam@gmail.com>", "hi", ""))
        self.assertTrue(any("No readable body" in u or "image-only" in u for u in a.unknowns))


class NoNetworkTests(unittest.TestCase):
    def test_default_analysis_makes_no_network_calls(self):
        raw = mk("PayPal <x@paypa1.com>", "Verify", "Verify your account https://paypa1.com/x",
                 html='<a href="https://paypa1.com/x">go</a>', attachments=[("a.exe", "application/octet-stream", b"MZ")])
        with mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network used")), \
             mock.patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")):
            a = analyze_bytes(raw)
        self.assertGreater(a.indicator, 0)


class ScoringCoherenceTests(unittest.TestCase):
    def test_verdict_and_indicator_agree(self):
        """A warning verdict must never sit beside a trivially low indicator (original complaint)."""
        cases = [
            mk("PayPal Security <s@paypa1.com>", "Verify", "Please verify your account within 24 hours https://paypa1.com/a",
               html='<a href="https://paypa1.com/a">Verify</a>'),
            mk("Sam <sam@gmail.com>", "hi", "Dinner Saturday?"),
            mk("Billing <b@x-freight.com>", "Invoice", "see attached", attachments=[("i.pdf.exe", "application/octet-stream", b"MZ")]),
        ]
        for raw in cases:
            a = analyze_bytes(raw)
            floor = {"phishing_likely": 70, "suspicious": 40, "spam_scam": 40, "minor": 15, "none": 0, "incomplete": 0}[a.verdict_code]
            self.assertGreaterEqual(a.indicator, floor, a.verdict)
            if a.verdict_code == "none":
                self.assertLess(a.indicator, 15)

    def test_indicator_meaning_is_not_a_probability_claim(self):
        a = analyze_bytes(mk("Sam <sam@gmail.com>", "hi", "hello"))
        self.assertIn("NOT the probability", a.indicator_meaning)

    def test_no_signals_is_never_called_safe(self):
        a = analyze_bytes(mk("Sam <sam@example.com>", "hi", "hello there"))
        self.assertEqual(a.verdict_code, "none")
        self.assertIn("not a safety clearance", a.verdict)
        self.assertNotIn("safe", a.verdict.replace("not a safety", ""))

    def test_duplicate_signals_do_not_stack_linearly(self):
        from mailscope.models import Signal
        from mailscope.risk_assessment import combine
        one = combine([Signal("a", "spam", "weak", "t", "d")])
        ten = combine([Signal(f"a{i}", "spam", "weak", "t", "d") for i in range(10)])
        self.assertLess(ten, 40)
        self.assertGreater(ten, one)


class TrustTests(unittest.TestCase):
    def test_recorded_auth_pass_gets_no_credit(self):
        base = dict(subject="Verify", text="Please verify your account within 24 hours https://paypa1.com/a",
                    html='<a href="https://paypa1.com/a">Verify</a>')
        plain = analyze_bytes(mk("PayPal Security <s@paypa1.com>", base["subject"], base["text"], html=base["html"]))
        claimed = analyze_bytes(mk("PayPal Security <s@paypa1.com>", base["subject"], base["text"], html=base["html"],
                                   headers={"Authentication-Results": "mx.example.net; spf=pass; dkim=pass; dmarc=pass"}))
        self.assertGreaterEqual(claimed.indicator, plain.indicator)
        self.assertTrue(claimed.auth_claims)
        self.assertIn("recorded text, not verification", " ".join(claimed.unknowns))

    def test_dkim_not_performed_by_default_and_listed_unknown(self):
        raw = mk("A <a@example.com>", "s", "t", headers={"DKIM-Signature": "v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=x; b=y"})
        pe = parse_email(raw)
        r = verify_dkim(pe, enabled=False)
        self.assertEqual(r.status, "not_performed")
        a = analyze_bytes(raw)
        self.assertEqual(a.checks_run["Cryptographic DKIM verification"], "not performed (opt-in)")

    def test_dkim_missing_library_is_labelled_unavailable(self):
        raw = mk("A <a@example.com>", "s", "t", headers={"DKIM-Signature": "v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=x; b=y"})
        with mock.patch.dict(sys.modules, {"dkim": None}):
            r = verify_dkim(parse_email(raw), enabled=True)
        self.assertEqual(r.status, "unavailable")

    def test_verified_domain_can_still_be_flagged(self):
        """A passing signature must not lower a malicious verdict."""
        raw = mk("Billing <b@x-freight.com>", "Invoice", "see attached",
                 attachments=[("i.pdf.exe", "application/octet-stream", b"MZ")],
                 headers={"Authentication-Results": "mx; dkim=pass header.d=x-freight.com"})
        a = analyze_bytes(raw)
        self.assertGreaterEqual(a.indicator, 60)

    def test_recorded_failure_is_reported_as_claim(self):
        pe = parse_email(mk("A <a@example.com>", "s", "t", headers={"Authentication-Results": "mx; spf=fail; dkim=none"}))
        self.assertIn("authentication-results: spf=fail", recorded_claims(pe))


class FalsePositiveGuardTests(unittest.TestCase):
    def test_genuine_brand_mail_with_own_links_is_quiet(self):
        a = analyze_bytes(mk("Chase <no-reply@alertsp.chase.com>", "Verify recent activity",
                             "Please confirm recent activity by signing in at https://www.chase.com/login",
                             html='<a href="https://www.chase.com/login">Sign in</a>'))
        self.assertLess(a.indicator, 15)

    def test_tracking_link_destination_is_unknown_not_flagged(self):
        a = analyze_bytes(mk("Shop <hi@shop.com>", "Sale", "Visit shop.com",
                             html='<a href="https://u1.ct.sendgrid.net/click?x=1">shop.com</a>'))
        self.assertNotIn("link_text_mismatch", ids(a))
        self.assertTrue(any("click-tracking" in u for u in a.unknowns))

    def test_ambiguous_brand_word_alone_is_not_impersonation(self):
        a = analyze_bytes(mk("Apple Pie Bakery <hello@applepiebakery.com>", "Pie", "Order now"))
        self.assertNotIn("brand_display_mismatch", ids(a))

    def test_internationalized_domain_not_flagged(self):
        a = analyze_bytes(mk("Shop <info@bücher.de>", "Order", "Danke https://www.bücher.de/x"))
        self.assertLess(a.indicator, 15)

    def test_mailing_list_reply_to_is_weak_only(self):
        a = analyze_bytes(mk("Dana <dana@univ.edu>", "[list] hi", "meeting", reply_to="list@lists.univ.edu"))
        self.assertLess(a.indicator, 15)

    # ---- regressions found on held-out set 2
    def test_regression_never_share_password_reassurance(self):
        """held-out2 n02: 'we will never ask you to share your password' was flagged as a credential request."""
        a = analyze_bytes(mk("Bank <a@notify.wellsfargo.com>", "Security tips",
                             "Wells Fargo will never ask you to share your password, PIN or one-time code by email."))
        self.assertNotIn("credential_disclosure", ids(a))

    def test_regression_receipt_call_us_is_not_callback_scam_strong(self):
        """held-out2 n03: a genuine receipt saying 'if you did not place this order call us' scored 60."""
        a = analyze_bytes(mk("Orders <o@kitchenstore.com>", "Receipt",
                             "Your card was charged $84.50. If you did not place this order, call customer service at 800-555-0199."))
        self.assertLess(a.indicator, 40)

    def test_regression_single_riskfree_phrase_is_weak(self):
        """held-out2 n04/n05: one phrase like 'risk-free rate' or 'work from home' must not look like a scheme."""
        a = analyze_bytes(mk("Editor <e@marketweekly.com>", "Rates", "We explain the risk-free rate this week."))
        self.assertLess(a.indicator, 15)


class RegressionDetectionTests(unittest.TestCase):
    """Weaknesses found on held-out set 1 (indicator had been 30-37, i.e. under the 'suspicious' line)."""

    def test_regression_reply_with_password_is_strong(self):
        a = analyze_bytes(mk("Mail Admin <m@webservices-center.org>", "Account closing",
                             "Your account will be closed within 24 hours. To retain it, reply with your password and username."))
        self.assertIn("credential_disclosure", ids(a))
        self.assertGreaterEqual(a.indicator, 40)

    def test_regression_payroll_link_to_sibling_domain(self):
        a = analyze_bytes(mk("HR <hr@northwind-payroll.com>", "Update direct deposit",
                             "All employees must update their direct deposit information today at https://northwind-hrportal.com/login",
                             html='<a href="https://northwind-hrportal.com/login">HR portal</a> update your direct deposit information today'))
        self.assertIn("combo_credential_unrelated_link", ids(a))
        self.assertGreaterEqual(a.indicator, 40)

    def test_regression_callback_phishing(self):
        a = analyze_bytes(mk("Billing <b@services-notice.com>", "Receipt",
                             "Your subscription renewal of $499.99 was charged today. If you did not authorize this charge, call 1-888-555-0142 to cancel and get a refund."))
        self.assertIn("callback_scam", ids(a))
        self.assertGreaterEqual(a.indicator, 40)

    def test_regression_risky_attachment_with_invoice_lure(self):
        a = analyze_bytes(mk("AP <a@sup-pliers.net>", "Overdue invoice", "See attached invoice and remit payment.",
                             attachments=[("inv.one", "application/octet-stream", b"\xe4R\\{" + b"\0" * 20)]))
        self.assertIn("combo_attachment_lure", ids(a))
        self.assertGreaterEqual(a.indicator, 40)

    def test_regression_get_rich_scheme_two_phrases(self):
        a = analyze_bytes(mk("Crypto <p@alpha-signals.xyz>", "Offer",
                             "Guaranteed returns, risk-free, double your bitcoin."))
        self.assertGreaterEqual(a.indicator, 40)

    def test_regression_org_name_on_freemail(self):
        a = analyze_bytes(mk("Careers Team <hiring.dept.hr@gmail.com>", "Job", "Work from home and earn $500 per day. No experience needed."))
        self.assertIn("org_name_on_freemail", ids(a))
        self.assertGreaterEqual(a.indicator, 40)

    def test_regression_inert_html_attachment_is_weak(self):
        a = analyze_bytes(mk("Tickets <t@citytheatre.org>", "Tickets", "attached",
                             attachments=[("t.html", "text/html", b"<html><body>Admit two</body></html>")]))
        self.assertLess(a.indicator, 15)

    def test_html_attachment_with_form_is_strong(self):
        a = analyze_bytes(mk("X <x@y.example>", "vm", "voicemail attached",
                             attachments=[("vm.html", "text/html", b"<form><input type='password'></form>")]))
        self.assertIn("att_html_active", ids(a))

    def test_disguised_executable(self):
        a = analyze_bytes(mk("X <x@y.example>", "doc", "see attached",
                             attachments=[("report.pdf", "application/pdf", b"MZ\x90\x00" + b"\0" * 50)]))
        self.assertIn("att_disguised", ids(a))

    def test_pdf_uri_links_are_extracted_as_links(self):
        a = analyze_bytes(mk("X <x@y.example>", "doc", "see attached",
                             attachments=[("r.pdf", "application/pdf", b"%PDF-1.4\n/URI (http://203.0.113.7/login)\n%%EOF")]))
        self.assertTrue(any(l.source == "pdf" for l in a.links))
        self.assertIn("link_ip_host", ids(a))


class ReputationTests(unittest.TestCase):
    def test_local_feed_match_is_strong(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# feed\nbad-site.example\nhttp://other.example/phish/login\n")
        try:
            a = analyze_bytes(mk("X <x@y.example>", "hi", "see https://login.bad-site.example/a"), feed_path=f.name)
            self.assertIn("reputation_listed", ids(a))
            self.assertGreaterEqual(a.indicator, 40)
            self.assertTrue(a.checks_run["Local threat feed"].startswith("loaded"))
        finally:
            os.unlink(f.name)

    def test_not_listed_stays_unknown(self):
        a = analyze_bytes(mk("X <x@y.example>", "hi", "see https://fine.example/a"))
        self.assertTrue(any("threat-intelligence" in u for u in a.unknowns))

    def test_missing_feed_file_is_labelled_unavailable(self):
        _, _, st = load_feed("/nonexistent/feed.txt")
        self.assertTrue(st.startswith("unavailable"))

    def test_urlhaus_without_key_is_unavailable_not_invented(self):
        from mailscope.models import Link
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MAILSCOPE_URLHAUS_KEY", None)
            sigs, st = check_reputation([Link("http://a.example/x", "a.example", "a.example")], use_urlhaus=True)
        self.assertEqual(sigs, [])
        self.assertTrue(st["urlhaus"].startswith("unavailable"))

    def test_urlhaus_code_path_with_mocked_transport(self):
        """Exercises our request/response handling only. The mock is NOT evidence about the real service."""
        from mailscope.models import Link
        class R:
            def __init__(s, body): s.body = body
            def read(s): return s.body
            def __enter__(s): return s
            def __exit__(s, *a): return False
        seen = {}
        def opener(req, timeout=0):
            seen["key"] = req.get_header("Auth-key")
            return R(json.dumps({"query_status": "ok", "url_status": "online", "threat": "malware_download"}).encode())
        sigs, st = check_reputation([Link("http://a.example/x", "a.example", "a.example")], use_urlhaus=True,
                                    urlhaus_key="k", opener=opener)
        self.assertEqual(seen["key"], "k")
        self.assertEqual(sigs[0].id, "reputation_listed")


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.a = analyze_bytes(mk('<script>alert(1)</script> PayPal <x@paypa1.com>', "<b>Verify</b>",
                                 "Verify your account https://paypa1.com/<img src=x onerror=alert(1)>"))

    def test_html_report_is_escaped_and_locked_down(self):
        h = to_html(self.a)
        self.assertNotIn("<script>alert(1)</script>", h)
        self.assertIn("Content-Security-Policy", h)
        self.assertNotIn("onerror=alert(1)>", h.replace("&lt;", "<").replace("onerror=alert(1)&gt;", ""))  # only escaped form present

    def test_links_defanged_in_reports(self):
        self.assertEqual(defang("https://evil.example/a"), "hxxps://evil[.]example/a")
        self.assertNotIn("https://paypa1.com", to_text(self.a))

    def test_json_roundtrip(self):
        d = json.loads(to_json(self.a))
        self.assertIn("indicator", d)
        self.assertIn("unknowns", d)

    def test_report_states_limits(self):
        t = to_text(self.a)
        self.assertIn("WHAT COULD NOT BE VERIFIED", t)
        self.assertIn("not a probability", t)


class Round3RegressionTests(unittest.TestCase):
    """Each test names the real weakness it pins down and the evaluation case where it was found."""

    def test_japanese_idn_is_not_mixed_script(self):
        """heldout4/n22: Katakana + Han in a genuine Japanese shop domain was flagged 'Likely phishing'."""
        from mailscope.domains import idn_findings
        self.assertEqual(idn_findings("カフェ山田.jp"), [])
        self.assertEqual(idn_findings("東京ショップ.jp"), [])
        self.assertEqual(idn_findings("한국몰.kr"), [])

    def test_cyrillic_in_latin_is_still_mixed_script(self):
        """The IDN fix must not weaken the real homograph check."""
        from mailscope.domains import idn_findings
        self.assertTrue(idn_findings("p\u0430ypal.com"))      # Cyrillic a inside Latin
        self.assertTrue(idn_findings("g\u03bfogle.com"))      # Greek omicron inside Latin

    def test_real_brand_domain_inside_foreign_subdomain_is_strong(self):
        """heldout3/p08: drive.google.com.share-docs.top scored only 'moderate' because Google is an everyday word."""
        from mailscope.domains import brand_lookalike
        r = brand_lookalike("drive.google.com.share-docs.top")
        self.assertEqual(r["strength"], "strong")

    def test_product_name_display_counts_as_brand_claim(self):
        """heldout3/p08: the display name 'Google Drive' was ignored because 'drive' was not a recognised service word."""
        a = analyze_bytes(mk("Google Drive <noreply@share-docs.top>", "File shared", "Open it: https://share-docs.top/x"))
        self.assertIn("brand_display_mismatch", ids(a))

    def test_googlegroups_is_not_a_lookalike(self):
        """heldout4/n09: googlegroups.com is a genuine Google domain, not a typo-squat."""
        a = analyze_bytes(mk("Club <club@googlegroups.com>", "[club] digest", "See you Saturday.", headers={"List-Id": "<club.googlegroups.com>"}))
        self.assertNotIn("lookalike_sender_domain", ids(a))

    def test_extortion_needs_claim_plus_demand(self):
        """heldout2/p09: plaintext sextortion got 10/100. A claim of compromise AND a crypto demand is the pattern."""
        a = analyze_bytes(mk("x <x@proton.me>", "I know your password",
                             "I hacked your webcam and recorded you. Send $1500 in bitcoin within 48 hours or I will send the video to all your contacts."))
        self.assertIn("extortion_threat", ids(a))
        self.assertGreaterEqual(a.indicator, 40)

    def test_security_article_about_bitcoin_is_not_extortion(self):
        a = analyze_bytes(mk("News <news@example-news.com>", "Bitcoin price", "Bitcoin rose 4% today. Our analysts explain why wallet address reuse matters."))
        self.assertNotIn("extortion_threat", ids(a))

    def test_macro_attachment_with_see_attached_is_flagged(self):
        """heldout2/p05: a .docm 'resume' with no invoice wording only scored 30."""
        a = analyze_bytes(mk("Applicant <cv@gmail.com>", "Application", "My resume is attached for your review.",
                             attachments=[("CV.docm", "application/vnd.ms-word.document.macroEnabled.12", b"PK\x03\x04" + b"\0" * 64)]))
        self.assertIn("combo_attachment_lure", ids(a))
        self.assertGreaterEqual(a.indicator, 40)

    def test_bank_move_message_asks_for_phone_check(self):
        """heldout2/p10: 'our accounting moved to another bank' scored 0."""
        a = analyze_bytes(mk("Marcus <marcus@some-supplier.com>", "Next transfer",
                             "Our accounting moved to another bank so please use the new account to pay from now on."))
        self.assertIn("payment_request", ids(a))
        self.assertTrue(any("phone" in x.lower() for x in a.actions))

    def test_own_portal_bank_notice_stays_low(self):
        """heldout3/n19: a supplier that points to its own portal and says not to rely on emailed details."""
        a = analyze_bytes(mk("Vendorco <accounts@vendorco.com>", "Bank details changing",
                             "From 1 December our bank details will change. See your portal: https://portal.vendorco.com/billing",
                             html='<p>Our bank details will change. <a href="https://portal.vendorco.com/billing">portal</a></p>'))
        self.assertLess(a.indicator, 40)

    def test_tech_support_scam_is_flagged(self):
        """heldout3/p14: 'virus detected, call this number' got 10."""
        a = analyze_bytes(mk("Windows Security <alert@win-support.info>", "Your PC is infected",
                             "Defender detected 5 viruses on your computer. Call support immediately at 1-888-555-0142 to remove the threat."))
        self.assertIn("tech_support_scam", ids(a))

    def test_mailbox_notice_from_unrelated_domain(self):
        """heldout3/p02: mailbox-full lure whose only link was on the sender's own (lookalike) domain."""
        a = analyze_bytes(mk("IT Helpdesk <helpdesk@acmecorp-support.net>", "Mailbox 98% full",
                             "Your mailbox is almost full and incoming mail will be rejected. Verify your account: https://acmecorp-support.net/quota",
                             to="alice@acmecorp.com"))
        self.assertIn("mailbox_admin_unrelated", ids(a))

    def test_mailbox_notice_from_own_domain_not_flagged_as_unrelated(self):
        a = analyze_bytes(mk("IT <it@acmecorp.com>", "Mailbox 98% full",
                             "Your mailbox is almost full. Clean it up: https://mail.acmecorp.com/cleanup", to="alice@acmecorp.com"))
        self.assertNotIn("mailbox_admin_unrelated", ids(a))

    def test_domain_renewal_solicitation(self):
        """heldout4/p17: 'this is not a bill, pay $289 to keep your domain listing' scored 0."""
        a = analyze_bytes(mk("Domain Registry <n@domain-registry-renewal.net>", "Domain Service Notice",
                             "This is not a bill. Your domain listing will expire. You must pay the renewal fee of $289 within 5 days."))
        self.assertIn("domain_fee_scam", ids(a))

    def test_new_payee_instruction_with_diverted_reply(self):
        """heldout4/p06: 'process an urgent payment to a new supplier' with replies diverted scored 27."""
        a = analyze_bytes(mk("Michael <m@brightpath.com>", "Urgent", "I need you to process an urgent payment to a new supplier today. Reply here, keep this confidential.",
                             reply_to="m.office@ceo-desk.net"))
        self.assertIn("combo_payment_redirect", ids(a))


class Round4RealWorldRegressionTests(unittest.TestCase):
    """Weaknesses found by running the engine over 12,271 real phishing-type emails written by other people."""

    def test_unknown_charset_does_not_crash(self):
        """Real mail with charset="U" made parsing raise LookupError and the result came back 'incomplete'."""
        raw = (b"From: a@example.com\r\nTo: b@example.org\r\nSubject: hi\r\nMIME-Version: 1.0\r\n"
               b"Content-Type: text/plain; charset=\"U\"\r\nContent-Transfer-Encoding: 8bit\r\n\r\nHello there, plain text.\r\n")
        a = analyze_bytes(raw)
        self.assertNotEqual(a.verdict_code, "incomplete")

    def test_invisible_characters_in_display_name(self):
        """A Coinbase-imitating name padded with invisible characters was invisible to brand matching."""
        a = analyze_bytes(mk("Coin\u200bba\u200bse <help@tamperfinder.example>", "Account notice", "Please review your account."))
        self.assertIn("name_obfuscation", ids(a))
        self.assertIn("brand_display_mismatch", ids(a))

    def test_cyrillic_lookalike_letters_in_subject(self):
        a = analyze_bytes(mk("Rewards <x@example.net>", "\u0421ongr\u0430tul\u0430tions your item sold", "See details."))
        self.assertIn("subject_obfuscation", ids(a))

    def test_emoji_and_persian_joiners_are_not_obfuscation(self):
        a = analyze_bytes(mk("Alerts <a@example.com>", "\u26a0\ufe0f Service notice \U0001F468\u200d\U0001F4BB", "Hello."))
        self.assertNotIn("subject_obfuscation", ids(a))
        b = analyze_bytes(mk("Shop <a@example.com>", "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645 \u0633\u0641\u0627\u0631\u0634", "Hello."))
        self.assertNotIn("subject_obfuscation", ids(b))

    def test_invisible_padding_in_body_preheader_is_ignored(self):
        a = analyze_bytes(mk("News <n@brand-example.com>", "Our spring catalogue", "Hello\u200c\u00a0\u200c\u00a0\u200c\u00a0 enjoy the season."))
        self.assertNotIn("name_obfuscation", ids(a))
        self.assertNotIn("subject_obfuscation", ids(a))

    def test_non_english_message_says_wording_was_not_assessed(self):
        text = ("Prezado cliente, identificamos uma inconsistencia na entrega do seu pedido. Acesse o link abaixo para regularizar "
                "e concluir o envio. Caso nao regularize em ate dois dias a mercadoria sera devolvida ao remetente. Obrigado pela atencao.")
        a = analyze_bytes(mk("Entregas <entregas@example.net>", "Aviso de entrega", text))
        self.assertTrue(any("does not look English" in u for u in a.unknowns))
        e = analyze_bytes(mk("Shop <s@example.com>", "Your order", "Thank you for your order. We will send you the tracking details when your package has shipped from our warehouse and is on its way to you."))
        self.assertFalse(any("does not look English" in u for u in e.unknowns))

    def test_brand_sender_with_only_foreign_links(self):
        """Forged From on a brand's real domain with links that all go elsewhere (seen constantly in real mail)."""
        html = '<p>Your points expire. <a href="https://cptdmy.example/redeem">Redeem</a></p>'
        a = analyze_bytes(mk("Rewards <noreply@paypal.com>", "Points expiring", "Your points expire soon.", html=html))
        self.assertIn("brand_sender_foreign_links", ids(a))

    def test_person_on_freemail_sharing_a_link_is_not_a_brand_sender(self):
        """Found by heldout4/n20 right after the rule was added: outlook.com is Microsoft's domain but also a person's mailbox."""
        for dom in ("outlook.com", "gmail.com", "hotmail.com", "icloud.com"):
            a = analyze_bytes(mk(f"Sam <sam.okafor@{dom}>", "Thought you'd like this",
                                 "Saw this and thought of you: https://www.bbc.com/news/technology-1234567. Coffee next week?"))
            self.assertNotIn("brand_sender_foreign_links", ids(a), dom)

    def test_free_hosting_sender_is_only_a_weak_hint(self):
        a = analyze_bytes(mk("Shop <noreply@myapp-1a2b.firebaseapp.com>", "Welcome", "Thanks for signing up for our app."))
        self.assertIn("sender_on_free_hosting", ids(a))
        self.assertLess(a.indicator, 15)

    def test_unfilled_template_placeholders(self):
        a = analyze_bytes(mk("Deals <d@promo-example.com>", "*|MC:SUBJECT|*", "*|MC_PREVIEW_TEXT|* View this email in your browser. Big deals inside."))
        self.assertIn("template_placeholders", ids(a))

    def test_casino_spam_gets_flagged_as_spam_not_phishing(self):
        a = analyze_bytes(mk("Casino Rewards <promo@bonus-spins.top>", "Play now: 125% bonus + 100 FREE spins!",
                             "Win big at our online casino. Welcome bonus, no deposit required, 200 free spins and a jackpot waiting for you. Limited-time offer!"))
        self.assertIn(a.verdict_code, ("spam_scam", "suspicious"))
        self.assertGreaterEqual(a.indicator, 40)

    def test_brand_sender_with_own_or_social_links_is_fine(self):
        own = analyze_bytes(mk("PayPal <service@paypal.com>", "Receipt", "Receipt.",
                               html='<a href="https://www.paypal.com/activity">View</a> <a href="https://www.facebook.com/paypal">Follow</a>'))
        self.assertNotIn("brand_sender_foreign_links", ids(own))
        social = analyze_bytes(mk("PayPal <service@paypal.com>", "Follow us", "Follow us.",
                                  html='<a href="https://www.facebook.com/paypal">Facebook</a> <a href="https://www.instagram.com/paypal">Instagram</a>'))
        self.assertNotIn("brand_sender_foreign_links", ids(social))


class SetupHelpersTests(unittest.TestCase):
    """The launcher and self-check exist because the first delivery 'did not work' on the user's Windows PC."""

    def test_engine_self_check_passes(self):
        from mailscope.doctor import engine_check
        ok, text = engine_check()
        self.assertTrue(ok, text)

    def test_windows_launcher_is_plain_ascii_with_windows_line_endings(self):
        raw = open(os.path.join(ROOT, "start_mailscope.bat"), "rb").read()
        self.assertTrue(all(c < 128 for c in raw), "non-ASCII characters can break cmd.exe")
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""), "every line should end in CRLF")

    def test_launcher_jumps_all_have_targets(self):
        import re
        t = open(os.path.join(ROOT, "start_mailscope.bat"), encoding="ascii").read()
        labels = set(re.findall(r"^:(\w+)", t, re.M))
        self.assertLessEqual(set(re.findall(r"goto :(\w+)", t)), labels)

    def test_streamlit_config_keeps_the_page_local(self):
        cfg = open(os.path.join(ROOT, ".streamlit", "config.toml"), encoding="utf-8").read()
        self.assertIn('address = "127.0.0.1"', cfg)
        self.assertIn("gatherUsageStats = false", cfg)


class EvaluationSetGuardTests(unittest.TestCase):
    """Pins current behaviour on the labelled sets so regressions are visible. Known misses are listed, not hidden."""
    KNOWN_MISSES = {
        "dev": set(),
        "heldout": {"h13_compromised_vendor_clean", "h18_seo_cold_spam"},
        "heldout2": set(),
        "heldout3": {"p15_hijacked_account_link"},
        "heldout4": {"p09_pdf_link_invoice", "p18_wrong_number_lure", "p19_hijacked_vendor_thread"},
    }

    def _run(self, name):
        d = os.path.join(ROOT, "evaluation", name)
        labels = json.load(open(os.path.join(d, "labels.json"), encoding="utf-8"))
        res = {}
        for cid, meta in labels.items():
            with open(os.path.join(d, cid + ".eml"), "rb") as fh:
                a = analyze_bytes(fh.read())
            res[cid] = (meta["label"], a)
        return res

    def test_sets(self):
        for name, known in self.KNOWN_MISSES.items():
            res = self._run(name)
            misses = {c for c, (lab, a) in res.items() if lab != "legit" and a.indicator < 40}
            fps = {c for c, (lab, a) in res.items() if lab == "legit" and a.indicator >= 40}
            self.assertEqual(misses, known, f"{name}: misses changed")
            self.assertEqual(fps, set(), f"{name}: false positives")
            self.assertFalse([c for c, (_, a) in res.items() if a.verdict_code == "incomplete"], f"{name}: analysis failures")


if __name__ == "__main__":
    unittest.main()
