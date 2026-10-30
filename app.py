"""MailScope web interface (Streamlit). Run:  streamlit run app.py

All analysis happens on this computer. Nothing is sent anywhere unless you tick one of the
optional online checks in the sidebar, which say exactly what would leave the machine.
"""
import os

import streamlit as st

from mailscope import INDICATOR_MEANING
from mailscope.report_tools import LIMITS, defang, defang_text, to_html, to_json, to_text
from mailscope.risk_assessment import analyze_bytes

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = {
    "Sample 1: lookalike PayPal login (synthetic)": "d01_paypal_homoglyph.eml",
    "Sample 2: executive gift-card request (synthetic)": "d04_ceo_giftcards.eml",
    "Sample 3: executable disguised as an invoice (synthetic)": "d06_exe_invoice.eml",
    "Sample 4: lottery advance-fee scam (synthetic)": "d08_lottery.eml",
    "Sample 5: ordinary newsletter via a bulk-mail service (synthetic)": "d10_newsletter_sendgrid.eml",
    "Sample 6: genuine-style password reset (synthetic)": "d12_real_password_reset.eml",
}
MAX_UPLOAD_MB = 25

st.set_page_config(page_title="MailScope", page_icon="✉️", layout="wide")
st.title("MailScope")
st.caption("A local first-pass check of a suspicious email. It explains its evidence, says what it could not verify, "
           "and never calls a message safe.")

# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.header("Privacy and optional checks")
    st.write("By default **nothing leaves this computer**. Messages are parsed locally; attachments are never opened, "
             "HTML is never rendered, images are never loaded, and links are never visited.")
    st.subheader("Optional checks (off by default)")
    dkim_on = st.checkbox("Verify DKIM signatures cryptographically",
                          help="Needs the 'dkimpy' package. Makes one DNS lookup per signing domain to fetch its public key. "
                               "Only the signer's domain and selector name are looked up; the message itself is not sent.")
    feed_path = st.text_input("Local threat-feed file (offline)", value=os.environ.get("MAILSCOPE_BLOCKLIST", ""),
                              help="Plain text file, one domain or URL per line. Compared locally, nothing is uploaded.")
    urlhaus_on = st.checkbox("Look up links on URLhaus (online)",
                             help="Sends each link's URL (up to 10) to abuse.ch's URLhaus service. The message text, sender and "
                                  "attachments are NOT sent. Needs a free key in the MAILSCOPE_URLHAUS_KEY environment variable.")
    if urlhaus_on and not os.environ.get("MAILSCOPE_URLHAUS_KEY"):
        st.warning("URLhaus is unavailable: the MAILSCOPE_URLHAUS_KEY environment variable is not set. "
                   "Get a free key at auth.abuse.ch, set the variable, and restart the app.")
    st.divider()
    with st.expander("How to get a .eml file"):
        st.markdown(
            "- **Gmail:** open the message, then the three-dot menu, then *Download message*.\n"
            "- **Outlook (desktop):** *File, Save As*, choose *Outlook Message Format* or drag the message to your desktop "
            "(some versions save .msg; use *Save as .eml* in newer Outlook or Thunderbird).\n"
            "- **Apple Mail:** drag the message to the desktop, or *File, Save As, Raw Message Source*.\n"
            "- **Thunderbird:** *File, Save As, File*.\n\n"
            "Do not forward the message to yourself first: forwarding changes the headers.")
    with st.expander("What MailScope can and cannot do"):
        for x in LIMITS:
            st.markdown(f"- {x}")

# ------------------------------------------------------------------ input
st.subheader("1. Choose a message")
c1, c2 = st.columns([3, 2])
with c1:
    up = st.file_uploader("Upload a .eml file", type=["eml"], help="The file is read in memory and analysed locally.")
with c2:
    sample_name = st.selectbox("Or try a synthetic example", ["(none)"] + list(SAMPLES))

raw, source = None, ""
if up is not None:
    data = up.getvalue()
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        st.error(f"This file is larger than {MAX_UPLOAD_MB} MB, which is above the limit. Re-export the message without large attachments.")
    else:
        raw, source = data, up.name
elif sample_name != "(none)":
    with open(os.path.join(HERE, "samples", SAMPLES[sample_name]), "rb") as fh:
        raw, source = fh.read(), sample_name

if raw is None:
    st.info("Upload a saved email (.eml) or pick an example to begin. Examples are synthetic messages written for testing.")
    st.stop()

with st.spinner("Analysing locally..."):
    a = analyze_bytes(raw, dkim_enabled=dkim_on, feed_path=feed_path.strip(), use_urlhaus=urlhaus_on)

# ------------------------------------------------------------------ verdict
st.subheader("2. Result")
st.caption(f"Message: {source}")
banner = {"phishing_likely": st.error, "suspicious": st.error, "spam_scam": st.warning,
          "minor": st.warning, "none": st.info, "incomplete": st.warning}[a.verdict_code]
banner(f"**{a.verdict}**")

m1, m2, m3 = st.columns(3)
m1.metric("Evidence indicator", f"{a.indicator} / 100", a.indicator_band, delta_color="off")
m2.metric("Evidence coverage", a.evidence_coverage)
m3.metric("Links / attachments", f"{len(a.links)} / {len(a.attachments)}")
st.progress(min(a.indicator, 100) / 100)
with st.expander("What does this number mean?"):
    st.write(INDICATOR_MEANING)
    st.write("Bands: 70+ High, 40-69 Medium, 15-39 Low, under 15 Minimal. A low number means little suspicious evidence was found, "
             "not that the message is safe.")

o, c = st.columns(2)
with o:
    st.markdown("#### Is the sender or origin suspicious?")
    st.write(f"**{a.origin_status}**")
    st.caption(a.origin_detail)
with c:
    st.markdown("#### Are the content, links or attachments dangerous?")
    st.write(f"**{a.content_status}**")

if a.errors:
    st.warning("Some checks did not complete. This result is incomplete and must not be treated as safe:\n\n"
               + "\n".join(f"- {e}" for e in a.errors))

st.markdown("#### Main reasons")
if a.reasons:
    for s in a.reasons:
        with st.expander(f"[{s.strength}] {s.title}", expanded=s.strength in ("strong", "combo")):
            st.write(s.detail)
            for ev in s.evidence:
                st.code(defang_text(ev), language=None)
else:
    st.write("No strong signals were found.")

st.markdown("#### What to do next")
for x in a.actions:
    st.markdown(f"- {x}")

st.markdown("#### What could not be verified")
for x in a.unknowns:
    st.markdown(f"- {defang_text(x)}")

# ------------------------------------------------------------------ details
st.subheader("3. Details")
t1, t2, t3, t4, t5, t6 = st.tabs(["Message", "Links", "Attachments", "Checks performed", "All signals", "Authentication claims"])
with t1:
    for k, v in a.parsed_summary.items():
        st.markdown(f"**{k}:** {defang_text(v)}")
with t2:
    st.caption("Shown defanged (hxxp, [.]) so they cannot be clicked. MailScope never visits links.")
    if a.links:
        st.dataframe([{"Link": defang(l.url), "Found in": l.source, "Visible text": l.text, "Flags": ", ".join(l.flags)} for l in a.links])
    else:
        st.write("No links found.")
with t3:
    st.caption("Attachments are never opened. Hashes are computed locally and can be looked up by you elsewhere if you choose.")
    if a.attachments:
        st.dataframe([{"File": t.filename, "Declared type": t.content_type, "Bytes": t.size, "SHA-256": t.sha256, "Notes": "; ".join(t.notes)}
                      for t in a.attachments])
    else:
        st.write("No attachments.")
with t4:
    for k, v in a.checks_run.items():
        st.markdown(f"- **{k}:** {v}")
with t5:
    if a.signals:
        st.dataframe([{"Strength": s.strength, "Category": s.category, "Signal": s.title} for s in a.signals])
    else:
        st.write("No signals.")
with t6:
    st.warning("These lines are text stored in the file. Anyone can write 'dkim=pass' into a file, so MailScope gives them no credit. "
               "Only the optional DKIM verification in the sidebar is a real cryptographic check.")
    st.write(a.auth_claims or "None recorded.")

# ------------------------------------------------------------------ export
st.subheader("4. Export")
d1, d2, d3 = st.columns(3)
d1.download_button("Download HTML report", to_html(a), file_name="mailscope_report.html", mime="text/html")
d2.download_button("Download JSON report", to_json(a), file_name="mailscope_report.json", mime="application/json")
d3.download_button("Download text report", to_text(a), file_name="mailscope_report.txt", mime="text/plain")
