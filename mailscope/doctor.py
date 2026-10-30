"""Self-check. Run this first when "it does not work":

    Windows:        py -3 -m mailscope.doctor
    macOS / Linux:  python3 -m mailscope.doctor

(from inside the project folder, the one that contains app.py).

It prints the facts that matter and proves the analysis engine itself runs, which needs nothing
beyond Python. Copy the whole output into a message when asking for help. Nothing is sent anywhere
and no email is read: it analyses one tiny built-in fake message.
"""
from __future__ import annotations

import importlib
import os
import platform
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A deliberately fake phishing-style message (reserved ".example" domain, nothing real).
SAMPLE = (b"From: PayPal <service@paypa1-secure.example>\r\nTo: you@example.org\r\nSubject: Verify your account\r\n"
          b"MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
          b"<p>Verify your account: <a href=\"https://paypa1-secure.example/login\">https://www.paypal.com/login</a></p>\r\n")


def engine_check() -> tuple[bool, str]:
    """Run the analysis engine on the built-in fake message. Returns (ok, one-line description)."""
    try:
        from .risk_assessment import analyze_bytes
        a = analyze_bytes(SAMPLE)
    except Exception as exc:  # report, never crash: this is the diagnostic
        return False, f"the analysis engine failed: {exc.__class__.__name__}: {str(exc)[:160]}"
    if a.verdict_code == "phishing_likely" and a.indicator >= 70:
        return True, f"the analysis engine works (built-in fake phishing message scored {a.indicator}/100)"
    return False, f"the engine ran but gave an unexpected result ({a.verdict_code}, {a.indicator}/100)"


def main() -> int:
    ok = True
    print("MailScope self-check")
    print(f"  Python:    {sys.version.split()[0]} on {platform.system()} {platform.machine()}")
    print(f"  Folder:    {ROOT}")
    if sys.version_info < (3, 10):
        print("  PROBLEM:   Python 3.10 or newer is needed. Install a newer Python from https://www.python.org/downloads/")
        ok = False

    for name, purpose, required in (("streamlit", "the web page", True), ("dkim", "the optional DKIM check", False)):
        try:
            mod = importlib.import_module(name)
            print(f"  {name + ':':<10} installed (version {getattr(mod, '__version__', 'unknown')}), used for {purpose}")
        except Exception as exc:
            tag = "PROBLEM:   " if required else "optional:  "
            print(f"  {tag}{name} is not available ({exc.__class__.__name__}); it is used for {purpose}.")
            if required:
                print("             Install it with:  python -m pip install -r requirements.txt")
                ok = False

    for rel in ("app.py", "requirements.txt", os.path.join("samples", "d01_paypal_homoglyph.eml")):
        if not os.path.exists(os.path.join(ROOT, rel)):
            print(f"  PROBLEM:   the file '{rel}' is missing from the folder above. "
                  "Extract the whole zip first, and run this from the folder that contains app.py.")
            ok = False

    good, text = engine_check()
    print(f"  Engine:    {'OK - ' if good else 'PROBLEM - '}{text}")
    ok = ok and good
    print("Result: " + ("everything needed is in place." if ok else "something above needs fixing (see the PROBLEM lines)."))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
