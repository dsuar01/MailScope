"""Smoke test for app.py using a recording stub of the Streamlit API.

This checks that the interface code runs end to end for every sample and for an
uploaded file, shows the key sections, never raises, and keeps text in English. It
does NOT prove the page renders correctly in a browser: run `streamlit run app.py`
and look at it for that.
"""
import os
import runpy
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "evaluation"))


class _Stop(Exception):
    pass


class _Any:
    def __init__(self, rec=None, name=""):
        self._rec, self._name = rec, name

    def __getattr__(self, n):
        if n.startswith("__"):
            raise AttributeError(n)
        return _Any(self._rec, n)

    def __call__(self, *a, **k):
        if self._rec is not None:
            self._rec.append((self._name, a, k))
        return _Any(self._rec, self._name)

    def __enter__(self): return self
    def __exit__(self, *a): return False
    def __iter__(self): return iter(())


def make_stub(upload=None, selection="(none)"):
    rec: list = []
    m = types.ModuleType("streamlit")

    def fn(name, ret=None):
        def f(*a, **k):
            rec.append((name, a, k))
            return ret(*a, **k) if callable(ret) else ret
        return f

    m.set_page_config = fn("set_page_config")
    for n in ("title", "caption", "header", "subheader", "write", "markdown", "code", "info", "warning", "error",
              "success", "metric", "progress", "divider", "dataframe", "download_button"):
        setattr(m, n, fn(n))
    m.sidebar = _Any(rec, "sidebar")
    m.expander = lambda *a, **k: (rec.append(("expander", a, k)), _Any(rec, "expander"))[1]
    m.spinner = lambda *a, **k: _Any(rec, "spinner")
    m.checkbox = fn("checkbox", False)
    m.text_input = fn("text_input", lambda label, value="", **k: value)
    m.file_uploader = fn("file_uploader", upload)
    m.selectbox = fn("selectbox", lambda label, options, **k: selection if selection in options else options[0])
    m.columns = lambda spec, **k: [_Any(rec, "col") for _ in range(spec if isinstance(spec, int) else len(spec))]
    m.tabs = lambda names, **k: [_Any(rec, "tab") for _ in names]

    def stop():
        rec.append(("stop", (), {}))
        raise _Stop()
    m.stop = stop
    return m, rec


class _Upload:
    def __init__(self, name, data): self.name, self._d = name, data
    def getvalue(self): return self._d


def run_app(upload=None, selection="(none)"):
    stub, rec = make_stub(upload, selection)
    saved = sys.modules.get("streamlit")
    sys.modules["streamlit"] = stub
    try:
        try:
            runpy.run_path(os.path.join(ROOT, "app.py"), run_name="__main__")
        except _Stop:
            pass
    finally:
        if saved is not None:
            sys.modules["streamlit"] = saved
        else:
            sys.modules.pop("streamlit", None)
    return rec


class AppSmokeTests(unittest.TestCase):
    def test_empty_state_prompts_user(self):
        rec = run_app()
        self.assertTrue(any(n == "info" and "Upload a saved email" in a[0] for n, a, _ in rec))
        self.assertTrue(any(n == "stop" for n, _, _ in rec))

    def test_every_sample_renders_all_sections(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("x", os.path.join(ROOT, "app.py"))
        names = [l.split('"')[1] for l in open(os.path.join(ROOT, "app.py"), encoding="utf-8") if l.strip().startswith('"Sample ')]
        self.assertEqual(len(names), 6)
        for name in names:
            rec = run_app(selection=name)
            kinds = [n for n, _, _ in rec]
            self.assertIn("progress", kinds, name)
            self.assertIn("metric", kinds, name)
            self.assertEqual(kinds.count("download_button"), 3, name)
            text = " ".join(str(a) for n, a, _ in rec if n in ("markdown", "subheader", "error", "warning", "info"))
            self.assertIn("What could not be verified", text, name)
            self.assertIn("What to do next", text, name)

    def test_upload_path_and_verdict_banner(self):
        raw = open(os.path.join(ROOT, "samples", "d01_paypal_homoglyph.eml"), "rb").read()
        rec = run_app(upload=_Upload("test.eml", raw))
        banners = [a[0] for n, a, _ in rec if n == "error"]
        self.assertTrue(any("Likely phishing" in b for b in banners))

    def test_oversized_upload_rejected_politely(self):
        rec = run_app(upload=_Upload("big.eml", b"x" * (26 * 1024 * 1024)))
        self.assertTrue(any(n == "error" and "larger than" in a[0] for n, a, _ in rec))

    def test_benign_sample_is_not_labelled_safe(self):
        rec = run_app(selection="Sample 5: ordinary newsletter via a bulk-mail service (synthetic)")
        banners = " ".join(a[0] for n, a, _ in rec if n in ("info", "warning", "error", "success") and a)
        self.assertNotIn("safe**", banners.replace("not a safety clearance", ""))
        self.assertIn("not a safety clearance", banners)

    def test_garbage_upload_yields_incomplete_not_crash(self):
        rec = run_app(upload=_Upload("junk.eml", b"\x00\xff\xfe garbage"))
        self.assertTrue(any(n in ("warning", "info", "error") for n, _, _ in rec))


if __name__ == "__main__":
    unittest.main()
