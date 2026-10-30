"""Static attachment inspection. Attachments are never opened, run or rendered.

We look at names, declared types, magic bytes, and (for a few formats) raw structure
such as zip member names or PDF keywords. Hashes are computed locally; nothing is
uploaded anywhere.
"""
from __future__ import annotations

import io
import re
import zipfile

from .email_analysis import make_link
from .models import ParsedEmail, Signal

EXECUTABLE = {"exe", "scr", "com", "pif", "cpl", "msi", "msp", "jar", "bat", "cmd", "ps1", "psm1",
              "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "reg", "dll", "apk", "sh", "app", "appx", "msix"}
MACRO_OFFICE = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb", "ppam", "sldm"}
HTML_LIKE = {"html", "htm", "xhtml", "shtml", "svg", "mht", "mhtml"}
DISK_IMAGES = {"iso", "img", "vhd", "vhdx", "dmg"}
ARCHIVES = {"zip", "rar", "7z", "cab", "ace", "gz", "tgz", "tar", "arj", "z"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "csv"}
MAGIC = [
    (b"MZ", "Windows executable"), (b"\x7fELF", "Linux executable"), (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP container (also .docx/.xlsx/.jar)"), (b"Rar!", "RAR archive"),
    (b"7z\xbc\xaf", "7-Zip archive"), (b"\xd0\xcf\x11\xe0", "legacy Office (OLE) file"),
    (b"\xff\xd8\xff", "JPEG image"), (b"\x89PNG", "PNG image"), (b"GIF8", "GIF image"),
    (b"L\x00\x00\x00\x01\x14\x02", "Windows shortcut (.lnk)"),
]
SCRIPTY = re.compile(rb"(?i)(<script|atob\(|eval\(|document\.write|unescape\(|fromcharcode|<input[^>]+password|<form|http-equiv=.?refresh|<iframe)")


def _ext_chain(name: str) -> list[str]:
    base = name.lower().strip().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    parts = base.split(".")
    return parts[1:] if len(parts) > 1 else []


def _magic_name(payload: bytes) -> str:
    for sig, label in MAGIC:
        if payload.startswith(sig):
            return label
    return ""


def analyze_attachments(pe: ParsedEmail, body_text: str) -> list[Signal]:
    sigs: list[Signal] = []
    archive_present = False
    for att, (name, payload) in zip(pe.attachments, pe.attachment_payloads):
        chain = _ext_chain(name)
        ext = chain[-1] if chain else ""
        mg = _magic_name(payload)
        if mg:
            att.notes.append(f"Content looks like: {mg}")

        if ext in EXECUTABLE:
            sigs.append(Signal(f"att_exec:{name}", "attachment", "strong", "Attachment is an executable or script type",
                               "File types like this can run code on your computer when opened.", [f"{name} ({att.size} bytes)"]))
        if len(chain) >= 2 and ext in (EXECUTABLE | MACRO_OFFICE | HTML_LIKE | ARCHIVES | DISK_IMAGES) and chain[-2] in DOC_EXT:
            sigs.append(Signal(f"att_double_ext:{name}", "attachment", "strong", "Attachment hides a risky type behind a document-looking name",
                               "The name looks like a document, but the real ending is different.", [name]))
        if mg in ("Windows executable", "Linux executable", "Windows shortcut (.lnk)") and ext not in EXECUTABLE:
            sigs.append(Signal(f"att_disguised:{name}", "attachment", "strong", "Attachment content does not match its file name",
                               f"The file name says '.{ext or '?'}' but its content looks like: {mg}.", [name]))
        if ext in MACRO_OFFICE:
            sigs.append(Signal(f"att_macro:{name}", "attachment", "moderate", "Macro-enabled Office file",
                               "Macros can run code; they are rarely needed for ordinary business documents.", [name]))
        if ext in DISK_IMAGES:
            sigs.append(Signal(f"att_diskimg:{name}", "attachment", "moderate", "Disk-image attachment",
                               "Disk images are used to smuggle files past some scanners.", [name]))
        if ext == "one":
            sigs.append(Signal(f"att_onenote:{name}", "attachment", "moderate", "OneNote attachment",
                               "OneNote files can carry embedded scripts and have been widely abused for malware delivery.", [name]))
        if ext in HTML_LIKE:
            hits = SCRIPTY.findall(payload[:2_000_000])
            if hits:
                sigs.append(Signal(f"att_html_active:{name}", "attachment", "strong", "HTML attachment contains scripts or a login form",
                                   "Local HTML files with forms or scripts are a common way to run a fake login page from your own computer.", [name]))
            else:
                sigs.append(Signal(f"att_html:{name}", "attachment", "weak", "HTML attachment",
                                   "Unusual in legitimate mail and sometimes used to deliver fake login pages. No scripts or forms were found in this one.", [name]))
        if ext in ARCHIVES or mg in ("RAR archive", "7-Zip archive"):
            archive_present = True
            sigs.extend(_inspect_zip(name, payload, ext))

        if ext == "pdf" or mg == "PDF":
            sigs.extend(_inspect_pdf(pe, name, payload))
        if mg.startswith("ZIP container") and ext in ("docx", "xlsx", "pptx", "docm", "xlsm", "zip", "jar"):
            sigs.extend(_inspect_zip(name, payload, ext))

    if archive_present and re.search(r"(?i)\bpassword\b\s*(is|:)\s*\S+", body_text):
        sigs.append(Signal("att_password_in_body", "attachment", "moderate", "Archive plus a password given in the email text",
                           "Sending the password in the same message prevents scanners from opening the archive and is common in malware delivery.",
                           ["Body contains a password hint next to an archive attachment"]))
    return _dedupe(sigs)


def _dedupe(sigs: list[Signal]) -> list[Signal]:
    seen, out = set(), []
    for s in sigs:
        if s.id not in seen:
            seen.add(s.id)
            out.append(s)
    return out


def _inspect_zip(name: str, payload: bytes, ext: str) -> list[Signal]:
    out: list[Signal] = []
    if not payload.startswith(b"PK"):
        return out
    try:
        zf = zipfile.ZipFile(io.BytesIO(payload))
        infos = zf.infolist()[:500]
    except (zipfile.BadZipFile, OSError, NotImplementedError):
        return out
    names = [i.filename.lower() for i in infos]
    if any(i.flag_bits & 0x1 for i in infos):
        out.append(Signal(f"att_encrypted:{name}", "attachment", "weak", "Password-protected archive",
                          "Encrypted contents cannot be inspected by MailScope or by most mail scanners.", [name]))
    risky = [n for n in names if n.rsplit(".", 1)[-1] in EXECUTABLE and not n.endswith("/")]
    if risky:
        out.append(Signal(f"att_zip_exec:{name}", "attachment", "strong", "Archive contains an executable or script",
                          "An archive that contains program files is a common malware wrapper.", [f"{name} contains: {', '.join(risky[:5])}"]))
    if any(n.endswith("vbaproject.bin") for n in names) and ext not in MACRO_OFFICE:
        out.append(Signal(f"att_hidden_macro:{name}", "attachment", "moderate", "Office file contains a macro project",
                          "The file has an embedded VBA project even though its name does not announce macros.", [name]))
    for i in infos:
        if i.filename.lower().endswith(".rels") and i.file_size < 1_000_000:
            try:
                data = zf.read(i)
            except Exception:
                continue
            if re.search(rb'(?i)attachedTemplate[^>]*TargetMode="External"|TargetMode="External"[^>]*attachedTemplate', data):
                out.append(Signal(f"att_remote_template:{name}", "attachment", "moderate", "Office file loads a template from a remote address",
                                  "Remote-template references are used to fetch malicious content when the file is opened.", [name]))
                break
    return out


def _inspect_pdf(pe: ParsedEmail, name: str, payload: bytes) -> list[Signal]:
    out: list[Signal] = []
    blob = payload[:5_000_000]
    for kw in (rb"/JavaScript", rb"/JS", rb"/Launch", rb"/OpenAction", rb"/EmbeddedFile"):
        if kw in blob:
            if kw in (rb"/Launch", rb"/JavaScript", rb"/JS"):
                out.append(Signal(f"att_pdf_active:{name}", "attachment", "moderate", "PDF contains active content",
                                  "JavaScript or launch actions are rare in ordinary PDFs.", [f"{name}: contains {kw.decode()}"]))
                break
    uris = re.findall(rb"/URI\s*\(([^)]{4,300})\)", blob)
    for u in uris[:20]:
        link = make_link(u.decode("latin-1"), "", "pdf")
        if link:
            pe.links.append(link)
    if re.search(rb"/Filter\s*/(FlateDecode|LZWDecode)", blob):
        pass  # compressed streams are not decompressed: reported as an unknown elsewhere
    return out
