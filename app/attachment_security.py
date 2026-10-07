"""Attachment safety classification from magic bytes + extension/MIME rules.

The classifier is deliberately **conservative and limited**:

* Only a small, explicit set of file signatures is recognized (executables,
  scripts, common documents/images/archives, plain text, HTML).
* Anything unrecognized is ``unknown`` — it is **never asserted safe**.
* Content is only *read* (a fixed-size prefix plus a text heuristic); bytes
  are never executed, decoded into runnable form, or sent anywhere.

The verdict keeps the evidence an archivist needs before downloading: the
detected signature, the filename extension and declared MIME it was checked
against, and human-readable reasons for the decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# Bump when rules change so rescans are distinguishable in stored records.
CLASSIFIER_VERSION = "sig-1"

# How many leading bytes are inspected for signatures / the text heuristic.
_SNIFF_BYTES = 8192


class SafetyCategory(str, Enum):
    MATCHED = "matched"        # signature agrees with filename extension and declared MIME
    EXECUTABLE = "executable"  # executable/script signature found in the content
    MISMATCH = "mismatch"      # known benign signature, but name/MIME claim something else
    UNKNOWN = "unknown"        # no recognized signature; safety cannot be asserted


@dataclass(frozen=True)
class AttachmentSafety:
    """Verdict for one attachment. ``suspicious`` is True for every category
    other than ``matched`` — unknown content is not vouched for."""

    category: SafetyCategory
    suspicious: bool
    detected_signature: str | None  # signature kind, e.g. "pe-mz", "pdf", "text"
    reasons: list[str] = field(default_factory=list)
    classifier_version: str = CLASSIFIER_VERSION


@dataclass(frozen=True)
class _Signature:
    kind: str
    label: str
    executable: bool
    magic: bytes
    offset: int = 0


# Limited, explicit signature table. Order matters: first match wins.
_SIGNATURES: tuple[_Signature, ...] = (
    _Signature("pe-mz", "Windows PE executable (MZ)", True, b"MZ"),
    _Signature("elf", "ELF executable", True, b"\x7fELF"),
    _Signature("mach-o", "Mach-O executable", True, b"\xfe\xed\xfa\xce"),
    _Signature("mach-o", "Mach-O executable", True, b"\xfe\xed\xfa\xcf"),
    _Signature("mach-o", "Mach-O executable", True, b"\xce\xfa\xed\xfe"),
    _Signature("mach-o", "Mach-O executable", True, b"\xcf\xfa\xed\xfe"),
    _Signature("mach-o", "Mach-O fat binary", True, b"\xca\xfe\xba\xbe"),
    _Signature("script", "script with shebang (#!)", True, b"#!"),
    _Signature("ole-cfb", "OLE compound document (legacy Office/MSI)", False, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    _Signature("pdf", "PDF document", False, b"%PDF-"),
    _Signature("png", "PNG image", False, b"\x89PNG\r\n\x1a\n"),
    _Signature("jpeg", "JPEG image", False, b"\xff\xd8\xff"),
    _Signature("gif", "GIF image", False, b"GIF87a"),
    _Signature("gif", "GIF image", False, b"GIF89a"),
    _Signature("zip", "ZIP archive", False, b"PK\x03\x04"),
    _Signature("zip", "ZIP archive (empty)", False, b"PK\x05\x06"),
    _Signature("gzip", "gzip stream", False, b"\x1f\x8b"),
    _Signature("rar", "RAR archive", False, b"Rar!\x1a\x07"),
    _Signature("7z", "7-Zip archive", False, b"7z\xbc\xaf'\x1c"),
)

# Extension (lowercase, with dot) -> acceptable signature kinds.
_EXT_EXPECT: dict[str, frozenset[str]] = {
    ".txt": frozenset({"text"}),
    ".md": frozenset({"text"}),
    ".csv": frozenset({"text"}),
    ".log": frozenset({"text"}),
    ".html": frozenset({"html", "text"}),
    ".htm": frozenset({"html", "text"}),
    ".pdf": frozenset({"pdf"}),
    ".png": frozenset({"png"}),
    ".jpg": frozenset({"jpeg"}),
    ".jpeg": frozenset({"jpeg"}),
    ".gif": frozenset({"gif"}),
    ".zip": frozenset({"zip"}),
    ".gz": frozenset({"gzip"}),
    ".rar": frozenset({"rar"}),
    ".7z": frozenset({"7z"}),
    ".exe": frozenset({"pe-mz"}),
    ".dll": frozenset({"pe-mz"}),
    ".com": frozenset({"pe-mz"}),
    ".scr": frozenset({"pe-mz"}),
    ".elf": frozenset({"elf"}),
    ".sh": frozenset({"script", "text"}),
    ".bat": frozenset({"script", "text"}),
    ".cmd": frozenset({"script", "text"}),
    ".ps1": frozenset({"script", "text"}),
    ".doc": frozenset({"ole-cfb"}),
    ".xls": frozenset({"ole-cfb"}),
    ".ppt": frozenset({"ole-cfb"}),
    ".msi": frozenset({"ole-cfb"}),
}

# Declared MIME type -> acceptable signature kinds. Types absent from this
# table (e.g. application/octet-stream) carry no expectation.
_MIME_EXPECT: dict[str, frozenset[str]] = {
    "text/plain": frozenset({"text"}),
    "text/csv": frozenset({"text"}),
    "text/html": frozenset({"html", "text"}),
    "application/pdf": frozenset({"pdf"}),
    "image/png": frozenset({"png"}),
    "image/jpeg": frozenset({"jpeg"}),
    "image/gif": frozenset({"gif"}),
    "application/zip": frozenset({"zip"}),
    "application/gzip": frozenset({"gzip"}),
    "application/x-7z-compressed": frozenset({"7z"}),
    "application/vnd.rar": frozenset({"rar"}),
    "application/x-msdownload": frozenset({"pe-mz"}),
    "application/x-dosexec": frozenset({"pe-mz"}),
    "application/x-executable": frozenset({"elf"}),
    "application/x-elf": frozenset({"elf"}),
    "application/x-sh": frozenset({"script", "text"}),
    "application/msword": frozenset({"ole-cfb"}),
    "application/vnd.ms-excel": frozenset({"ole-cfb"}),
    "application/vnd.ms-powerpoint": frozenset({"ole-cfb"}),
    "application/x-msi": frozenset({"ole-cfb"}),
}

# Bytes (other than whitespace) that mark content as non-text.
_CONTROL_BYTES = frozenset(range(0x00, 0x20)) - {0x09, 0x0A, 0x0C, 0x0D}


def _detect_signature(prefix: bytes) -> _Signature | None:
    for sig in _SIGNATURES:
        if prefix[sig.offset :].startswith(sig.magic):
            return sig
    return None


def _looks_like_text(prefix: bytes) -> bool:
    if not prefix:
        return True  # empty file: nothing executable about it
    if any(b in _CONTROL_BYTES or b == 0x7F for b in prefix):
        return False
    try:
        prefix.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _looks_like_html(prefix: bytes) -> bool:
    head = prefix[:512].lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def _extension_of(filename: str | None) -> str | None:
    if not filename:
        return None
    base = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    stem, dot, ext = base.rpartition(".")
    if not dot or not stem:
        return None
    ext = ext.lower().strip()
    if not ext or len(ext) > 16:
        return None
    # Keep the reason strings ASCII-safe for HTTP headers and logs.
    if not ext.isascii() or not ext.isalnum():
        return None
    return f".{ext}"


def classify_attachment(
    filename: str | None,
    declared_content_type: str | None,
    data: bytes,
) -> AttachmentSafety:
    """Classify one attachment from its bytes, display name and declared MIME.

    Never raises, never executes content, never logs. ``data`` is the stored
    byte sequence (only a prefix is inspected).
    """
    prefix = data[:_SNIFF_BYTES]
    ext = _extension_of(filename)
    mime = (declared_content_type or "").split(";", 1)[0].strip().lower() or None

    sig = _detect_signature(prefix)
    if sig is None and _looks_like_html(prefix):
        sig = _Signature("html", "HTML document", False, b"")
    if sig is None and _looks_like_text(prefix):
        sig = _Signature("text", "plain text", False, b"")

    # 1) Executable content is always flagged, whatever the name claims.
    if sig is not None and sig.executable:
        reasons = [f"content starts with {sig.label} signature"]
        if ext is not None and ext not in _EXT_EXPECT:
            reasons.append(f"filename extension '{ext}' is not a known program extension")
        ext_expect = _EXT_EXPECT.get(ext or "")
        if ext_expect is not None and sig.kind not in ext_expect:
            reasons.append(f"filename extension '{ext}' does not match {sig.kind} content")
        mime_expect = _MIME_EXPECT.get(mime or "")
        if mime_expect is not None and sig.kind not in mime_expect:
            reasons.append(f"declared MIME '{mime}' does not match {sig.kind} content")
        return AttachmentSafety(SafetyCategory.EXECUTABLE, True, sig.kind, reasons)

    # 2) No recognized signature: cannot vouch for it.
    if sig is None:
        reasons = ["no recognized file signature; type cannot be verified"]
        if ext is not None:
            reasons.append(f"filename claims extension '{ext}'")
        if mime is not None:
            reasons.append(f"declared MIME is '{mime}'")
        reasons.append("unknown content is not asserted safe")
        return AttachmentSafety(SafetyCategory.UNKNOWN, True, None, reasons)

    # 3) Known benign signature: check name/MIME claims against it.
    reasons = [f"content identified as {sig.label}"]
    mismatches: list[str] = []
    if ext is not None:
        ext_expect = _EXT_EXPECT.get(ext)
        if ext_expect is None:
            reasons.append(f"extension '{ext}' is outside the classification rules")
        elif sig.kind not in ext_expect:
            mismatches.append(f"filename extension '{ext}' implies {sorted(ext_expect)} but content is {sig.kind}")
    mime_expect = _MIME_EXPECT.get(mime or "")
    if mime_expect is not None and sig.kind not in mime_expect:
        mismatches.append(f"declared MIME '{mime}' implies {sorted(mime_expect)} but content is {sig.kind}")

    if mismatches:
        return AttachmentSafety(SafetyCategory.MISMATCH, True, sig.kind, reasons + mismatches)
    reasons.append("signature, filename and declared MIME agree")
    return AttachmentSafety(SafetyCategory.MATCHED, False, sig.kind, reasons)
