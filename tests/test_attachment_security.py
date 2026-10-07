"""Unit tests for the finite attachment signature/extension classifier."""
from __future__ import annotations

import pytest

from app.parser.attachment_security import (
    CLASSIFIER_VERSION,
    AttachmentCategory,
    classify_attachment,
)

C = AttachmentCategory


def _cat(data, mime=None, filename=None, charset=None):
    return classify_attachment(data, declared_mime=mime, filename=filename, declared_charset=charset)


# -- executables -----------------------------------------------------------
def test_pe_disguised_as_txt_is_executable_with_masquerade_evidence():
    sec = _cat(b"MZ\x90\x00" + b"\x00" * 40, "text/plain", "notes.txt")
    assert sec.category == C.EXECUTABLE.value
    assert sec.suspicious is True
    assert sec.detected_signature == "dos_pe_mz"
    rules = {e.rule for e in sec.evidence}
    assert "magic:dos_pe_mz" in rules
    assert "conflict:extension" in rules  # executable hidden behind .txt
    assert "conflict:mime" in rules


def test_honest_pe_also_flagged_without_conflict():
    sec = _cat(b"MZ\x90\x00rest", "application/x-msdownload", "tool.exe")
    assert sec.category == C.EXECUTABLE.value
    rules = {e.rule for e in sec.evidence}
    assert "conflict:extension" not in rules
    assert "conflict:mime" not in rules


@pytest.mark.parametrize(
    "magic,sig",
    [
        (b"\x7fELF\x02\x01", "elf"),
        (b"\xfe\xed\xfa\xce\x00", "mach_o"),
        (b"\xca\xfe\xba\xbe\x00", "java_class"),
        (b"dex\n035\x00", "dex"),
        (b"#!/bin/sh\necho hi\n", "shebang"),
        (b"#!/usr/bin/env python3\nprint(1)\n", "shebang"),
    ],
)
def test_executable_signatures(magic, sig):
    sec = _cat(magic, "text/plain", "innocent.txt")
    assert sec.category == C.EXECUTABLE.value
    assert sec.detected_signature == sig


def test_shebang_requires_first_line():
    # leading bytes before #! means it is not an interpreter directive
    sec = _cat(b"padding #!/bin/sh\n", "text/plain", "notes.txt")
    assert sec.category != C.EXECUTABLE.value


def test_script_extension_flagged_even_as_plain_text():
    sec = _cat(b"@echo off\r\nformat c:\r\n", "application/octet-stream", "go.bat")
    assert sec.category == C.EXECUTABLE.value
    assert any(e.rule == "decision:executable-extension" for e in sec.evidence)


def test_declared_executable_mime_flagged_without_signature():
    sec = _cat(b"plain-looking bytes", "application/x-sharedlib", "lib.bin")
    assert sec.category == C.EXECUTABLE.value


# -- mismatches ------------------------------------------------------------
def test_png_bytes_named_jpg_is_mismatch():
    sec = _cat(b"\x89PNG\r\n\x1a\nrest", "image/jpeg", "photo.jpg")
    assert sec.category == C.MISMATCH.value
    assert sec.detected_signature == "png"
    assert sec.detected_mime == "image/png"
    assert any(e.rule == "conflict:mime" for e in sec.evidence)
    assert any(e.rule == "conflict:extension" for e in sec.evidence)


def test_text_declared_as_pdf_is_mismatch():
    sec = _cat(b"just words\n", "application/pdf", "report.pdf")
    assert sec.category == C.MISMATCH.value
    assert sec.detected_signature == "text:plain"


def test_zip_family_extensions_are_consistent():
    sec = _cat(b"PK\x03\x04binzip", "application/zip", "bundle.zip")
    assert sec.category == C.CONSISTENT.value
    sec_docx = _cat(
        b"PK\x03\x04binzip",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "doc.docx",
    )
    assert sec_docx.category == C.CONSISTENT.value


@pytest.mark.parametrize("mime,ext,magic", [
    ("application/pdf", "a.pdf", b"%PDF-1.7\nbody"),
    ("image/png", "a.png", b"\x89PNG\r\n\x1a\nxx"),
    ("image/gif", "a.gif", b"GIF89afake"),
    ("image/jpeg", "a.jpg", b"\xff\xd8\xff\xe0junk"),
    ("application/gzip", "a.gz", b"\x1f\x8b\x08junk"),
    ("application/vnd.rar", "a.rar", b"Rar!\x1a\x07\x00junk"),
    ("application/x-7z-compressed", "a.7z", b"7z\xbc\xaf\x27\x1cjunk"),
])
def test_recognized_honest_types_are_consistent(mime, ext, magic):
    assert _cat(magic, mime, ext).category == C.CONSISTENT.value


# -- unknown is never called safe -----------------------------------------
def test_unrecognized_blob_is_unknown_not_consistent():
    sec = _cat(bytes((i * 31 + 7) % 256 for i in range(256)),
               "application/octet-stream", "data.bin")
    assert sec.category == C.UNKNOWN.value
    assert sec.suspicious is True
    assert sec.detected_signature is None
    assert any("NOT asserted safe" in e.detail for e in sec.evidence)


def test_unrecognized_blob_with_typed_claim_is_unknown():
    sec = _cat(bytes(range(256)), "application/pdf", "claim.pdf")
    assert sec.category == C.UNKNOWN.value
    assert any(e.rule == "decision:unconfirmed-claim" for e in sec.evidence)


def test_empty_part_is_unknown():
    assert _cat(b"", "application/octet-stream", "x.dat").category == C.UNKNOWN.value
    assert _cat(b"", "text/plain", "x.txt").category == C.UNKNOWN.value


# -- text heuristics -------------------------------------------------------
def test_plain_text_consistent_with_text_types():
    sec = _cat(b"hello world\nsecond line\n", "text/plain", "a.txt")
    assert sec.category == C.CONSISTENT.value
    assert sec.detected_signature == "text:plain"


def test_generic_mime_makes_no_claim_so_text_is_consistent():
    sec = _cat(b"hello", "application/octet-stream", "notes.txt")
    assert sec.category == C.CONSISTENT.value


def test_binary_control_bytes_are_not_text():
    assert _cat(b"abc\x00def", "text/plain", "a.txt").category == C.UNKNOWN.value


def test_utf8_bom_text_detected():
    sec = _cat(b"\xef\xbb\xbfhello", "application/octet-stream", "a.txt")
    assert sec.category == C.CONSISTENT.value
    assert any("UTF-8 BOM" in e.detail for e in sec.evidence)


def test_declared_charset_allows_text_detection():
    payload = "这是中文正文\n".encode("gb18030")
    sec = _cat(payload, "text/plain", "a.txt", charset="gb18030")
    assert sec.category == C.CONSISTENT.value


def test_gbk_without_charset_hint_is_honestly_unknown_not_mismatch():
    # The finite text rule only validates declared/BOM/UTF-8 decodes; unknown
    # legacy encodings must not be rubber-stamped, but nor is a typed claim
    # contradicted, so this lands in unknown rather than mismatch.
    payload = "这是中文正文\n".encode("gb18030")
    sec = _cat(payload, "text/plain", "a.txt")
    assert sec.category == C.UNKNOWN.value


def test_xml_and_html_text_markers():
    assert _cat(b"<?xml version='1.0'?><a/>", "application/xml", "a.xml").category == C.CONSISTENT.value
    assert _cat(b"<html><body>x</body></html>", "text/html", "a.html").category == C.CONSISTENT.value


# -- evidence / provenance -------------------------------------------------
def test_evidence_preserves_declared_name_mime_and_basis():
    sec = _cat(b"MZxx", "text/plain; charset=utf-8", "notes.txt")
    assert sec.declared_mime == "text/plain"
    assert sec.declared_extension == "txt"
    rules = [e.rule for e in sec.evidence]
    assert rules[0] == "declared:mime"
    assert rules[1] == "declared:extension"
    assert any(e.rule == "inspection:scope" and CLASSIFIER_VERSION in e.detail
               and "not executed" in e.detail for e in sec.evidence)
    assert sec.classifier_version == CLASSIFIER_VERSION


def test_inspection_is_bounded_to_prefix():
    # ISO9660 marker at 0x8001 is the furthest supported offset, and it is
    # still inside the 64 KiB inspection window.
    data = b"\x00" * 0x8001 + b"CD001" + b"\x00" * (70 * 1024)
    sec = _cat(data, "application/x-iso9660-image", "disc.iso")
    assert sec.detected_signature == "iso9660"
    assert sec.inspected_bytes == 64 * 1024
    assert sec.category == C.CONSISTENT.value


def test_classifier_is_pure_and_deterministic():
    data = b"\x89PNG\r\n\x1a\nx"
    a = _cat(data, "image/jpeg", "x.jpg")
    b = _cat(data, "image/jpeg", "x.jpg")
    assert a == b
    # evidence is rule-based text, never a dump of payload bytes
    for e in a.evidence:
        assert isinstance(e.rule, str) and isinstance(e.detail, str)
        assert "\\x89" not in e.detail


def test_same_filename_different_content_classified_separately():
    name = "notes.txt"
    exe = _cat(b"MZ\x90\x00junk", "text/plain", name)
    txt = _cat(b"plain harmless text\n", "text/plain", name)
    assert exe.category == C.EXECUTABLE.value
    assert txt.category == C.CONSISTENT.value
