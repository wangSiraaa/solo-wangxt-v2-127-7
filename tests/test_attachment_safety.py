"""Attachment safety classification: unit tests + API acceptance tests.

Acceptance covered here:
* an executable signature disguised as ``.txt`` is flagged;
* same filename with different content is classified per-content;
* after a rescan ("refresh"), classification and evidence path stay traceable;
* ordinary logs never contain attachment bytes;
* downloads carry warnings but are never refused.
"""
from __future__ import annotations

import logging
from email.message import EmailMessage

import pytest

from app.attachment_security import (
    CLASSIFIER_VERSION,
    SafetyCategory,
    classify_attachment,
)

MZ_PAYLOAD = b"MZ" + b"\x90" * 30 + b"PE\x00\x00" + b"\xde\xad\xbe\xef" * 8
TEXT_PAYLOAD = b"Meeting notes: nothing executable here.\nSecond line.\n"
UNKNOWN_PAYLOAD = bytes(range(1, 255)) * 4  # binary, matches no signature


def _eml_with_attachment(filename: str, payload: bytes, mime: str = "text/plain") -> bytes:
    msg = EmailMessage()
    msg["From"] = "archivist@example.com"
    msg["To"] = "evidence@example.com"
    msg["Subject"] = f"evidence: {filename}"
    msg["Message-ID"] = f"<{filename.replace(' ', '_')}-id@example.com>"
    msg.set_content("See attached.\n")
    maintype, _, subtype = mime.partition("/")
    msg.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
    return msg.as_bytes()


def _post(client, name, data):
    return client.post("/ingest", files={"file": (name, data, "message/rfc822")})


# ---- classifier unit tests -------------------------------------------------
def test_executable_disguised_as_txt_is_flagged():
    v = classify_attachment("notes.txt", "text/plain", MZ_PAYLOAD)
    assert v.category is SafetyCategory.EXECUTABLE
    assert v.suspicious
    assert v.detected_signature == "pe-mz"
    assert any(".txt" in r for r in v.reasons)  # disguise is part of the evidence
    assert v.classifier_version == CLASSIFIER_VERSION


def test_elf_and_script_signatures_flagged():
    elf = classify_attachment("run", "application/octet-stream", b"\x7fELF" + b"\x00" * 64)
    assert elf.category is SafetyCategory.EXECUTABLE
    script = classify_attachment("deploy.txt", "text/plain", b"#!/bin/sh\nrm -rf /\n")
    assert script.category is SafetyCategory.EXECUTABLE


def test_honest_executable_still_flagged_but_not_mismatch():
    v = classify_attachment("tool.exe", "application/x-msdownload", MZ_PAYLOAD)
    assert v.category is SafetyCategory.EXECUTABLE
    assert v.suspicious  # executables are always called out


def test_matching_types_are_clean():
    v = classify_attachment("readme.txt", "text/plain", TEXT_PAYLOAD)
    assert v.category is SafetyCategory.MATCHED
    assert not v.suspicious
    pdf = classify_attachment("doc.pdf", "application/pdf", b"%PDF-1.7\n...")
    assert pdf.category is SafetyCategory.MATCHED


def test_benign_content_wrong_name_is_mismatch():
    v = classify_attachment("picture.txt", "text/plain", b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    assert v.category is SafetyCategory.MISMATCH
    assert v.suspicious
    assert v.detected_signature == "png"


def test_unknown_content_is_not_asserted_safe():
    v = classify_attachment("data.bin", "application/octet-stream", UNKNOWN_PAYLOAD)
    assert v.category is SafetyCategory.UNKNOWN
    assert v.suspicious  # unknown is never called safe
    assert any("not asserted safe" in r for r in v.reasons)


def test_same_name_different_content_classified_separately():
    a = classify_attachment("report.txt", "text/plain", TEXT_PAYLOAD)
    b = classify_attachment("report.txt", "text/plain", MZ_PAYLOAD)
    assert a.category is SafetyCategory.MATCHED
    assert b.category is SafetyCategory.EXECUTABLE


def test_classifier_never_raises_on_edge_inputs():
    for data in (b"", b"\x00", b"MZ", TEXT_PAYLOAD):
        v = classify_attachment(None, None, data)
        assert isinstance(v.category, SafetyCategory)


# ---- API / ingest flow -----------------------------------------------------
def test_ingest_flags_disguised_executable_and_filter_finds_it(client):
    c, _ = client
    r = _post(c, "evil.eml", _eml_with_attachment("invoice.txt", MZ_PAYLOAD))
    assert r.status_code == 201, r.text
    att = r.json()["attachments"][0]
    assert att["safety_category"] == "executable"
    assert att["suspicious"] is True
    assert att["detected_signature"] == "pe-mz"
    assert att["safety_reasons"]

    pk = r.json()["message_pk"]
    detail = c.get(f"/messages/{pk}").json()["attachments"][0]
    assert detail["safety_category"] == "executable"
    assert detail["classifier_version"]
    assert detail["classified_at"]
    # original name + declared MIME preserved for forensics
    assert detail["filename"] == "invoice.txt"
    assert detail["content_type"] == "text/plain"

    suspicious = c.get("/attachments", params={"suspicious": True}).json()
    assert any(a["id"] == detail["id"] for a in suspicious)
    executables = c.get("/attachments", params={"category": "executable"}).json()
    assert any(a["id"] == detail["id"] for a in executables)
    clean = c.get("/attachments", params={"suspicious": False}).json()
    assert all(a["id"] != detail["id"] for a in clean)
    assert c.get("/attachments", params={"category": "bogus"}).status_code == 422


def test_download_warns_but_does_not_refuse(client):
    c, _ = client
    r = _post(c, "evil.eml", _eml_with_attachment("invoice.txt", MZ_PAYLOAD))
    pk = r.json()["message_pk"]
    meta = c.get(f"/messages/{pk}").json()["attachments"][0]
    dl = c.get(f"/messages/{pk}/attachments/{meta['id']}/download")
    assert dl.status_code == 200  # legitimate forensics not blocked
    assert dl.content == MZ_PAYLOAD  # bytes served verbatim
    assert dl.headers["x-attachment-safety-category"] == "executable"
    assert dl.headers["x-attachment-suspicious"] == "true"
    assert "pe-mz" in dl.headers["x-attachment-safety-warning"] or "executable" in dl.headers["x-attachment-safety-warning"]
    assert dl.headers["x-content-type-options"] == "nosniff"


def test_clean_download_has_no_warning(client):
    c, _ = client
    r = _post(c, "ok.eml", _eml_with_attachment("notes.txt", TEXT_PAYLOAD))
    pk = r.json()["message_pk"]
    meta = c.get(f"/messages/{pk}").json()["attachments"][0]
    assert meta["safety_category"] == "matched"
    dl = c.get(f"/messages/{pk}/attachments/{meta['id']}/download")
    assert dl.status_code == 200
    assert dl.headers["x-attachment-suspicious"] == "false"
    assert "x-attachment-safety-warning" not in dl.headers


def test_same_filename_different_content_stored_and_classified_separately(client):
    c, _ = client
    r1 = _post(c, "a.eml", _eml_with_attachment("report.txt", TEXT_PAYLOAD))
    r2 = _post(c, "b.eml", _eml_with_attachment("report.txt", MZ_PAYLOAD))
    a1 = r1.json()["attachments"][0]
    a2 = r2.json()["attachments"][0]
    assert a1["filename"] == a2["filename"] == "report.txt"
    assert a1["safety_category"] == "matched"
    assert a2["safety_category"] == "executable"
    assert a1["sha256"] != a2["sha256"]
    assert a1["storage_path"] != a2["storage_path"]


def test_rescan_backfills_legacy_rows_without_touching_bytes(client):
    c, arch = client
    r = _post(c, "evil.eml", _eml_with_attachment("invoice.txt", MZ_PAYLOAD))
    pk = r.json()["message_pk"]
    meta = c.get(f"/messages/{pk}").json()["attachments"][0]
    path_before = meta["storage_path"]
    sha_before = meta["checksum_sha256"]
    bytes_before = arch.attachment_storage.resolve(path_before).read_bytes()

    # Simulate a legacy row from before classification existed.
    for row in arch.repo.attachments:
        row.update(
            safety_category=None,
            suspicious=False,
            detected_signature=None,
            safety_reasons=[],
            classifier_version=None,
            classified_at=None,
        )
    legacy = c.get(f"/messages/{pk}").json()["attachments"][0]
    assert legacy["safety_category"] is None

    rescan = c.post("/attachments/rescan").json()
    assert rescan["updated"] >= 1
    assert rescan["digest_mismatch"] == 0

    after = c.get(f"/messages/{pk}").json()["attachments"][0]
    # classification restored and evidence path still traceable
    assert after["safety_category"] == "executable"
    assert after["suspicious"] is True
    assert after["storage_path"] == path_before
    assert after["checksum_sha256"] == sha_before
    assert after["classifier_version"]
    assert arch.attachment_storage.resolve(after["storage_path"]).read_bytes() == bytes_before


def test_rescan_reports_digest_mismatch_without_relabeling(client):
    c, arch = client
    r = _post(c, "ok.eml", _eml_with_attachment("notes.txt", TEXT_PAYLOAD))
    pk = r.json()["message_pk"]
    meta = c.get(f"/messages/{pk}").json()["attachments"][0]
    # corrupt the stored evidence out from under the archive
    evidence = arch.attachment_storage.resolve(meta["storage_path"])
    evidence.write_bytes(b"tampered")
    rescan = c.post("/attachments/rescan").json()
    assert rescan["digest_mismatch"] == 1
    after = c.get(f"/messages/{pk}").json()["attachments"][0]
    assert after["safety_category"] == "matched"  # not relabeled from bad bytes


def test_attachment_bytes_not_in_logs_during_ingest_and_rescan(client, caplog):
    c, _ = client
    marker = MZ_PAYLOAD  # distinctive binary content
    with caplog.at_level(logging.DEBUG):
        _post(c, "evil.eml", _eml_with_attachment("invoice.txt", marker))
        pk = c.get("/messages").json()[0]["id"]
        meta = c.get(f"/messages/{pk}").json()["attachments"][0]
        c.get(f"/messages/{pk}/attachments/{meta['id']}/download")
        c.post("/attachments/rescan")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "MZ" not in text
    assert marker.hex() not in text
    # but the suspicious verdict itself is auditable in logs
    assert any("suspicious attachment" in r.getMessage() for r in caplog.records)


def test_unknown_attachment_listed_as_suspicious(client):
    c, _ = client
    r = _post(c, "blob.eml", _eml_with_attachment("payload.dat", UNKNOWN_PAYLOAD, "application/octet-stream"))
    att = r.json()["attachments"][0]
    assert att["safety_category"] == "unknown"
    assert att["suspicious"] is True
    unknowns = c.get("/attachments", params={"category": "unknown"}).json()
    assert len(unknowns) == 1
