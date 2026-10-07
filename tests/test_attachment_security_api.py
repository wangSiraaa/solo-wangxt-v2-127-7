"""API-level tests for attachment security classification and rescan."""
from __future__ import annotations

import logging

from conftest import SAMPLES


def _post(client, name, data, **params):
    return client.post(
        "/ingest",
        files={"file": (name, data, "message/rfc822")},
        params=params,
    )


def _by_name(attachments, name):
    return next(a for a in attachments if a["filename"] == name)


def test_masquerade_sample_classifications(client):
    c, _ = client
    r = _post(c, "10_masquerade.eml", (SAMPLES / "10_masquerade.eml").read_bytes())
    assert r.status_code == 201, r.text
    atts = r.json()["attachments"]

    exe = _by_name(atts, "notes.txt")
    assert exe["security"]["category"] == "executable"
    assert exe["security"]["detected_signature"] == "dos_pe_mz"
    rules = {e["rule"] for e in exe["security"]["evidence"]}
    assert {"declared:mime", "declared:extension", "magic:dos_pe_mz",
            "conflict:extension", "conflict:mime"} <= rules

    jpg = _by_name(atts, "photo.jpg")
    assert jpg["security"]["category"] == "mismatch"
    assert jpg["security"]["detected_signature"] == "png"

    blob = _by_name(atts, "data.bin")
    assert blob["security"]["category"] == "unknown"
    assert blob["security"]["suspicious"] is True
    assert any("NOT asserted safe" in e["detail"] for e in blob["security"]["evidence"])

    txt = _by_name(atts, "readme.txt")
    assert txt["security"]["category"] == "consistent"
    assert txt["security"]["suspicious"] is False


def test_same_filename_different_content_gets_separate_classification(client):
    c, _ = client
    r = _post(c, "10_masquerade.eml", (SAMPLES / "10_masquerade.eml").read_bytes())
    atts = r.json()["attachments"]
    assert _by_name(atts, "notes.txt")["security"]["category"] == "executable"
    assert _by_name(atts, "readme.txt")["security"]["category"] == "consistent"


def test_message_detail_carries_security_with_evidence(client):
    c, _ = client
    body = _post(c, "10_masquerade.eml",
                 (SAMPLES / "10_masquerade.eml").read_bytes()).json()
    pk = body["message_pk"]
    msg = c.get(f"/messages/{pk}").json()
    exe = _by_name(msg["attachments"], "notes.txt")
    assert exe["security"]["category"] == "executable"
    assert exe["security"]["declared_mime"] == "text/plain"
    assert exe["security"]["declared_extension"] == "txt"
    assert exe["security"]["classifier_version"]
    assert exe["security"]["evidence"]


def test_review_queue_filters(client):
    c, _ = client
    _post(c, "10_masquerade.eml", (SAMPLES / "10_masquerade.eml").read_bytes())

    review = c.get("/attachments", params={"suspicious": "true"}).json()
    cats = {a["security"]["category"] for a in review["results"]}
    assert {"executable", "mismatch", "unknown"} <= cats
    assert "consistent" not in cats

    consistent = c.get("/attachments", params={"suspicious": "false"}).json()
    assert all(a["security"]["category"] == "consistent" for a in consistent["results"])

    exe_only = c.get("/attachments", params={"category": "executable"}).json()
    assert exe_only["count"] == 1
    assert exe_only["results"][0]["filename"] == "notes.txt"

    unknown_only = c.get("/attachments", params={"category": "unknown"}).json()
    assert {a["filename"] for a in unknown_only["results"]} == {"data.bin"}

    bad = c.get("/attachments", params={"category": "bogus"})
    assert bad.status_code == 422


def test_download_advises_but_does_not_refuse(client):
    c, _ = client
    body = _post(c, "10_masquerade.eml",
                 (SAMPLES / "10_masquerade.eml").read_bytes()).json()
    pk = body["message_pk"]
    atts = c.get(f"/messages/{pk}").json()["attachments"]

    exe = _by_name(atts, "notes.txt")
    dl = c.get(f"/messages/{pk}/attachments/{exe['id']}/download")
    assert dl.status_code == 200  # forensic access is preserved
    assert dl.headers["X-Attachment-Security"] == "executable"
    assert "Warning" in dl.headers and "executable" in dl.headers["Warning"]
    assert dl.headers["X-Content-Type-Options"] == "nosniff"
    assert dl.headers["X-Attachment-Detected-Signature"] == "dos_pe_mz"

    ok = _by_name(atts, "readme.txt")
    dl_ok = c.get(f"/messages/{pk}/attachments/{ok['id']}/download")
    assert dl_ok.status_code == 200
    assert dl_ok.headers["X-Attachment-Security"] == "consistent"
    assert "Warning" not in dl_ok.headers


def test_rescan_backfills_legacy_rows_without_touching_bytes(client):
    c, arch = client
    body = _post(c, "10_masquerade.eml",
                 (SAMPLES / "10_masquerade.eml").read_bytes()).json()
    pk = body["message_pk"]
    atts = c.get(f"/messages/{pk}").json()["attachments"]
    exe = _by_name(atts, "notes.txt")
    blob = _by_name(atts, "data.bin")

    # Simulate pre-classifier legacy rows.
    for row in arch.repo.attachments:
        if row["id"] in (exe["id"], blob["id"]):
            for key in ("security_category", "security_detected_sig",
                        "security_detected_mime", "security_evidence",
                        "security_classifier", "security_inspected",
                        "security_classified_at"):
                row[key] = None

    # Legacy rows show up in the review queue and download with a warning.
    queue = c.get("/attachments", params={"suspicious": "true"}).json()
    assert queue["count"] >= 2
    dl = c.get(f"/messages/{pk}/attachments/{exe['id']}/download")
    assert "unclassified" in dl.headers["Warning"]

    stored_path = arch.repo.get_attachment(exe["id"])["storage_path"]
    before = arch.attachment_storage.resolve(stored_path).read_bytes()

    report = c.post("/attachments/rescan").json()
    assert report["read_only"] is True
    assert report["newly_classified"] == 2
    cats = {i["attachment_id"]: i["category"] for i in report["items"]}
    assert cats[exe["id"]] == "executable"
    assert cats[blob["id"]] == "unknown"
    for item in report["items"]:
        assert item["storage_path"] and item["sha256"]

    # Evidence + path stay traceable after refresh.
    refreshed = arch.repo.get_attachment(exe["id"])
    assert refreshed["security"]["category"] == "executable"
    assert refreshed["security"]["detected_signature"] == "dos_pe_mz"
    assert refreshed["storage_path"] == stored_path
    assert any(e["rule"] == "magic:dos_pe_mz" for e in refreshed["security"]["evidence"])

    # Bytes on disk unchanged.
    after = arch.attachment_storage.resolve(stored_path).read_bytes()
    assert before == after

    # A second rescan of everything changes nothing.
    again = c.post("/attachments/rescan",
                   params={"only_unclassified": "false"}).json()
    assert again["unchanged"] >= 4 and again["changed"] == 0
    assert again["newly_classified"] == 0


def test_rescan_skips_checksum_mismatch_and_preserves_old_verdict(client):
    c, arch = client
    body = _post(c, "10_masquerade.eml",
                 (SAMPLES / "10_masquerade.eml").read_bytes()).json()
    pk = body["message_pk"]
    exe = _by_name(c.get(f"/messages/{pk}").json()["attachments"], "notes.txt")

    # Tamper with the on-disk bytes directly (content-addressed file).
    row = arch.repo.get_attachment(exe["id"])
    path = arch.attachment_storage.resolve(row["storage_path"])
    path.write_bytes(b"completely different bytes after tampering")

    report = c.post("/attachments/rescan",
                    params={"only_unclassified": "false"}).json()
    skip = next(s for s in report["skipped"] if s["attachment_id"] == exe["id"])
    assert skip["reason"] == "checksum_mismatch"
    assert skip["actual_sha256"] != skip["recorded_sha256"]

    kept = arch.repo.get_attachment(exe["id"])
    assert kept["security"]["category"] == "executable"  # old verdict preserved


def test_rescan_marks_backfilled_timestamp(client):
    from datetime import datetime

    c, arch = client
    _post(c, "10_masquerade.eml", (SAMPLES / "10_masquerade.eml").read_bytes())
    rows = arch.repo.attachments
    for row in rows:
        row["security_category"] = None
        row["security_detected_sig"] = None
        row["security_detected_mime"] = None
        row["security_evidence"] = None
        row["security_classifier"] = None
        row["security_inspected"] = None
        row["security_classified_at"] = None
    c.post("/attachments/rescan")
    assert all(isinstance(r["security_classified_at"], datetime) for r in rows)


def test_classification_logs_never_contain_attachment_bytes(client, caplog):
    c, _ = client
    marker = b"MZ\x90\x00"
    with caplog.at_level(logging.INFO):
        _post(c, "10_masquerade.eml", (SAMPLES / "10_masquerade.eml").read_bytes())
        c.post("/attachments/rescan", params={"only_unclassified": "false"})
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert "MZ" not in blob.replace("dos_pe_mz", "")  # rule id is metadata
    assert marker.decode("latin-1") not in blob
    assert "ordinary text file" not in blob
