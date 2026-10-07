"""Application services: orchestrate parse, controlled storage, persistence."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.parser import ParseStatus, parse_eml
from app.parser.attachment_security import classify_attachment, security_to_json
from app.repository import Repository
from app.storage import ControlledStorage, StorageError

log = logging.getLogger("emlarchive.service")


@dataclass
class IngestResult:
    ingest_id: int
    message_pk: int | None
    status: str
    raw_sha256: str
    raw_size: int
    defects_count: int
    fatal_error: str | None
    attachments: list[dict[str, Any]]
    threads: dict[str, Any]


class IngestService:
    def __init__(self, repo: Repository, raw_storage: ControlledStorage, attachment_storage: ControlledStorage) -> None:
        self._repo = repo
        self._raw = raw_storage
        self._att = attachment_storage

    def ingest(self, data: bytes, *, source_name: str | None = None, recompute_threads: bool = True) -> IngestResult:
        # Parse first so even catastrophic failures have a digest.
        parsed = parse_eml(data)

        raw_relpath: str | None = None
        if parsed.status is not ParseStatus.FAILED:
            try:
                _, raw_relpath = self._raw.store_raw(data)
            except Exception as exc:  # storage failure must not be swallowed
                log.error("raw eml storage failed sha256=%s: %s", parsed.raw_sha256, exc)
                raise

        stored: list[tuple[Any, str]] = []
        att_summaries: list[dict[str, Any]] = []
        for att in parsed.attachments:
            if att.bytes_to_persist is None:
                continue
            try:
                rel = self._att.store_attachment(
                    att.bytes_to_persist,
                    att.checksum_sha256,
                    att.filename,
                )
            except Exception as exc:
                # Keep parse metadata but mark the attachment as not stored so
                # the failure is locatable; never log bytes.
                log.error(
                    "attachment storage failed part=%s content_type=%s bytes=%d sha256=%s: %s",
                    att.mime_path,
                    att.content_type,
                    att.byte_size,
                    att.checksum_sha256,
                    exc,
                )
                att_summaries.append(
                    {
                        "mime_path": att.mime_path,
                        "filename": att.filename,
                        "stored": False,
                        "error": str(exc),
                        "byte_size": att.byte_size,
                        "security": security_to_json(att.security),
                    }
                )
                continue
            stored.append((att, rel))
            att.storage_path = rel
            att.bytes_to_persist = None  # free memory; bytes are on disk now
            summary = {
                "mime_path": att.mime_path,
                "filename": att.filename,
                "content_type": att.content_type,
                "stored": True,
                "storage_path": rel,
                "byte_size": att.byte_size,
                "sha256": att.checksum_sha256,
                "security": security_to_json(att.security),
            }
            att_summaries.append(summary)
            if att.security is not None:
                # Metadata only — never log attachment bytes.
                log.info(
                    "attachment classified id_part=%s category=%s signature=%s sha256=%s relpath=%s",
                    att.mime_path,
                    att.security.category,
                    att.security.detected_signature,
                    att.checksum_sha256,
                    rel,
                )

        saved = self._repo.save_ingest(
            parsed,
            raw_relpath=raw_relpath,
            stored_attachments=stored,
            source_name=source_name,
            status=parsed.status.value,
            fatal_error=parsed.fatal_error,
        )

        threads: dict[str, Any] = {}
        if recompute_threads and saved.get("message_id") is not None:
            threads = self._repo.rebuild_threads()

        return IngestResult(
            ingest_id=saved["ingest_id"],
            message_pk=saved.get("message_id"),
            status=parsed.status.value,
            raw_sha256=parsed.raw_sha256 or "",
            raw_size=parsed.raw_size or len(data),
            defects_count=len(parsed.defects),
            fatal_error=parsed.fatal_error,
            attachments=att_summaries,
            threads=threads,
        )

    # -- read-only attachment rescan ---------------------------------------
    def rescan_attachments(self, *, only_unclassified: bool = True, limit: int | None = None) -> dict[str, Any]:
        """Backfill attachment security classifications without changing bytes.

        Old records carry no classification. This re-reads the stored bytes
        through the storage boundary, verifies their sha256 against the value
        recorded at ingest, and runs the same finite classifier used at
        ingest. The on-disk files are opened read-only; nothing is written to
        the storage root and nothing is executed.
        """
        rows = self._repo.attachments_for_rescan(
            only_unclassified=only_unclassified, limit=limit
        )
        scanned = 0
        classified = 0
        unchanged = 0
        changed = 0
        skipped: list[dict[str, Any]] = []
        items: list[dict[str, Any]] = []

        for row in rows:
            scanned += 1
            rel = row.get("storage_path")
            attachment_id = row["id"]
            if not rel:
                skipped.append({
                    "attachment_id": attachment_id,
                    "reason": "not_stored",
                    "detail": "attachment has no stored bytes (ingest-time storage failure)",
                })
                continue
            try:
                path = self._att.resolve(rel)
            except StorageError as exc:
                log.error("rescan path rejected id=%d: %s", attachment_id, exc)
                skipped.append({
                    "attachment_id": attachment_id,
                    "reason": "invalid_path",
                    "detail": "stored relative path escapes the controlled root",
                })
                continue
            if not path.is_file():
                skipped.append({
                    "attachment_id": attachment_id,
                    "reason": "missing_bytes",
                    "detail": f"stored file absent at {rel}",
                })
                continue

            hasher = hashlib.sha256()
            try:
                with open(path, "rb") as fh:
                    while True:
                        chunk = fh.read(1024 * 1024)
                        if not chunk:
                            break
                        hasher.update(chunk)
                    fh.seek(0)
                    head = fh.read(64 * 1024)
            except OSError as exc:
                skipped.append({
                    "attachment_id": attachment_id,
                    "reason": "read_error",
                    "detail": str(exc),
                })
                continue

            actual_sha = hasher.hexdigest()
            if actual_sha != row.get("checksum_sha256"):
                # Provenance break: never overwrite the original classification
                # with a verdict over bytes that no longer match the record.
                log.error(
                    "rescan integrity mismatch id=%d recorded_sha256=%s actual_sha256=%s",
                    attachment_id, row.get("checksum_sha256"), actual_sha,
                )
                skipped.append({
                    "attachment_id": attachment_id,
                    "reason": "checksum_mismatch",
                    "detail": "stored bytes differ from the sha256 recorded at ingest; "
                              "classification left untouched",
                    "recorded_sha256": row.get("checksum_sha256"),
                    "actual_sha256": actual_sha,
                })
                continue

            sec = classify_attachment(
                head,
                declared_mime=row.get("content_type"),
                filename=row.get("filename"),
                declared_charset=row.get("charset"),
            )
            previous = row.get("security_category")
            self._repo.set_attachment_security(
                attachment_id,
                category=sec.category,
                detected_signature=sec.detected_signature,
                detected_mime=sec.detected_mime,
                evidence=[{"rule": e.rule, "detail": e.detail} for e in sec.evidence],
                classifier_version=sec.classifier_version,
                inspected_bytes=sec.inspected_bytes,
                classified_at=datetime.now(timezone.utc),
            )
            classified += 1
            if previous is None:
                pass  # counted via newly_classified below
            elif previous == sec.category:
                unchanged += 1
            else:
                changed += 1
            items.append({
                "attachment_id": attachment_id,
                "message_pk": row.get("message_pk"),
                "filename": row.get("filename"),
                "category": sec.category,
                "suspicious": sec.suspicious,
                "previous_category": previous,
                "detected_signature": sec.detected_signature,
                "storage_path": rel,
                "sha256": actual_sha,
                "classifier_version": sec.classifier_version,
            })
            log.info(
                "rescan classified attachment id=%d category=%s signature=%s sha256=%s relpath=%s",
                attachment_id, sec.category, sec.detected_signature, actual_sha, rel,
            )

        newly_classified = sum(1 for it in items if it["previous_category"] is None)
        return {
            "scanned": scanned,
            "classified": classified,
            "newly_classified": newly_classified,
            "unchanged": unchanged,
            "changed": changed,
            "skipped": skipped,
            "items": items,
            "read_only": True,
            "only_unclassified": only_unclassified,
        }
