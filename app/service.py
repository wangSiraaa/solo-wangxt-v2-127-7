"""Application services: orchestrate parse, controlled storage, persistence."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any

from app.attachment_security import classify_attachment
from app.parser import ParseStatus, parse_eml
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
            # Classify from the in-memory bytes *before* they are released.
            # The classifier only reads a prefix; content is never executed.
            att.safety = classify_attachment(att.filename, att.content_type, att.bytes_to_persist)
            if att.safety.suspicious:
                # Metadata only — attachment bytes never enter a log line.
                log.warning(
                    "suspicious attachment part=%s name=%r content_type=%s category=%s "
                    "signature=%s bytes=%d sha256=%s",
                    att.mime_path,
                    att.filename,
                    att.content_type,
                    att.safety.category.value,
                    att.safety.detected_signature,
                    att.byte_size,
                    att.checksum_sha256,
                )
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
                        "safety_category": att.safety.category.value,
                        "suspicious": att.safety.suspicious,
                        "detected_signature": att.safety.detected_signature,
                        "safety_reasons": list(att.safety.reasons),
                    }
                )
                continue
            stored.append((att, rel))
            att.storage_path = rel
            att.bytes_to_persist = None  # free memory; bytes are on disk now
            att_summaries.append(
                {
                    "mime_path": att.mime_path,
                    "filename": att.filename,
                    "content_type": att.content_type,
                    "stored": True,
                    "storage_path": rel,
                    "byte_size": att.byte_size,
                    "sha256": att.checksum_sha256,
                    "safety_category": att.safety.category.value,
                    "suspicious": att.safety.suspicious,
                    "detected_signature": att.safety.detected_signature,
                    "safety_reasons": list(att.safety.reasons),
                }
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

    def rescan_attachment_safety(self, *, batch_size: int = 200) -> dict[str, Any]:
        """Re-classify stored attachments without touching their bytes.

        Read-only with respect to evidence: bytes are read back from the
        controlled store, verified against the recorded sha256, classified,
        and only the classification columns are updated. Files whose digest
        no longer matches the recorded checksum are reported, not re-labeled.
        """
        scanned = updated = missing_bytes = digest_mismatch = 0
        offset = 0
        while True:
            rows = self._repo.list_attachments(
                suspicious=None, category=None, limit=batch_size, offset=offset
            )
            if not rows:
                break
            offset += len(rows)
            for row in rows:
                rel = row.get("storage_path")
                if not rel:
                    continue  # never stored (or failed) — nothing to rescan
                try:
                    path = self._att.resolve(rel)
                except StorageError:
                    log.error("rescan skipped id=%s: stored path rejected", row.get("id"))
                    continue
                if not path.is_file():
                    missing_bytes += 1
                    log.warning(
                        "rescan: bytes missing id=%s sha256=%s relpath=%s",
                        row.get("id"),
                        row.get("checksum_sha256"),
                        rel,
                    )
                    continue
                data = path.read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                recorded = row.get("checksum_sha256")
                if recorded and digest != recorded:
                    # Evidence integrity problem: surface it, do not relabel.
                    digest_mismatch += 1
                    log.error(
                        "rescan digest mismatch id=%s recorded=%s actual=%s relpath=%s",
                        row.get("id"),
                        recorded,
                        digest,
                        rel,
                    )
                    continue
                verdict = classify_attachment(row.get("filename"), row.get("content_type"), data)
                self._repo.update_attachment_safety(row["id"], verdict)
                scanned += 1
                updated += 1
        result = {
            "scanned": scanned,
            "updated": updated,
            "missing_bytes": missing_bytes,
            "digest_mismatch": digest_mismatch,
        }
        # Metadata only — never log content.
        log.info("attachment safety rescan complete: %s", result)
        return result
