"""In-memory repository mirroring :class:`PgRepository` behavior.

Used by unit tests and by ``EMLARCH_DATABASE_DSN``-less runs. The read shapes
match the PostgreSQL implementation so the API layer sees identical data.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Sequence

from app.parser.attachment_security import (
    REVIEW_CATEGORIES,
    security_from_columns,
    security_to_json,
)
from app.parser.html_sanitizer import escape_html
from app.parser.models import ParsedMessage
from app.threads import ThreadInput, compute_threads


def _addr_json(addrs) -> list[dict[str, Any]]:
    return [asdict(a) for a in addrs]


class MemoryRepository:
    def __init__(self) -> None:
        self.ingests: dict[int, dict[str, Any]] = {}
        self.messages: dict[int, dict[str, Any]] = {}
        self.headers: list[dict[str, Any]] = []
        self.identifiers: list[dict[str, Any]] = []
        self.bodies: list[dict[str, Any]] = []
        self.attachments: list[dict[str, Any]] = []
        self.defects: list[dict[str, Any]] = []
        self.thread_runs: list[dict[str, Any]] = []
        self._ingest_seq = 0
        self._msg_seq = 0
        self._att_seq = 0

    def init_schema(self) -> None:  # nothing to do
        return None

    def save_ingest(
        self,
        parsed: ParsedMessage,
        *,
        raw_relpath: str | None,
        stored_attachments: Sequence[tuple[Any, str]],
        source_name: str | None,
        status: str,
        fatal_error: str | None,
    ) -> dict[str, Any]:
        self._ingest_seq += 1
        ingest_id = self._ingest_seq
        self.ingests[ingest_id] = {
            "id": ingest_id,
            "received_at": datetime.now(timezone.utc),
            "source_name": source_name,
            "status": status,
            "raw_sha256": parsed.raw_sha256,
            "raw_size": parsed.raw_size,
            "raw_path": raw_relpath,
            "fatal_error": fatal_error,
            "defect_count": len(parsed.defects),
        }
        message_pk: int | None = None
        if status != "failed":
            self._msg_seq += 1
            message_pk = self._msg_seq
            self.messages[message_pk] = {
                "id": message_pk,
                "ingest_id": ingest_id,
                "message_id": parsed.message_id,
                "subject": parsed.subject,
                "raw_subject": parsed.raw_subject,
                "date": parsed.date,
                "from_json": _addr_json(parsed.from_),
                "to_json": _addr_json(parsed.to),
                "cc_json": _addr_json(parsed.cc),
                "bcc_json": _addr_json(parsed.bcc),
                "reply_to_json": _addr_json(parsed.reply_to),
                "sender_json": _addr_json(parsed.sender),
                "tree_json": asdict(parsed.tree) if parsed.tree else None,
                "raw_sha256": parsed.raw_sha256,
                "raw_path": raw_relpath,
                "thread_key": None,
                "missing_id": parsed.message_id is None,
            }
            self.headers.extend(
                {
                    "message_id": message_pk,
                    "ordinal": h.ordinal,
                    "name": h.name,
                    "value": h.value,
                    "raw_value": h.raw_value,
                }
                for h in parsed.headers
            )
            if parsed.message_id:
                self.identifiers.append(
                    {"message_pk": message_pk, "kind": "message_id", "value": parsed.message_id, "ordinal": 0}
                )
            self.identifiers.extend(
                {"message_pk": message_pk, "kind": "references", "value": v, "ordinal": i}
                for i, v in enumerate(parsed.references)
            )
            self.identifiers.extend(
                {"message_pk": message_pk, "kind": "in_reply_to", "value": v, "ordinal": i}
                for i, v in enumerate(parsed.in_reply_to)
            )
            for body in parsed.bodies:
                self.bodies.append(
                    {
                        "message_pk": message_pk,
                        "mime_path": body.mime_path,
                        "content_type": body.content_type,
                        "charset": body.charset,
                        "declared_charset": body.declared_charset,
                        "disposition": body.disposition.value,
                        "content_id": body.content_id,
                        "content_location": body.content_location,
                        "byte_size": body.byte_size,
                        "text": body.text if body.content_type == "text/plain" else None,
                        "safe_html": body.safe_html,
                        "escaped_html": escape_html(body.text) if body.content_type == "text/html" else None,
                        "plain_text": body.plain_text,
                        "referenced_cids": list(body.referenced_cids),
                    }
                )
            for att in parsed.attachments:
                self._att_seq += 1
                sec = security_to_json(att.security)
                self.attachments.append(
                    {
                        "id": self._att_seq,
                        "message_pk": message_pk,
                        "mime_path": att.mime_path,
                        "content_type": att.content_type,
                        "charset": att.charset,
                        "disposition": att.disposition.value,
                        "filename": att.filename,
                        "raw_filename": att.raw_filename,
                        "content_id": att.content_id,
                        "content_location": att.content_location,
                        "byte_size": att.byte_size,
                        "checksum_sha256": att.checksum_sha256,
                        "storage_path": att.storage_path,
                        "stored": att.storage_path is not None,
                        "security_category": (sec or {}).get("category"),
                        "security_detected_sig": (sec or {}).get("detected_signature"),
                        "security_detected_mime": (sec or {}).get("detected_mime"),
                        "security_evidence": (sec or {}).get("evidence"),
                        "security_classifier": (sec or {}).get("classifier_version"),
                        "security_inspected": (sec or {}).get("inspected_bytes"),
                        "security_classified_at": datetime.now(timezone.utc) if sec else None,
                    }
                )
        self.defects.extend(
            {
                "ingest_id": ingest_id,
                "message_pk": message_pk,
                "stage": d.stage,
                "level": d.level,
                "message": d.message,
            }
            for d in parsed.defects
        )
        return {"ingest_id": ingest_id, "message_id": message_pk}

    def rebuild_threads(self) -> dict[str, Any]:
        inputs: list[ThreadInput] = []
        for pk, m in self.messages.items():
            refs = [i["value"] for i in self.identifiers if i["message_pk"] == pk and i["kind"] == "references"]
            irt = [i["value"] for i in self.identifiers if i["message_pk"] == pk and i["kind"] == "in_reply_to"]
            ts = m["date"].timestamp() if m["date"] else None
            inputs.append(ThreadInput(pk, m["message_id"], refs, irt, m["subject"], ts))
        result = compute_threads(inputs)
        for pk, key in result.thread_of.items():
            self.messages[pk]["thread_key"] = key
        run = {
            "id": len(self.thread_runs) + 1,
            "ran_at": datetime.now(timezone.utc),
            "duplicate_ids": result.duplicate_ids,
            "dangling": result.dangling_references,
            "cycles": result.cycles,
            "weak_suggestions": result.weak_suggestions,
        }
        self.thread_runs.append(run)
        return {
            "thread_run_id": run["id"],
            "messages": len(inputs),
            "threads": len(set(result.thread_of.values())),
            "duplicate_ids": result.duplicate_ids,
            "dangling_references": result.dangling_references,
            "cycles": result.cycles,
            "weak_suggestions": result.weak_suggestions,
        }

    # -- reads -------------------------------------------------------------
    def _summary(self, m: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": m["id"],
            "ingest_id": m["ingest_id"],
            "message_id": m["message_id"],
            "subject": m["subject"],
            "date": m["date"],
            "from_json": m["from_json"],
            "thread_key": m["thread_key"],
            "raw_sha256": m["raw_sha256"],
            "missing_id": m["missing_id"],
        }

    def get_message(self, pk: int) -> dict[str, Any] | None:
        m = self.messages.get(pk)
        if not m:
            return None
        out = dict(m)
        out["bodies"] = [dict(b) for b in self.bodies if b["message_pk"] == pk]
        out["attachments"] = [
            _shape_attachment(a) for a in self.attachments if a["message_pk"] == pk
        ]
        out["defects"] = [
            {"stage": d["stage"], "level": d["level"], "message": d["message"]}
            for d in self.defects
            if d["message_pk"] == pk
        ]
        return out

    def get_ingest(self, ingest_id: int) -> dict[str, Any] | None:
        ing = self.ingests.get(ingest_id)
        if not ing:
            return None
        out = dict(ing)
        out["defects"] = [
            {"stage": d["stage"], "level": d["level"], "message": d["message"]}
            for d in self.defects
            if d["ingest_id"] == ingest_id
        ]
        pks = [m["id"] for m in self.messages.values() if m["ingest_id"] == ingest_id]
        out["message_pk"] = pks[0] if pks else None
        return out

    def list_messages(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        ordered = sorted(self.messages.values(), key=lambda x: x["id"], reverse=True)
        return [self._summary(m) for m in ordered[offset : offset + limit]]

    def search_messages(self, query: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        q = query.lower()

        def match(m: dict[str, Any]) -> bool:
            if (m["subject"] or "").lower().find(q) >= 0:
                return True
            if (m["message_id"] or "").lower().find(q) >= 0:
                return True
            for h in self.headers:
                if h["message_id"] == m["id"] and h["value"].lower().find(q) >= 0:
                    return True
            for b in self.bodies:
                if b["message_pk"] == m["id"] and (b.get("plain_text") or "").lower().find(q) >= 0:
                    return True
            return False

        hits = [self._summary(m) for m in self.messages.values() if match(m)]
        return {"query": query, "count": len(hits), "results": hits[offset : offset + limit]}

    def get_thread(self, thread_key: str) -> dict[str, Any] | None:
        msgs = [m for m in self.messages.values() if m["thread_key"] == thread_key]
        if not msgs:
            return None
        rows = []
        for m in sorted(msgs, key=lambda x: (x["date"] or datetime.min.replace(tzinfo=timezone.utc), x["id"])):
            rows.append(
                {
                    "id": m["id"],
                    "message_id": m["message_id"],
                    "subject": m["subject"],
                    "date": m["date"],
                    "from_json": m["from_json"],
                    "references": [
                        i["value"]
                        for i in self.identifiers
                        if i["message_pk"] == m["id"] and i["kind"] == "references"
                    ],
                    "in_reply_to": [
                        i["value"]
                        for i in self.identifiers
                        if i["message_pk"] == m["id"] and i["kind"] == "in_reply_to"
                    ],
                }
            )
        return {"thread_key": thread_key, "messages": rows}

    def list_threads(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for m in self.messages.values():
            if m["thread_key"]:
                grouped.setdefault(m["thread_key"], []).append(m)
        out = []
        for key, members_ in grouped.items():
            dates = [x["date"] for x in members_ if x["date"]]
            out.append(
                {
                    "thread_key": key,
                    "message_count": len(members_),
                    "started_at": min(dates) if dates else None,
                    "last_at": max(dates) if dates else None,
                    "has_missing_id": any(x["missing_id"] for x in members_),
                    "distinct_message_ids": len({x["message_id"] for x in members_ if x["message_id"]}),
                }
            )
        out.sort(key=lambda x: x["last_at"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        return out[offset : offset + limit]

    def list_failures(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        rows = []
        for ing in self.ingests.values():
            defects = [
                {"stage": d["stage"], "level": d["level"], "message": d["message"]}
                for d in self.defects
                if d["ingest_id"] == ing["id"]
            ]
            if ing["status"] == "failed" or defects:
                rows.append(
                    {
                        "ingest_id": ing["id"],
                        "received_at": ing["received_at"],
                        "source_name": ing["source_name"],
                        "status": ing["status"],
                        "raw_sha256": ing["raw_sha256"],
                        "raw_size": ing["raw_size"],
                        "fatal_error": ing["fatal_error"],
                        "defect_count": len(defects),
                        "defects": defects,
                    }
                )
        rows.sort(key=lambda x: x["ingest_id"], reverse=True)
        return rows[offset : offset + limit]

    def get_attachment(self, attachment_id: int) -> dict[str, Any] | None:
        for a in self.attachments:
            if a["id"] == attachment_id:
                return _shape_attachment(a)
        return None

    def get_attachment_by_message(self, message_pk: int, attachment_id: int) -> dict[str, Any] | None:
        for a in self.attachments:
            if a["id"] == attachment_id and a["message_pk"] == message_pk:
                return _shape_attachment(a)
        return None

    # -- attachment security review / read-only rescan ---------------------
    def list_attachments(
        self,
        *,
        suspicious: bool | None = None,
        category: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        rows = []
        for a in self.attachments:
            if category is not None and a.get("security_category") != category:
                continue
            if suspicious is not None:
                cat = a.get("security_category")
                # Unclassified legacy rows are never offered as "clear"; they
                # are shown in the review queue until a rescan classifies them.
                is_review = cat is None or cat in REVIEW_CATEGORIES
                if suspicious and not is_review:
                    continue
                if suspicious is False and is_review:
                    continue
            rows.append(a)
        ordered = sorted(rows, key=lambda x: x["id"], reverse=True)
        items = [_shape_attachment(a) for a in ordered[offset : offset + limit]]
        return {"count": len(rows), "limit": limit, "offset": offset, "results": items}

    def attachments_for_rescan(
        self, *, only_unclassified: bool, limit: int | None = None
    ) -> list[dict[str, Any]]:
        rows = [dict(a) for a in self.attachments]
        if only_unclassified:
            rows = [a for a in rows if a.get("security_category") is None]
        rows.sort(key=lambda x: x["id"])
        return rows[:limit] if limit is not None else rows

    def set_attachment_security(
        self,
        attachment_id: int,
        *,
        category: str,
        detected_signature: str | None,
        detected_mime: str | None,
        evidence: list[dict[str, Any]],
        classifier_version: str,
        inspected_bytes: int,
        classified_at: datetime,
    ) -> None:
        for a in self.attachments:
            if a["id"] == attachment_id:
                a["security_category"] = category
                a["security_detected_sig"] = detected_signature
                a["security_detected_mime"] = detected_mime
                a["security_evidence"] = evidence
                a["security_classifier"] = classifier_version
                a["security_inspected"] = inspected_bytes
                a["security_classified_at"] = classified_at
                return
        raise KeyError(attachment_id)


def _shape_attachment(a: dict[str, Any]) -> dict[str, Any]:
    """Return an API-shaped row with nested security facts (flat cols kept)."""
    out = dict(a)
    out["security"] = security_from_columns(
        category=a.get("security_category"),
        detected_sig=a.get("security_detected_sig"),
        detected_mime=a.get("security_detected_mime"),
        evidence=a.get("security_evidence"),
        classifier=a.get("security_classifier"),
        inspected=a.get("security_inspected"),
        declared_mime=_raw_mime_of(a.get("content_type")),
        declared_extension=_ext_of(a.get("filename")),
    )
    return out


def _raw_mime_of(content_type: str | None) -> str | None:
    if not content_type:
        return None
    raw = content_type.split(";", 1)[0].strip().lower()
    return raw or None


def _ext_of(filename: str | None) -> str | None:
    if not filename:
        return None
    leaf = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in leaf:
        return None
    ext = leaf.rsplit(".", 1)[1].strip().lower()
    return ext or None
