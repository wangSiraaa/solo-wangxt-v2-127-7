"""Finite, read-only attachment content classification.

Before an archivist downloads an attachment they need to know whether the
sender-supplied **filename**, the **declared MIME type** and the **actual
bytes** agree. This module answers that with a deliberately *small, fixed*
rule set:

* a finite table of binary file signatures ("magic numbers");
* a finite table of executable filename extensions / MIME types;
* a conservative text heuristic (valid decode + no binary control bytes).

Categories:

``executable``
    An executable signature was found (PE/ELF/Mach-O/Java/shebang/...) or the
    declared MIME/extension itself denotes an executable. Always flagged,
    even when honestly named; an explicit masquerade (``notes.txt`` carrying
    an ``MZ`` header) is recorded as additional evidence.

``mismatch``
    A recognized, non-executable signature positively *contradicts* the
    declared MIME type or a known extension (PNG bytes named ``photo.jpg``).

``unknown``
    No finite rule recognized the content. This is **never** labeled safe —
    evidence states the format could not be confirmed.

``consistent``
    A recognized signature agrees with the declaration. This means only
    "signatures agree"; it is not a claim that the content is harmless.

The classifier only inspects a bounded byte prefix. It never executes,
imports, mounts or otherwise activates payload content, and evidence strings
contain rule identifiers/metadata only — never payload bytes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

CLASSIFIER_VERSION = "sig-v1"

# Only the first 64 KiB are needed for every rule in the table (the furthest
# signature is the ISO9660 marker at offset 0x8001).
INSPECT_LIMIT = 64 * 1024


class AttachmentCategory(str, Enum):
    EXECUTABLE = "executable"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"
    CONSISTENT = "consistent"


# Categories that must land on an archivist's review queue. ``unknown`` is
# included on purpose: content we cannot confirm must not be silently passed.
REVIEW_CATEGORIES: tuple[str, ...] = (
    AttachmentCategory.EXECUTABLE.value,
    AttachmentCategory.MISMATCH.value,
    AttachmentCategory.UNKNOWN.value,
)


@dataclass(frozen=True)
class SecurityEvidence:
    """One deterministic reason supporting a classification.

    ``rule`` is a stable machine-readable id; ``detail`` is human-readable.
    Neither field ever carries payload bytes.
    """

    rule: str
    detail: str


@dataclass(frozen=True)
class AttachmentSecurity:
    category: str  # one of AttachmentCategory
    suspicious: bool  # category != consistent (incl. unknown: never cleared)
    declared_mime: str | None  # content-type as declared, parameters stripped
    declared_extension: str | None  # lowercase extension without dot
    detected_signature: str | None  # rule id of the matched signature
    detected_mime: str | None  # canonical MIME inferred from the signature
    inspected_bytes: int
    classifier_version: str
    evidence: list[SecurityEvidence] = field(default_factory=list)


@dataclass(frozen=True)
class _MagicRule:
    rule_id: str
    magics: tuple[bytes, ...]
    offset: int
    mime: str
    aliases: frozenset[str]
    extensions: frozenset[str]
    executable: bool
    description: str


# Fixed signature table. Order matters only for weak prefixes (e.g. BMP's
# two-byte "BM"): strong/long signatures are listed first.
_MAGIC_RULES: tuple[_MagicRule, ...] = (
    _MagicRule(
        "dos_pe_mz", (b"MZ",), 0,
        "application/x-dosexec",
        frozenset({
            "application/x-dosexec", "application/x-ms-dos-executable",
            "application/vnd.microsoft.portable-executable",
            "application/x-msdownload", "application/x-executable",
        }),
        frozenset({"exe", "dll", "sys", "scr", "com", "cpl", "drv", "ocx"}),
        True,
        "MZ header at offset 0: DOS/Windows PE executable",
    ),
    _MagicRule(
        "elf", (b"\x7fELF",), 0,
        "application/x-elf",
        frozenset({"application/x-elf", "application/x-executable",
                   "application/x-sharedlib", "application/x-pie-executable"}),
        frozenset({"elf", "so", "o", "bin"}),
        True,
        "ELF magic at offset 0: Linux/Unix executable or shared object",
    ),
    _MagicRule(
        "mach_o",
        (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"),
        0,
        "application/x-mach-binary",
        frozenset({"application/x-mach-binary", "application/x-executable"}),
        frozenset({"macho", "dylib", "o"}),
        True,
        "Mach-O magic at offset 0: macOS executable",
    ),
    _MagicRule(
        "java_class", (b"\xca\xfe\xba\xbe",), 0,
        "application/java-vm",
        frozenset({"application/java-vm", "application/x-java-class"}),
        frozenset({"class"}),
        True,
        "0xCAFEBABE magic at offset 0: Java class file",
    ),
    _MagicRule(
        "dex", (b"dex\n",), 0,
        "application/vnd.android.dex",
        frozenset({"application/vnd.android.dex", "application/x-dex"}),
        frozenset({"dex"}),
        True,
        "Dalvik DEX magic at offset 0: Android executable bytecode",
    ),
    _MagicRule(
        "pdf", (b"%PDF-",), 0,
        "application/pdf",
        frozenset({"application/pdf", "application/x-pdf"}),
        frozenset({"pdf"}),
        False,
        "%PDF- signature at offset 0: PDF document",
    ),
    _MagicRule(
        "png", (b"\x89PNG\r\n\x1a\n",), 0,
        "image/png",
        frozenset({"image/png"}),
        frozenset({"png", "apng"}),
        False,
        "PNG signature at offset 0",
    ),
    _MagicRule(
        "jpeg", (b"\xff\xd8\xff",), 0,
        "image/jpeg",
        frozenset({"image/jpeg", "image/jpg"}),
        frozenset({"jpg", "jpeg", "jpe", "jfif"}),
        False,
        "JPEG SOI marker at offset 0",
    ),
    _MagicRule(
        "gif", (b"GIF87a", b"GIF89a"), 0,
        "image/gif",
        frozenset({"image/gif"}),
        frozenset({"gif"}),
        False,
        "GIF signature at offset 0",
    ),
    _MagicRule(
        "tiff", (b"II*\x00", b"MM\x00*"), 0,
        "image/tiff",
        frozenset({"image/tiff", "image/tiff-fx"}),
        frozenset({"tif", "tiff"}),
        False,
        "TIFF endian marker at offset 0",
    ),
    _MagicRule(
        "cfb_ole", (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",), 0,
        "application/x-cfb",
        frozenset({"application/x-cfb", "application/msword",
                   "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
                   "application/x-msi"}),
        frozenset({"doc", "xls", "ppt", "msg", "msi", "vsd", "wps", "dot"}),
        False,
        "OLE/CFB signature at offset 0 (legacy Office/Installer container)",
    ),
    _MagicRule(
        "zip", (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"), 0,
        "application/zip",
        frozenset({"application/zip", "application/java-archive",
                   "application/vnd.android.package-archive",
                   "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                   "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                   "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                   "application/epub+zip", "application/x-xpinstall"}),
        frozenset({"zip", "jar", "apk", "docx", "xlsx", "pptx", "odt", "ods",
                   "odp", "odg", "epub", "xpi", "crx", "war"}),
        False,
        "ZIP local-file/end marker at offset 0 (ZIP-family container)",
    ),
    _MagicRule(
        "gzip", (b"\x1f\x8b\x08",), 0,
        "application/gzip",
        frozenset({"application/gzip", "application/x-gzip", "application/gzip-compressed"}),
        frozenset({"gz", "gzip", "tgz"}),
        False,
        "gzip magic at offset 0",
    ),
    _MagicRule(
        "rar", (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"), 0,
        "application/vnd.rar",
        frozenset({"application/vnd.rar", "application/x-rar-compressed"}),
        frozenset({"rar"}),
        False,
        "RAR signature at offset 0",
    ),
    _MagicRule(
        "seven_z", (b"7z\xbc\xaf\x27\x1c",), 0,
        "application/x-7z-compressed",
        frozenset({"application/x-7z-compressed"}),
        frozenset({"7z"}),
        False,
        "7-Zip signature at offset 0",
    ),
    _MagicRule(
        "ar_deb", (b"!<arch>\n",), 0,
        "application/x-archive",
        frozenset({"application/x-archive", "application/x-deb",
                   "application/vnd.debian.binary-package"}),
        frozenset({"a", "ar", "deb"}),
        False,
        "ar archive signature at offset 0 (also used by .deb packages)",
    ),
    _MagicRule(
        "tar_ustar", (b"ustar\x00", b"ustar  "), 0x101,
        "application/x-tar",
        frozenset({"application/x-tar"}),
        frozenset({"tar"}),
        False,
        "POSIX ustar marker at offset 257",
    ),
    _MagicRule(
        "iso9660", (b"CD001",), 0x8001,
        "application/x-iso9660-image",
        frozenset({"application/x-iso9660-image"}),
        frozenset({"iso"}),
        False,
        "ISO 9660 marker at offset 0x8001",
    ),
    # Weak two-byte prefix; kept last so stronger signatures win.
    _MagicRule(
        "bmp", (b"BM",), 0,
        "image/bmp",
        frozenset({"image/bmp", "image/x-bmp"}),
        frozenset({"bmp"}),
        False,
        "BMP 'BM' marker at offset 0",
    ),
)

# Unix interpreter directive. It marks executable scripts even when the rest
# of the file is plain text and the extension claims otherwise.
_SHEBANG_MAGIC = b"#!"
_SHEBANG_RULE = _MagicRule(
    "shebang", (_SHEBANG_MAGIC,), 0,
    "text/x-shellscript",
    frozenset({"text/x-shellscript", "application/x-sh", "text/x-python",
               "application/x-python", "text/x-perl", "application/x-ruby",
               "application/x-node", "application/javascript"}),
    frozenset({"sh", "bash", "zsh", "py", "pl", "rb", "php", "node", "js",
               "mjs", "ps1"}),
    True,
    "shebang (#!) interpreter directive in first line: executable script",
)

# Extensions that themselves denote executable content. Used when no binary
# signature exists (Windows scripts, honestly-named script files, ...).
_EXECUTABLE_EXTENSIONS = frozenset({
    "exe", "scr", "com", "cmd", "bat", "ps1", "psm1", "vbs", "vbe", "js",
    "jse", "wsf", "msi", "jar", "apk", "cpl", "sh", "bash", "zsh", "py",
    "pl", "rb", "php", "node",
})

# Declared MIME types that assert executable content on their own.
_EXECUTABLE_MIMES = frozenset({
    "application/x-dosexec", "application/x-ms-dos-executable",
    "application/vnd.microsoft.portable-executable", "application/x-msdownload",
    "application/x-elf", "application/x-executable", "application/x-sharedlib",
    "application/x-pie-executable", "application/x-mach-binary",
    "application/java-vm", "application/x-java-class",
    "text/x-shellscript", "application/x-sh", "application/x-bat",
    "application/x-powershell", "application/x-msi",
})

# MIME values that explicitly make no claim about concrete content.
_GENERIC_MIMES = frozenset({
    "application/octet-stream", "binary/octet-stream", "application/unknown",
    "content/unknown", "application/binary",
})

_MIME_ALIASES = {
    "application/x-pdf": "application/pdf",
    "image/jpg": "image/jpeg",
    "application/x-gzip": "application/gzip",
    "application/gzip-compressed": "application/gzip",
    "application/x-rar": "application/vnd.rar",
    "application/x-rar-compressed": "application/vnd.rar",
}

# Extensions compatible with plain/structured text. An unknown extension makes
# no claim and therefore never conflicts; only *known* extensions do.
_TEXT_EXTENSIONS = frozenset({
    "txt", "log", "csv", "tsv", "md", "markdown", "rst", "tex", "text",
    "ini", "conf", "cfg", "json", "geojson", "yaml", "yml", "toml", "html",
    "htm", "xhtml", "xml", "svg", "css", "rtf", "sql", "py", "sh", "bash",
    "zsh", "pl", "rb", "php", "js", "mjs", "c", "h", "cc", "cpp", "java",
    "go", "rs",
})
_TEXT_MIME_EXTRA = frozenset({
    "application/json", "application/xml", "application/javascript",
    "application/x-sh", "application/x-python", "text/x-python",
    "image/svg+xml", "application/rtf",
})
_HTML_MIME = frozenset({"text/html", "application/xhtml+xml"})
_HTML_EXT = frozenset({"html", "htm", "xhtml"})
_XML_MIME = frozenset({"application/xml", "text/xml", "image/svg+xml"})
_XML_EXT = frozenset({"xml", "svg", "xsd", "xsl"})

# Every extension the finite rule set has an opinion about.
_KNOWN_EXTENSIONS: frozenset[str] = frozenset(
    ext for rule in (*_MAGIC_RULES, _SHEBANG_RULE) for ext in rule.extensions
) | _EXECUTABLE_EXTENSIONS | _TEXT_EXTENSIONS

_BOMS = (
    (b"\xef\xbb\xbf", "UTF-8 BOM", "utf-8-sig"),
    (b"\xff\xfe\x00\x00", "UTF-32 LE BOM", "utf-32"),
    (b"\x00\x00\xfe\xff", "UTF-32 BE BOM", "utf-32"),
    (b"\xff\xfe", "UTF-16 LE BOM", "utf-16"),
    (b"\xfe\xff", "UTF-16 BE BOM", "utf-16"),
)
# Allowed non-printable bytes inside "text".
_TEXT_ALLOWED_CONTROL = frozenset({0x09, 0x0A, 0x0C, 0x0D})


def _normalize_mime(declared: str | None) -> str | None:
    if not declared:
        return None
    raw = declared.split(";", 1)[0].strip().lower()
    if not raw or raw in _GENERIC_MIMES:
        return None
    return _MIME_ALIASES.get(raw, raw)


def _raw_mime(declared: str | None) -> str | None:
    if not declared:
        return None
    raw = declared.split(";", 1)[0].strip().lower()
    return raw or None


def _extension(filename: str | None) -> str | None:
    if not filename:
        return None
    leaf = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
    if "." not in leaf:
        return None
    ext = leaf.rsplit(".", 1)[1].strip().lower()
    return ext or None


def _matches_at(head: bytes, total: int, magic: bytes, offset: int) -> bool:
    return total >= offset + len(magic) and head[offset : offset + len(magic)] == magic


def _detect_magic(head: bytes, total: int) -> tuple[_MagicRule | None, list[SecurityEvidence]]:
    evidence: list[SecurityEvidence] = []
    # Shebang only counts as the first line, without embedded NUL bytes.
    first_line = head.split(b"\n", 1)[0][:256]
    if first_line.startswith(_SHEBANG_MAGIC) and b"\x00" not in first_line:
        evidence.append(SecurityEvidence("magic:shebang", _SHEBANG_RULE.description))
        return _SHEBANG_RULE, evidence
    for rule in _MAGIC_RULES:
        if any(_matches_at(head, total, magic, rule.offset) for magic in rule.magics):
            evidence.append(SecurityEvidence(f"magic:{rule.rule_id}", rule.description))
            return rule, evidence
    return None, evidence


def _decode_text(head: bytes, declared_charset: str | None) -> tuple[str | None, str | None]:
    """Decode the prefix with a BOM-aware codec, declared charset, then UTF-8.

    A successful decode *and* the absence of binary control bytes is required
    before content is treated as text; bytes are never interpreted beyond
    decoding for this check. Returns ``(text, bom_label)``.
    """
    bom_label: str | None = None
    candidates: list[str] = []
    for marker, label, codec in _BOMS:
        if head.startswith(marker):
            bom_label = label
            candidates.append(codec)
            head = head[len(marker) :]
            break
    if declared_charset:
        candidates.append(declared_charset)
    candidates.append("utf-8")
    seen: set[str] = set()
    for codec in candidates:
        if codec in seen:
            continue
        seen.add(codec)
        try:
            text = head.decode(codec)
        except (UnicodeDecodeError, LookupError):
            continue
        if any(ord(ch) < 0x20 and ord(ch) not in _TEXT_ALLOWED_CONTROL for ch in text):
            return None, None
        if "\x7f" in text:
            return None, None
        return text, bom_label
    return None, None


def _detect_text(
    head: bytes, declared_charset: str | None
) -> tuple[str, frozenset[str], frozenset[str], str | None, str | None] | None:
    """Return (kind, mime_aliases, extensions, bom_label, mime_hint)."""
    text, bom = _decode_text(head, declared_charset)
    if text is None:
        return None
    stripped = text.lstrip("﻿").lstrip().lower()
    if stripped.startswith("<?xml"):
        return "xml", _XML_MIME, _XML_EXT, bom, "application/xml"
    if re.match(r"\s*<(?:html|!doctype\s+html)(?:\s|>)", text.lstrip("﻿"), re.IGNORECASE):
        return "html", _HTML_MIME, _HTML_EXT, bom, "text/html"
    return "plain", frozenset(), _TEXT_EXTENSIONS, bom, "text/plain"


def _mime_compatible(mime: str | None, aliases: frozenset[str], *, text_kind: str | None) -> bool:
    if mime is None:
        return True  # generic/absent declaration makes no concrete claim
    if mime in aliases:
        return True
    if text_kind == "plain" and (mime.startswith("text/") or mime in _TEXT_MIME_EXTRA):
        return True
    return False


def _ext_compatible(ext: str | None, compatible: frozenset[str]) -> bool:
    if ext is None:
        return True  # no extension -> no claim
    if ext in compatible:
        return True
    if ext not in _KNOWN_EXTENSIONS:
        return True  # unrecognized extension -> no concrete claim
    return False


def classify_attachment(
    data: bytes,
    *,
    declared_mime: str | None,
    filename: str | None = None,
    declared_charset: str | None = None,
) -> AttachmentSecurity:
    """Classify attachment bytes against the finite signature/extension rules.

    Pure and side-effect free: no execution, no subprocess, no mutation.
    """
    total = len(data)
    head = data[:INSPECT_LIMIT]
    mime = _normalize_mime(declared_mime)
    mime_raw = _raw_mime(declared_mime)
    ext = _extension(filename)

    evidence: list[SecurityEvidence] = [
        SecurityEvidence(
            "declared:mime",
            f"declared Content-Type {mime_raw or 'absent/generic'}"
            + (" (generic binary type: no concrete claim)" if mime is None and mime_raw else ""),
        ),
        SecurityEvidence(
            "declared:extension",
            f"declared extension {'.' + ext if ext else 'absent/unrecognized'}",
        ),
    ]
    if declared_charset:
        evidence.append(SecurityEvidence("declared:charset", f"declared charset {declared_charset!r}"))

    text_info = None
    scope = SecurityEvidence(
        "inspection:scope",
        f"inspected first {min(total, INSPECT_LIMIT)} of {total} bytes with {CLASSIFIER_VERSION}; "
        "content was not executed",
    )

    def result(category: AttachmentCategory, detected: _MagicRule | None, mime_hint: str | None) -> AttachmentSecurity:
        evidence.append(scope)
        suspicious = category is not AttachmentCategory.CONSISTENT
        return AttachmentSecurity(
            category=category.value,
            suspicious=suspicious,
            declared_mime=mime_raw,
            declared_extension=ext,
            detected_signature=detected.rule_id if detected is not None else (
                f"text:{text_info[0]}" if text_info is not None else None
            ),
            detected_mime=detected.mime if detected is not None else mime_hint,
            inspected_bytes=min(total, INSPECT_LIMIT),
            classifier_version=CLASSIFIER_VERSION,
            evidence=list(evidence),
        )

    # 0) Zero-byte part: no claim about content can be verified. Honest
    #    "unknown", never "consistent".
    if total == 0:
        evidence.append(SecurityEvidence(
            "decision:unknown",
            "empty attachment: no signature or text content to confirm; NOT asserted safe",
        ))
        return result(AttachmentCategory.UNKNOWN, None, None)

    sig, sig_evidence = _detect_magic(head, total)
    evidence.extend(sig_evidence)
    if sig is None:
        text_info = _detect_text(head, declared_charset)
        if text_info is not None:
            kind, _, _, bom, _hint = text_info
            detail = {
                "plain": "prefix decodes as text without binary control bytes",
                "html": "prefix decodes as text and begins with an HTML document marker",
                "xml": "prefix decodes as text and begins with an <?xml declaration",
            }[kind]
            if bom:
                detail += f" ({bom})"
            evidence.append(SecurityEvidence(f"text:{kind}", detail))

    # 1) Executable content signature — highest priority, always flagged.
    if sig is not None and sig.executable:
        if ext and ext not in sig.extensions:
            evidence.append(SecurityEvidence(
                "conflict:extension",
                f"executable signature but extension {'.' + ext} does not name an executable "
                "(possible masquerade)",
            ))
        if mime and mime not in sig.aliases:
            evidence.append(SecurityEvidence(
                "conflict:mime",
                f"executable signature conflicts with declared MIME {mime}",
            ))
        return result(AttachmentCategory.EXECUTABLE, sig, None)

    # 2) The declaration itself claims an executable type.
    if mime in _EXECUTABLE_MIMES:
        evidence.append(SecurityEvidence(
            "decision:executable-mime",
            f"declared MIME {mime} denotes an executable; no clearing signature present",
        ))
        return result(AttachmentCategory.EXECUTABLE, sig, None)

    # 3) An executable extension (scripts/Java archives/PE names) — flag even
    #    though scripts carry no binary signature.
    if ext in _EXECUTABLE_EXTENSIONS:
        evidence.append(SecurityEvidence(
            "decision:executable-extension",
            f"extension {'.' + ext} denotes an executable/script by the finite extension rules",
        ))
        # If a concrete non-executable signature exists, record it too.
        return result(AttachmentCategory.EXECUTABLE, sig, None)

    # 4) Recognized, non-executable signature: compare with the declaration.
    if sig is not None:
        ext_ok = _ext_compatible(ext, sig.extensions)
        mime_ok = _mime_compatible(mime, sig.aliases, text_kind=None)
        if not ext_ok or not mime_ok:
            if not ext_ok:
                evidence.append(SecurityEvidence(
                    "conflict:extension",
                    f"signature indicates {sig.mime} but extension {'.' + ext} claims another type",
                ))
            if not mime_ok:
                evidence.append(SecurityEvidence(
                    "conflict:mime",
                    f"signature indicates {sig.mime} but declared MIME is {mime}",
                ))
            return result(AttachmentCategory.MISMATCH, sig, None)
        evidence.append(SecurityEvidence(
            "decision:signature-match",
            f"signature {sig.rule_id} is consistent with the declared MIME/extension",
        ))
        return result(AttachmentCategory.CONSISTENT, sig, None)

    # 5) Recognized text: compare with the declaration.
    if text_info is not None:
        kind, aliases, text_exts, _bom, mime_hint = text_info
        ext_ok = _ext_compatible(ext, text_exts)
        mime_ok = _mime_compatible(mime, aliases, text_kind=kind)
        if not ext_ok or not mime_ok:
            if not ext_ok:
                evidence.append(SecurityEvidence(
                    "conflict:extension",
                    f"content is text but extension {'.' + ext} claims a binary type",
                ))
            if not mime_ok:
                evidence.append(SecurityEvidence(
                    "conflict:mime",
                    f"content is text but declared MIME is {mime}",
                ))
            return result(AttachmentCategory.MISMATCH, None, mime_hint)
        evidence.append(SecurityEvidence(
            "decision:text-match",
            "text content is consistent with the declared MIME/extension",
        ))
        return result(AttachmentCategory.CONSISTENT, None, mime_hint)

    # 6) No finite rule recognized the content. Do NOT call it safe.
    if mime or (ext and ext in _KNOWN_EXTENSIONS):
        claimed = mime or f"extension .{ext}"
        evidence.append(SecurityEvidence(
            "decision:unconfirmed-claim",
            f"declared {claimed} could not be confirmed: no matching finite signature",
        ))
    evidence.append(SecurityEvidence(
        "decision:unknown",
        "no finite file signature matched and content is not decodable text; "
        "unrecognized format — NOT asserted safe",
    ))
    return result(AttachmentCategory.UNKNOWN, None, None)


def security_to_json(sec: AttachmentSecurity | None) -> dict:
    """JSON shape used by the API; ``None`` stays ``None`` (legacy rows)."""
    if sec is None:
        return None
    return {
        "category": sec.category,
        "suspicious": sec.suspicious,
        "declared_mime": sec.declared_mime,
        "declared_extension": sec.declared_extension,
        "detected_signature": sec.detected_signature,
        "detected_mime": sec.detected_mime,
        "inspected_bytes": sec.inspected_bytes,
        "classifier_version": sec.classifier_version,
        "evidence": [{"rule": e.rule, "detail": e.detail} for e in sec.evidence],
    }


def security_from_columns(
    *,
    category: str | None,
    detected_sig: str | None,
    detected_mime: str | None,
    evidence: list | None,
    classifier: str | None,
    inspected: int | None,
    declared_mime: str | None,
    declared_extension: str | None,
) -> dict | None:
    """Rebuild the nested API shape from persisted columns (memory or PG)."""
    if category is None:
        return None
    return {
        "category": category,
        "suspicious": category in REVIEW_CATEGORIES,
        "declared_mime": declared_mime,
        "declared_extension": declared_extension,
        "detected_signature": detected_sig,
        "detected_mime": detected_mime,
        "inspected_bytes": inspected,
        "classifier_version": classifier,
        "evidence": evidence or [],
    }
