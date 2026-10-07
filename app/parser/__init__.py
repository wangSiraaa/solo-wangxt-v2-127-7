from .attachment_security import (
    CLASSIFIER_VERSION,
    AttachmentCategory,
    AttachmentSecurity,
    SecurityEvidence,
    classify_attachment,
)
from .eml_parser import ParseFailure, parse_eml
from .html_sanitizer import escape_html, sanitize_html, strip_to_text
from .models import (
    Address,
    Attachment,
    BodyPart,
    ContentDisposition,
    Defect,
    ParseStatus,
    PartNode,
    ParsedMessage,
)

__all__ = [
    "parse_eml",
    "ParseFailure",
    "sanitize_html",
    "escape_html",
    "strip_to_text",
    "ParsedMessage",
    "BodyPart",
    "Attachment",
    "Address",
    "Defect",
    "PartNode",
    "ParseStatus",
    "ContentDisposition",
    "AttachmentCategory",
    "AttachmentSecurity",
    "SecurityEvidence",
    "classify_attachment",
    "CLASSIFIER_VERSION",
]
