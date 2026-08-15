"""
services/document_processing/cleaner.py
-----------------------------------------
Text cleaning and normalization for extracted document text.
"""

import re
from app.core.logger import get_logger

logger = get_logger(__name__)

# Control characters regex: match ascii 0-31 except \t (9), \n (10), \r (13), and DEL (127)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Multiple spaces/tabs regex
_HORIZONTAL_WS_RE = re.compile(r"[ \t]+")
# More than 2 consecutive newlines regex
_MULTI_NEWLINE_RE = re.compile(r"\n{3,}")


class TextCleaner:
    """
    Cleans and normalizes extracted text without modifying essential content.
    """

    def clean(self, raw_text: str) -> str:
        if not raw_text:
            return ""

        # 1. Normalize line endings to \n
        text = raw_text.replace("\r\n", "\n").replace("\r", "\n")

        # 2. Strip non-printable control characters
        text = _CONTROL_CHAR_RE.sub("", text)

        # 3. Normalize horizontal whitespace line by line (preserving indentation/newlines)
        lines = []
        for line in text.split("\n"):
            cleaned_line = _HORIZONTAL_WS_RE.sub(" ", line).strip()
            lines.append(cleaned_line)

        text = "\n".join(lines)

        # 4. Collapse >2 consecutive newlines into double newlines
        text = _MULTI_NEWLINE_RE.sub("\n\n", text)

        # 5. Final strip
        cleaned = text.strip()
        logger.debug("Cleaned text | input_len=%d | output_len=%d", len(raw_text), len(cleaned))
        return cleaned
