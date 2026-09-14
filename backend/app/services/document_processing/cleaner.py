
import re
from app.core.logger import get_logger

logger = get_logger(__name__)


_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_HORIZONTAL_WS_RE = re.compile(r"[ \t]+")

_MULTI_NEWLINE_RE = re.compile(r"\n{3,}")


class TextCleaner:

    def clean(self, raw_text: str) -> str:
        if not raw_text:
            return ""


        text = raw_text.replace("\r\n", "\n").replace("\r", "\n")


        text = _CONTROL_CHAR_RE.sub("", text)


        lines = []
        for line in text.split("\n"):
            cleaned_line = _HORIZONTAL_WS_RE.sub(" ", line).strip()
            lines.append(cleaned_line)

        text = "\n".join(lines)


        text = _MULTI_NEWLINE_RE.sub("\n\n", text)


        cleaned = text.strip()
        logger.debug("Cleaned text | input_len=%d | output_len=%d", len(raw_text), len(cleaned))
        return cleaned
