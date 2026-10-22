"""multipart/form-data parser.

Lenient enough not to choke on the broken bodies attackers send.
"""

import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field

# quoted values may contain \" like PHP's rfc1867 parser accepts
_RE_NAME = re.compile(
    rb"""\bname\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;\s]+))""", re.I
)
_RE_FILENAME = re.compile(
    rb"""\bfilename\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;\s]*))""", re.I
)
_RE_UNESCAPE = re.compile(rb"\\([\\\"])")
_RE_BOUNDARY = re.compile(r'boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))', re.I)

MAX_HEADER_SAMPLE = 20


@dataclass
class Part:
    """One body part with its parsed headers and raw content."""

    name: str | None
    filename: str | None
    content_type: str | None
    size: int
    header_lines: int
    sha256: str
    content: bytes


@dataclass
class MultipartResult:  # pylint: disable=too-many-instance-attributes
    """Parsed parts plus the structural statistics used for detection."""

    boundary: str | None
    parts: list[Part] = field(default_factory=list)
    part_count: int = 0
    truncated: bool = False
    empty_filename_parts: int = 0
    max_part_header_lines: int = 0
    max_repeated_header: tuple[str, int] | None = None
    field_name_counts: Counter = field(default_factory=Counter)
    closed: bool = False


def get_boundary(content_type: str | None) -> str | None:
    """Extract the boundary from a multipart Content-Type, if any."""
    if not content_type or "multipart" not in content_type.lower():
        return None
    m = _RE_BOUNDARY.search(content_type)
    if not m:
        return None
    return m.group(1) or m.group(2)


def _first(m) -> str | None:
    """Decoded value of a name/filename match (quoted or bare form)."""
    if not m:
        return None
    if m.group(1) is not None:
        return _RE_UNESCAPE.sub(rb"\1", m.group(1)).decode("utf-8", "replace")
    return (
        m.group(2).decode("utf-8", "replace")
        if m.group(2) is not None
        else None
    )


def parse(body: bytes, boundary: str, max_parts: int) -> MultipartResult:
    """Split body on boundary; keep at most max_parts parts, count all."""
    res = MultipartResult(boundary=boundary)
    delim = b"--" + boundary.encode("latin-1", "replace")
    pos = body.find(delim)
    while pos != -1:
        start = pos + len(delim)
        if body[start:start + 2] == b"--":
            res.closed = True
            break
        if body[start:start + 2] == b"\r\n":
            start += 2
        elif body[start:start + 1] == b"\n":
            start += 1
        nxt = body.find(delim, start)
        end = len(body) if nxt == -1 else nxt
        # Strip the line break that precedes the next delimiter.
        if body[end - 2:end] == b"\r\n":
            end -= 2
        elif body[end - 1:end] == b"\n":
            end -= 1
        _consume_part(res, body[start:end], max_parts)
        pos = nxt
    return res


def _split_part(raw: bytes) -> tuple[bytes, bytes]:
    """Split a raw part into (header block, content)."""
    sep = raw.find(b"\r\n\r\n")
    sep_len = 4
    if sep == -1:
        sep = raw.find(b"\n\n")
        sep_len = 2
    if sep == -1:
        return raw, b""
    return raw[:sep], raw[sep + sep_len:]


def _scan_headers(
    res: MultipartResult, lines: list[bytes]
) -> tuple[bytes | None, str | None]:
    """Record header statistics; return (disposition, content type)."""
    res.max_part_header_lines = max(res.max_part_header_lines, len(lines))
    names = Counter()
    disposition = None
    ctype = None
    for line in lines:
        k, _, v = line.partition(b":")
        key = k.strip().lower()
        names[key] += 1
        if key == b"content-disposition" and disposition is None:
            disposition = v
        elif key == b"content-type" and ctype is None:
            ctype = v.strip().decode("latin-1", "replace")
    if names:
        top, count = names.most_common(1)[0]
        if (
            res.max_repeated_header is None
            or count > res.max_repeated_header[1]
        ):
            res.max_repeated_header = (top.decode("latin-1", "replace"), count)
    return disposition, ctype


def _consume_part(res: MultipartResult, raw: bytes, max_parts: int) -> None:
    """Parse one raw part into res, honouring the max_parts limit."""
    res.part_count += 1
    head, content = _split_part(raw)
    lines = head.splitlines()
    disposition, ctype = _scan_headers(res, lines)

    name = filename = None
    if disposition is not None:
        name = _first(_RE_NAME.search(disposition))
        fm = _RE_FILENAME.search(disposition)
        if fm:
            filename = _first(fm) or ""
            if filename == "":
                res.empty_filename_parts += 1
    if name is not None:
        res.field_name_counts[name] += 1

    if len(res.parts) >= max_parts:
        res.truncated = True
        return
    res.parts.append(
        Part(
            name=name,
            filename=filename,
            content_type=ctype,
            size=len(content),
            header_lines=len(lines),
            sha256=hashlib.sha256(content).hexdigest(),
            content=content,
        )
    )
