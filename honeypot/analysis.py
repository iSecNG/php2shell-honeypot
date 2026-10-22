"""PHP2Shell indicators and stage classification.

Also finds attacker code in requests and emulates it with the fake shell.
"""

import re
from dataclasses import dataclass, field

from . import multipart
from .fakeshell import (
    B64_RE,
    FakeShell,
    Observation,
    looks_like_php,
    looks_like_shell,
    try_b64,
)

UPLOAD_PROGRESS_FIELD = "php_session_upload_progress"

KNOWN_UA_RE = re.compile(
    r"php2shell|php-session-startup-rce|nuclei|zgrab|python-requests"
    r"|go-http-client|curl/|wget/",
    re.I,
)
TOOL_UA_RE = re.compile(r"php2shell|php-session-startup-rce", re.I)
KNOWN_BOUNDARY_RE = re.compile(r"^-*(?:p2s|p2shell|nucleiBoundary|atk)", re.I)
REPEATED_CHAR_BOUNDARY_RE = re.compile(r"(.)\1{40,}")

MAX_TEXT_CANDIDATE = 256 * 1024


@dataclass
class Analysis:
    """Verdict for one request: tags, attack stage and emulated output."""

    tags: list[str] = field(default_factory=list)
    stage: str = "none"
    obs: Observation = field(default_factory=Observation)
    output: str = ""
    upload_progress_values: list[str] = field(default_factory=list)
    arm: bool = False

    def tag(self, t: str) -> None:
        """Add a tag once, preserving insertion order."""
        if t not in self.tags:
            self.tags.append(t)

    @property
    def php2shell_indicators(self) -> list[str]:
        """Tags that point at the PHP2Shell technique."""
        return [t for t in self.tags if t.startswith("php2shell.")]


# positional signature is used by the server
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def classify(
    method: str,
    headers: dict[str, list[str]],
    body: bytes,
    body_truncated: bool,
    mp: multipart.MultipartResult | None,
    arm_threshold: int,
    chunked: bool,
) -> Analysis:
    """Tag a request with PHP2Shell indicators and derive its stage."""
    a = Analysis()
    ua = (headers.get("user-agent") or [""])[0]
    ctype = (headers.get("content-type") or [""])[0]

    if TOOL_UA_RE.search(ua):
        a.tag("php2shell.tool_user_agent")
    elif not ua:
        a.tag("http.no_user_agent")
    elif KNOWN_UA_RE.search(ua):
        a.tag("http.scanner_user_agent")

    if mp is not None:
        _tag_multipart(a, mp, chunked)
    elif "multipart" in ctype.lower():
        a.tag("php2shell.multipart_without_boundary")

    if method == "POST" and (len(body) >= arm_threshold or body_truncated):
        a.tag("php2shell.oversized_body")

    a.arm = any(
        t in a.tags
        for t in (
            "php2shell.oversized_body",
            "php2shell.many_empty_filenames",
            "php2shell.repeated_part_headers",
            "php2shell.repeated_field_names",
            "php2shell.long_repeated_filename",
        )
    )
    if a.arm:
        a.stage = "arm"
    elif any(t.startswith("php2shell.") for t in a.tags):
        a.stage = "probe"
    return a


def _tag_multipart(
    a: Analysis, mp: multipart.MultipartResult, chunked: bool
) -> None:
    """Tag structural multipart anomalies and collect progress values."""
    b = mp.boundary or ""
    if KNOWN_BOUNDARY_RE.search(b):
        a.tag("php2shell.tool_boundary")
    if REPEATED_CHAR_BOUNDARY_RE.search(b):
        a.tag("php2shell.repeated_char_boundary")
    for p in mp.parts:
        if p.name and p.name.lower() == UPLOAD_PROGRESS_FIELD:
            a.upload_progress_values.append(
                p.content[:4096].decode("utf-8", "replace")
            )
    if a.upload_progress_values or any(
        n.lower() == UPLOAD_PROGRESS_FIELD for n in mp.field_name_counts
    ):
        a.tag("php2shell.upload_progress_field")
    # still an indicator, but no 500: PHP 8.3 stops at
    # max_multipart_body_parts (1020) and runs the script normally
    if mp.part_count >= 500:
        a.tag("php2shell.many_parts")
    if mp.empty_filename_parts >= 10:
        a.tag("php2shell.many_empty_filenames")
    if mp.max_part_header_lines >= 100:
        a.tag("php2shell.repeated_part_headers")
    if (
        mp.field_name_counts
        and mp.field_name_counts.most_common(1)[0][1] >= 200
    ):
        a.tag("php2shell.repeated_field_names")
    if any(
        p.filename and len(p.filename) > 512 and len(set(p.filename)) <= 2
        for p in mp.parts
    ):
        a.tag("php2shell.long_repeated_filename")
    if chunked:
        a.tag("php2shell.chunked_multipart")


# positional signature is used by the server
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def text_candidates(
    query: dict[str, list[str]],
    form: dict[str, list[str]],
    headers: dict[str, list[str]],
    mp: multipart.MultipartResult | None,
    body: bytes,
    is_form: bool,
) -> list[tuple[str, str]]:
    """(origin, text) pairs that may carry attacker code."""
    out: list[tuple[str, str]] = []
    for k, vs in query.items():
        out += [(f"query:{k}", v) for v in vs]
        out.append(("query_key", k))
    raw = (
        body[:MAX_TEXT_CANDIDATE + 1].decode("utf-8", "replace")
        if is_form and len(body) <= MAX_TEXT_CANDIDATE
        else ""
    )
    if raw and (looks_like_php(raw) or looks_like_shell(raw)):
        # raw code with a form content type (php://input, PHP-CGI exploits)
        out.append(("body", raw))
    else:
        for k, vs in form.items():
            out += [(f"form:{k}", v) for v in vs]
    for k, vs in headers.items():
        if k in (
            "host",
            "content-length",
            "content-type",
            "accept",
            "accept-encoding",
            "connection",
        ):
            continue
        out += [(f"header:{k}", v) for v in vs]
    if mp is not None:
        for p in mp.parts:
            if p.filename:  # files are handled by the server
                continue
            if p.size <= MAX_TEXT_CANDIDATE and len(set(p.content[:4096])) > 3:
                out.append(
                    (
                        f"multipart:{p.name}",
                        p.content.decode("utf-8", "replace"),
                    )
                )
    elif body and not is_form and len(body) <= MAX_TEXT_CANDIDATE:
        sample = body[:4096]
        if (
            sum(32 <= c < 127 or c in (9, 10, 13) for c in sample)
            / max(len(sample), 1)
            > 0.9
        ):
            out.append(("body", body.decode("utf-8", "replace")))
    return out


def emulate(
    candidates: list[tuple[str, str]], shell: FakeShell, a: Analysis
) -> None:
    """Run candidate texts (and base64 inside them) through the shell.

    Records code origins, the exploit stage and the combined output on a.
    """
    outputs = []
    origins = []
    for origin, text in candidates:
        if not text:
            continue
        found = _emulate_text(text, shell, a.obs)
        if found is None:
            for tok in B64_RE.findall(text)[:50]:
                dec = try_b64(tok)
                if dec and (looks_like_php(dec) or looks_like_shell(dec)):
                    a.obs.decoded_b64.append(dec[:4000])
                    found = (found or "") + (
                        _emulate_text(dec, shell, a.obs) or ""
                    )
        if found is not None:
            origins.append(origin)
            outputs.append(found)
    if origins:
        a.tag("exploit.code_in_request")
        a.code_origins = origins  # type: ignore[attr-defined]
        if a.stage in ("none", "probe", "arm"):
            a.stage = "exploit"
    if a.obs.urls:
        a.tag("postexploit.download_url")
    a.output = "".join(outputs)


def _emulate_text(
    text: str, shell: FakeShell, obs: Observation
) -> str | None:
    """Emulate text as PHP or shell; None if it looks like neither."""
    if looks_like_php(text):
        return shell.run_php(text, obs)
    if looks_like_shell(text):
        return shell.run_shell(text, obs)
    return None
