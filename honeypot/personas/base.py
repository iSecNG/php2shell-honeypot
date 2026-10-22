"""Base class for personas (the site on top of the fake Apache/PHP)."""

import html
import json
from dataclasses import dataclass, field
from typing import Callable

from .. import stack
from ..config import Config

HTML = "text/html; charset=UTF-8"
JSON = "application/json; charset=UTF-8"
XML = "application/xml; charset=UTF-8"
APACHE_HTML = "text/html; charset=iso-8859-1"

# upload paths from PHP2Shell scans
SCAN_UPLOAD_PATHS = frozenset(
    {
        "/upload.php",
        "/app/upload.php",
        "/api/endpoint.php",
        "/api/upload.php",
        "/uploads.php",
    }
)


# plain data record, one field per request property
@dataclass
class Request:  # pylint: disable=too-many-instance-attributes
    """Parsed HTTP request as seen by a persona."""

    method: str
    path: str
    host: str
    scheme: str
    port: int  # public port (80/443)
    form: dict[str, list[str]]
    body: bytes
    files: list[str]
    output: str = ""  # fake command output, append to pages that "ran" PHP

    @property
    def base_url(self) -> str:
        """Public scheme://host of the request."""
        return f"{self.scheme}://{self.host}"


@dataclass
class Response:
    """HTTP response produced by a persona."""

    status: int
    ctype: str
    body: str
    headers: dict[str, str] = field(default_factory=dict)


def urlset(entries: list[tuple[str, str | None]]) -> str:
    """Render a sitemap <urlset> from (loc, lastmod) pairs."""
    urls = "".join(
        f"<url><loc>{html.escape(loc)}</loc>"
        + (f"<lastmod>{mod}</lastmod>" if mod else "")
        + "</url>"
        for loc, mod in entries
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"{urls}</urlset>\n"
    )


Emit = Callable[..., None]


class Persona:
    """Base persona: shared upload, progress and robots.txt handling."""

    name = ""
    upload_endpoints: frozenset[str] = SCAN_UPLOAD_PATHS
    progress_paths: frozenset[str] = frozenset({"/progress.php"})
    # path -> (user field, password field)
    login_forms: dict[str, tuple[str, str]] = {}
    decoy_uploads: list[str] = []
    robots = "User-agent: *\nDisallow:\n"  # {base} -> scheme://host

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def uploads_dir(self) -> str:
        """Public URL prefix where uploaded files appear."""
        raise NotImplementedError

    def upload_page(self, req: Request) -> Response:
        """Page shown for GET on an upload endpoint."""
        raise NotImplementedError

    def upload_done(self, req: Request) -> Response:
        """Response to a POST on an upload endpoint."""
        raise NotImplementedError

    def php_headers(self) -> dict[str, str]:
        """Headers PHP adds to every generated response."""
        return {"X-Powered-By": f"PHP/{self.cfg.php_version}"}

    def observe(self, req: Request, emit: Emit) -> None:
        """Persona specific events, e.g. XML-RPC calls."""

    def route(self, req: Request) -> Response | None:
        """Return the response for req, or None if the path is unknown."""
        if req.path in self.upload_endpoints:
            json_api = req.path.startswith("/api/")
            if req.method == "POST":
                return (
                    self.upload_json(req)
                    if json_api
                    else self.upload_done(req)
                )
            if json_api:
                return Response(
                    200,
                    JSON,
                    json.dumps({"status": "ok", "version": "2.1.4"})
                    + req.output,
                    self.php_headers(),
                )
            return self.upload_page(req)
        if req.path in self.progress_paths:
            data = json.dumps(
                {
                    "start_time": 0,
                    "content_length": 0,
                    "bytes_processed": 0,
                    "done": True,
                    "files": [],
                }
            )
            return Response(
                200,
                JSON,
                (data if req.method != "POST" else "null") + req.output,
                self.php_headers(),
            )
        if req.path == "/robots.txt":
            return Response(
                200,
                "text/plain; charset=utf-8",
                self.robots.replace("{base}", req.base_url),
            )
        return None

    def upload_json(self, req: Request) -> Response:
        """JSON answer of an AJAX/REST upload endpoint."""
        d = self.uploads_dir()
        if req.files:
            res = {
                "success": True,
                "data": {
                    "files": [{"name": n, "url": d + n} for n in req.files]
                },
            }
        else:
            res = {"success": False, "data": {"message": "No file received."}}
        return Response(
            200, JSON, json.dumps(res) + req.output, self.php_headers()
        )

    def not_found(self, req: Request) -> Response:
        """404 for unknown paths, Apache's error page by default."""
        return Response(
            404,
            APACHE_HTML,
            stack.apache_error(self.cfg, 404, req.path, req.port),
        )
