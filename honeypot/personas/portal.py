"""Hand-written PHP customer portal, Bootstrap look.

Plain .php files, so 404s come from Apache.

Author: Markus Fritz (wirehack7)
"""

import html
from typing import Callable

from .base import HTML, XML, Persona, Request, Response, urlset
from ..config import Config

NAV = [
    ("/index.php", "Home"),
    ("/services.php", "Services"),
    ("/upload.php", "Upload documents"),
    ("/contact.php", "Contact"),
]
PAGES = {
    "/services.php": (
        "Services",
        "Road freight, warehousing and distribution across North America. "
        "Contract customers upload delivery notes and customs papers here.",
    ),
    "/contact.php": (
        "Contact",
        "Send us your documents with the form. Our dispatch team replies "
        "within two business days.",
    ),
}

LOGIN_REDIRECTS = (
    "/admin",
    "/admin/",
    "/admin.php",
    "/login",
    "/logout.php",
    "/account.php",
)

STATIC_CSS = (
    "/*!\n * Bootstrap  v5.3.3 (https://getbootstrap.com/)\n"
    " * Copyright 2011-2024 The Bootstrap Authors\n */\n"
)
STATIC_JS = (
    "/*!\n  * Bootstrap v5.3.3 (https://getbootstrap.com/)\n"
    "  * Copyright 2011-2024 The Bootstrap Authors\n  */\n"
)


def _layout(cfg: Config, title: str, active: str, main: str) -> str:
    """Full HTML page with navbar and footer around main."""
    site = html.escape(cfg.site_title)
    nav = "".join(
        '<li class="nav-item">'
        f'<a class="nav-link{" active" if href == active else ""}" '
        f'href="{href}">{label}</a></li>'
        for href, label in NAV
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} | {site} Customer Portal</title>
<link href="/assets/css/bootstrap.min.css" rel="stylesheet">
<link href="/assets/css/portal.css?v=3.2.1" rel="stylesheet">
<style>
body{{background:#f4f6f9;\
font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,\
sans-serif;color:#212529;margin:0}}
.navbar{{background:#1f3a5f;padding:.8rem 0}}\
.navbar .container{{display:flex;align-items:center;\
justify-content:space-between}}
.navbar-brand{{color:#fff;font-weight:600;text-decoration:none}}\
.navbar-nav{{list-style:none;display:flex;gap:1.2rem;margin:0;padding:0}}
.nav-link{{color:rgba(255,255,255,.75);text-decoration:none}}\
.nav-link.active,.nav-link:hover{{color:#fff}}
.container{{max-width:1140px;margin:0 auto;padding:0 1rem}}
.row{{display:grid;grid-template-columns:7fr 5fr;gap:2rem;padding:2.5rem 0}}
.card{{background:#fff;border:1px solid #dee2e6;border-radius:.375rem;\
padding:1.5rem}}
.card h5{{margin-top:0;font-size:1.15rem}}
.form-label{{display:block;margin:.8rem 0 .3rem;font-size:.9rem}}
.form-control{{width:100%;padding:.45rem .75rem;border:1px solid #ced4da;\
border-radius:.375rem;box-sizing:border-box}}
.btn-primary{{background:#0d6efd;border:0;color:#fff;padding:.5rem 1rem;\
border-radius:.375rem;margin-top:1rem;cursor:pointer}}
.alert-danger{{background:#f8d7da;color:#842029;border:1px solid #f5c2c7;\
border-radius:.375rem;padding:.75rem 1rem}}
.alert-success{{background:#d1e7dd;color:#0f5132;border:1px solid #badbcc;\
border-radius:.375rem;padding:.75rem 1rem}}
.progress{{width:100%;margin-top:.8rem}}
footer{{border-top:1px solid #dee2e6;padding:1.5rem 0;font-size:.85rem;\
color:#6c757d}}
@media(max-width:768px){{.row{{grid-template-columns:1fr}}\
.navbar .container{{flex-direction:column;gap:.6rem}}}}
</style>
</head>
<body>
<nav class="navbar"><div class="container">
<a class="navbar-brand" href="/index.php">{site}</a>
<ul class="navbar-nav">{nav}\
<li class="nav-item"><a class="nav-link" href="/login.php">Customer login</a>\
</li></ul>
</div></nav>
<main class="container">
{main}
</main>
<footer><div class="container">\
&copy; 2026 {site} &middot; Customer Portal 3.2.1</div></footer>
<script src="/assets/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""


def _upload_card() -> str:
    """Upload form with PHP_SESSION_UPLOAD_PROGRESS polling."""
    return """<div class="card">
<h5>Upload documents</h5>
<form action="/upload.php" method="post" enctype="multipart/form-data" \
id="upload-form">
<input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="upl_1">
<input type="hidden" name="MAX_FILE_SIZE" value="8388608">
<label class="form-label" for="ref">Shipment or customer number</label>\
<input class="form-control" type="text" id="ref" name="reference">
<label class="form-label" for="email">Email</label>\
<input class="form-control" type="email" id="email" name="email">
<label class="form-label" for="doc">Document (PDF, JPG, max. 8 MB)</label>\
<input class="form-control" type="file" id="doc" name="document">
<button type="submit" class="btn-primary">Upload</button>
<progress class="progress" id="upload-progress" value="0" max="100"></progress>
</form>
<script>
document.getElementById('upload-form').addEventListener('submit',function(){
  var t=setInterval(function(){fetch('/progress.php?id=upl_1')\
.then(function(r){return r.json()}).then(function(d){
    if(d&&d.content_length){\
document.getElementById('upload-progress').value=\
100*d.bytes_processed/d.content_length}
    if(d&&d.done){clearInterval(t)}})},500);
});
</script>
</div>"""


def index(cfg: Config) -> str:
    """Start page."""
    main = f"""<div class="row"><div>
<h1>{html.escape(cfg.site_tagline)}</h1>
<p>Welcome to the {html.escape(cfg.site_title)} customer portal. \
Upload delivery notes, bills of lading and
customs documents for your shipments. Registered customers can track orders \
after logging in.</p>
<p><a href="/login.php">Log in to your account</a></p>
</div><div>{_upload_card()}</div></div>"""
    return _layout(cfg, "Home", "/index.php", main)


def page(cfg: Config, path: str, title: str, text: str) -> str:
    """Text page with the upload card."""
    main = f"""<div class="row"><div>\
<h1>{html.escape(title)}</h1><p>{html.escape(text)}</p></div>
<div>{_upload_card()}</div></div>"""
    return _layout(cfg, title, path, main)


def upload_ok(cfg: Config, d: str, stored: list[str]) -> str:
    """Result page after an upload, listing the stored files."""
    if stored:
        items = "".join(
            f'<li><a href="{d}{html.escape(n)}">{html.escape(n)}</a></li>'
            for n in stored
        )
        msg = (
            '<div class="alert-success">Upload successful. Thank you!</div>'
            f"<ul>{items}</ul>"
        )
    else:
        msg = (
            '<div class="alert-danger">'
            "No file received. Please select a file.</div>"
        )
    main = (
        '<div class="row"><div><h1>Upload documents</h1>'
        f"{msg}</div><div>{_upload_card()}</div></div>"
    )
    return _layout(cfg, "Upload documents", "/upload.php", main)


def login(cfg: Config, error: bool = False, user: str = "") -> str:
    """Customer login form, with an error after a failed POST."""
    err = (
        '<div class="alert-danger">Invalid username or password.</div>'
        if error
        else ""
    )
    main = f"""<div class="row"><div class="card">
<h5>Customer login</h5>{err}
<form action="/login.php" method="post">
<label class="form-label" for="username">Username</label>\
<input class="form-control" type="text" id="username" name="username" \
value="{html.escape(user)}" autocomplete="username">
<label class="form-label" for="password">Password</label>\
<input class="form-control" type="password" id="password" name="password" \
autocomplete="current-password">
<button type="submit" class="btn-primary">Log in</button>
</form>
<p><a href="/forgot.php">Forgot your password?</a></p>
</div><div></div></div>"""
    return _layout(cfg, "Login", "/login.php", main)


class PortalPersona(Persona):
    """Logistics customer portal written in plain PHP."""

    name = "portal"
    login_forms = {"/login.php": ("username", "password")}
    decoy_uploads = [
        "invoice_2026-10-0412.pdf",
        "delivery_note_88213.pdf",
        "customs_scan_0007.jpg",
    ]
    robots = (
        "User-agent: *\nDisallow: /admin/\nDisallow: /uploads/\n\n"
        "Sitemap: {base}/sitemap.xml\n"
    )

    def __init__(self, cfg: Config):
        super().__init__(cfg)
        self._routes: dict[str, Callable[[Request], Response]] = {
            "/": self._index,
            "/index.php": self._index,
            "/login.php": self._login,
            "/sitemap.xml": self._sitemap,
            **{path: self._page for path in PAGES},
            **{path: self._to_login for path in LOGIN_REDIRECTS},
        }

    def uploads_dir(self) -> str:
        return "/uploads/"

    def upload_page(self, req: Request) -> Response:
        text = (
            "Select the document and enter your shipment or customer number."
        )
        return Response(
            200,
            HTML,
            page(self.cfg, "/upload.php", "Upload documents", text)
            + req.output,
            self.php_headers(),
        )

    def upload_done(self, req: Request) -> Response:
        return Response(
            200,
            HTML,
            upload_ok(self.cfg, self.uploads_dir(), req.files) + req.output,
            self.php_headers(),
        )

    def route(self, req: Request) -> Response | None:
        handler = self._routes.get(req.path)
        if handler is not None:
            return handler(req)
        if req.path.startswith("/assets/"):
            if req.path.endswith(".css"):
                return Response(200, "text/css", STATIC_CSS)
            if req.path.endswith(".js"):
                return Response(200, "application/javascript", STATIC_JS)
        return super().route(req)

    def _index(self, req: Request) -> Response:
        return Response(
            200, HTML, index(self.cfg) + req.output, self.php_headers()
        )

    def _page(self, req: Request) -> Response:
        body = page(self.cfg, req.path, *PAGES[req.path])
        return Response(200, HTML, body + req.output, self.php_headers())

    def _login(self, req: Request) -> Response:
        post = req.method == "POST"
        user = (req.form.get("username") or [""])[0] if post else ""
        body = login(self.cfg, error=post, user=user)
        return Response(200, HTML, body + req.output, self.php_headers())

    def _to_login(self, _req: Request) -> Response:
        return Response(
            302, HTML, "", {**self.php_headers(), "Location": "/login.php"}
        )

    def _sitemap(self, req: Request) -> Response:
        pages = [
            "/",
            "/services.php",
            "/upload.php",
            "/contact.php",
            "/login.php",
        ]
        return Response(
            200,
            XML,
            urlset([(req.base_url + p, "2026-09-18") for p in pages]),
        )
