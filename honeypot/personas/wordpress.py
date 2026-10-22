"""WordPress 6.x site, Twenty Twenty-Four look.

Comes with a made-up upload plugin "simple-file-upload".

Author: Markus Fritz (wirehack7)
"""

import html
import json
import posixpath
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Callable

from .base import (
    HTML,
    JSON,
    SCAN_UPLOAD_PATHS,
    XML,
    Emit,
    Persona,
    Request,
    Response,
    urlset,
)
from ..config import Config

PLUGIN = "/wp-content/plugins/simple-file-upload"
AJAX_PATH = "/wp-admin/admin-ajax.php"

POSTS = [
    (
        "new-warehouse-opens",
        "New warehouse opens",
        "October 14, 2026",
        "130,000 sq ft of additional space for our contract logistics "
        "business.",
    ),
    (
        "hiring-dispatchers",
        "We are hiring dispatchers",
        "October 2, 2026",
        "We have open dispatcher positions at our main site. "
        "Please apply through the form.",
    ),
    (
        "customer-portal-relaunch",
        "Customer portal relaunch",
        "September 18, 2026",
        "Delivery notes and freight documents can now be uploaded online.",
    ),
]
STATIC_PAGES = {
    "/services/": "Services",
    "/careers/": "Careers",
    "/blog/": "Blog",
    "/contact/": "Contact",
}
PAGES = {**STATIC_PAGES, **{f"/{slug}/": title for slug, title, _, _ in POSTS}}
SITEMAPS = ("posts-post", "posts-page", "users")
LOGIN_REDIRECTS = ("/wp-admin", "/wp-admin/", "/admin", "/login")

STATIC_CSS = (
    "/*! WordPress block library */.wp-block-group{box-sizing:border-box}\n"
)
STATIC_JS = (
    "/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors "
    "| jquery.org/license */\n"
)


def _ver(cfg: Config) -> str:
    return html.escape(cfg.wp_version)


def _head(cfg: Config, title: str) -> str:
    v = _ver(cfg)
    site = html.escape(cfg.site_title)
    return f"""<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name='robots' content='max-image-preview:large' />
<title>{html.escape(title)} &#8211; {site}</title>
<link rel="alternate" type="application/rss+xml" \
title="{site} &raquo; Feed" href="/feed/" />
<link rel='stylesheet' id='wp-block-library-css' \
href='/wp-includes/css/dist/block-library/style.min.css?ver={v}' media='all' />
<link rel='stylesheet' id='contact-form-upload-css' \
href='{PLUGIN}/assets/css/upload.css?ver=2.1.4' media='all' />
<link rel="https://api.w.org/" href="/wp-json/" />
<link rel="EditURI" type="application/rsd+xml" title="RSD" \
href="/xmlrpc.php?rsd" />
<meta name="generator" content="WordPress {v}" />
<style id='twentytwentyfour-inline-css'>
:root{{--wp--preset--color--base:#f9f9f9;--wp--preset--color--contrast:#111;\
--wp--preset--color--accent:#cfcabe}}
body{{margin:0;background:var(--wp--preset--color--base);\
color:var(--wp--preset--color--contrast);
font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,\
sans-serif;font-size:1.1rem;line-height:1.6}}
a{{color:inherit}}
.wp-site-blocks{{max-width:1200px;margin:0 auto;padding:0 2rem}}
header.wp-block-template-part{{display:flex;justify-content:space-between;\
align-items:center;padding:1.6rem 0}}
.wp-block-site-title a{{text-decoration:none;font-weight:600;font-size:1.1rem}}
.wp-block-navigation a{{text-decoration:none;margin-left:1.6rem;\
font-size:.95rem}}
.hero{{padding:5rem 0 4rem;border-bottom:1px solid #e3e3e3}}
.hero h1{{font-family:"Cardo",Georgia,serif;font-weight:400;font-size:3.4rem;\
line-height:1.15;max-width:15em;margin:0 0 1rem}}
.cols{{display:grid;grid-template-columns:2fr 1fr;gap:4rem;padding:3rem 0}}
.wp-block-post-title{{font-family:"Cardo",Georgia,serif;font-weight:400;\
font-size:2rem;margin:.2rem 0}}
.wp-block-post-date{{font-size:.85rem;color:#636363}}
article{{margin-bottom:2.8rem}}
.widget{{background:#fff;border:1px solid #e3e3e3;padding:1.6rem}}
.widget h2{{font-size:1.1rem;margin-top:0}}
.sfu-form label{{display:block;font-size:.9rem;margin:.8rem 0 .2rem}}
.sfu-form input[type=text],.sfu-form input[type=email]{{width:100%;\
padding:.5rem;border:1px solid #ccc;box-sizing:border-box}}
.wp-element-button{{background:#111;color:#fff;border:0;padding:.7rem 1.4rem;\
font-size:.95rem;cursor:pointer;margin-top:1rem}}
progress{{width:100%;margin-top:.8rem}}
footer.wp-block-template-part{{border-top:1px solid #e3e3e3;padding:2.5rem 0;\
font-size:.85rem;color:#636363}}
@media(max-width:780px){{.cols{{grid-template-columns:1fr}}\
.hero h1{{font-size:2.4rem}}}}
</style>
</head>
"""


def _layout(cfg: Config, title: str, body_class: str, main: str) -> str:
    site = html.escape(cfg.site_title)
    tagline = html.escape(cfg.site_tagline)
    return (
        _head(cfg, title) + f"""<body class="{body_class} wp-embed-responsive">
<div class="wp-site-blocks">
<header class="wp-block-template-part">
<p class="wp-block-site-title"><a href="/" rel="home">{site}</a></p>
<nav class="wp-block-navigation"><a href="/services/">Services</a>\
<a href="/careers/">Careers</a><a href="/blog/">Blog</a>\
<a href="/contact/">Contact</a></nav>
</header>
<main class="wp-block-group">
{main}
</main>
<footer class="wp-block-template-part">
<p>{site} &middot; {tagline}</p>
<p>Designed with \
<a href="https://wordpress.org" rel="nofollow">WordPress</a></p>
</footer>
</div>
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1" \
id="jquery-core-js"></script>
<script src="{PLUGIN}/assets/js/upload.js?ver=2.1.4" id="sfu-js"></script>
</body>
</html>"""
    )


def _upload_widget() -> str:
    # scanners look for the PHP_SESSION_UPLOAD_PROGRESS field
    return f"""<div class="widget">
<h2>Send us your documents</h2>
<form class="sfu-form" action="{AJAX_PATH}" method="post" \
enctype="multipart/form-data" id="sfu-form-1">
<input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="sfu_1" />
<input type="hidden" name="action" value="sfu_upload" />
<input type="hidden" name="_wpnonce" value="8c1f0e2a7d" />
<label for="sfu-name">Name</label>\
<input type="text" id="sfu-name" name="sfu_name" />
<label for="sfu-mail">Email</label>\
<input type="email" id="sfu-mail" name="sfu_email" />
<label for="sfu-file">File (PDF, max. 8 MB)</label>\
<input type="file" id="sfu-file" name="sfu_file" />
<button type="submit" class="wp-element-button">Upload</button>
<progress id="sfu-progress" value="0" max="100"></progress>
</form>
<script>
document.getElementById('sfu-form-1').addEventListener('submit',function(){{
  var t=setInterval(function(){{fetch('{PLUGIN}/progress.php?id=sfu_1')
    .then(function(r){{return r.json()}}).then(function(d){{
      if(d&&d.content_length){{\
document.getElementById('sfu-progress').value=\
100*d.bytes_processed/d.content_length}}
      if(d&&d.done){{clearInterval(t)}}}})}},500);
}});
</script>
</div>"""


def _articles() -> str:
    return "".join(
        f"""<article class="post type-post status-publish">\
<div class="wp-block-post-date">{d}</div>
<h2 class="wp-block-post-title"><a href="/{y}/">{html.escape(t)}</a></h2>\
<p>{html.escape(x)}</p></article>"""
        for y, t, d, x in POSTS
    )


def author(cfg: Config) -> str:
    """Author archive of the only user."""
    main = f"""<div class="cols"><div><h1 class="wp-block-post-title">\
Author: editor</h1>{_articles()}</div>
<aside>{_upload_widget()}</aside></div>"""
    return _layout(
        cfg, "editor", "archive author author-editor author-1", main
    )


def index(cfg: Config) -> str:
    """Blog front page."""
    arts = _articles()
    main = f"""<section class="hero"><h1>{html.escape(cfg.site_tagline)}</h1>
<p>Transport, warehousing and distribution since 1999.</p></section>
<div class="cols"><div>{arts}</div><aside>{_upload_widget()}</aside></div>"""
    return _layout(cfg, "Home", "home blog", main)


def page(cfg: Config, title: str) -> str:
    """Static page with the upload widget."""
    main = f"""<div class="cols"><div><h1 class="wp-block-post-title">\
{html.escape(title)}</h1>
<p>Upload your documents with the form. We reply within two business days.</p>\
</div>
<aside>{_upload_widget()}</aside></div>"""
    return _layout(cfg, title, "page-template-default page", main)


def upload_ok(
    cfg: Config, d: str, stored: list[str], extra_output: str = ""
) -> str:
    """Thank-you page listing the stored files."""
    items = (
        "".join(
            f'<li><a href="{d}{html.escape(n)}">{d}{html.escape(n)}</a></li>'
            for n in stored
        )
        or "<li>No file received.</li>"
    )
    main = f"""<div class="cols"><div><h1 class="wp-block-post-title">\
Thank you!</h1>
<p>Your files were saved:</p><ul>{items}</ul></div><aside></aside></div>"""
    return _layout(cfg, "Upload", "page", main) + extra_output


def wp_login(cfg: Config, error: bool = False, user: str = "") -> str:
    """wp-login.php, with the wrong-password notice after a POST."""
    v = _ver(cfg)
    site = html.escape(cfg.site_title)
    err = (
        (
            '<div id="login_error" class="notice notice-error"><p>'
            "<strong>Error:</strong> The password you entered for the "
            f"username <strong>{html.escape(user)}</strong> is incorrect. "
            '<a href="/wp-login.php?action=lostpassword">'
            "Lost your password?</a></p></div>"
        )
        if error
        else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en-US"><head>\
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; {site} &#8212; WordPress</title>\
<meta name='robots' content='noindex, follow' />
<link rel='stylesheet' href='/wp-admin/load-styles.php?c=0&amp;dir=ltr&amp;\
load%5Bchunk_0%5D=dashicons,buttons,forms,l10n,login&amp;ver={v}' \
media='all' />
<style>body{{background:#f0f0f1;\
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;\
font-size:13px}}
#login{{width:320px;padding:8% 0 0;margin:auto}}#login h1{{margin:0}}\
#login h1 a{{display:block;width:84px;height:84px;margin:0 auto 25px;
background:#3c434a;border-radius:50%;color:#fff;text-decoration:none;\
text-align:center;line-height:84px;
font:400 58px/84px Georgia,"Times New Roman",serif}}\
form{{background:#fff;border:1px solid #c3c4c7;padding:26px 24px;
box-shadow:0 1px 3px rgba(0,0,0,.04)}}label{{font-size:14px}}\
input[type=text],input[type=password]{{width:100%;font-size:24px;
padding:3px 5px;margin:2px 6px 16px 0;border:1px solid #8c8f94;\
border-radius:4px;box-sizing:border-box}}
.button-primary{{background:#2271b1;border:1px solid #2271b1;color:#fff;\
border-radius:3px;padding:0 12px;min-height:32px;float:right}}
#login_error{{background:#fff;border-left:4px solid #d63638;padding:12px;\
margin-bottom:20px}}#nav,#backtoblog{{padding:0 24px;margin:24px 0 0}}
#nav a,#backtoblog a{{color:#50575e;text-decoration:none}}</style></head>
<body class="login no-js login-action-login wp-core-ui locale-en-us">
<div id="login"><h1><a href="https://wordpress.org/" title="Powered by \
WordPress">W</a></h1>{err}
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>\
<input type="text" name="log" id="user_login" \
value="{html.escape(user)}" size="20" autocapitalize="off" \
autocomplete="username" required="required" /></p>
<div class="user-pass-wrap"><label for="user_pass">Password</label>\
<input type="password" name="pwd" id="user_pass" value="" size="20" \
autocomplete="current-password" required="required" /></div>
<p class="forgetmenot">\
<input name="rememberme" type="checkbox" id="rememberme" value="forever" /> \
<label for="rememberme">Remember Me</label></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" \
class="button button-primary button-large" value="Log In" />
<input type="hidden" name="redirect_to" value="/wp-admin/" />\
<input type="hidden" name="testcookie" value="1" /></p>
<div style="clear:both"></div></form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">\
Lost your password?</a></p>
<p id="backtoblog"><a href="/">&larr; Go to {site}</a></p>\
</div></body></html>"""


def wp_json_root(cfg: Config, base: str) -> str:
    """REST API index at /wp-json/."""
    return json.dumps(
        {
            "name": cfg.site_title,
            "description": cfg.site_tagline,
            "url": base,
            "home": base,
            "gmt_offset": "-5",
            "timezone_string": "America/Chicago",
            "namespaces": [
                "oembed/1.0",
                "sfu/v1",
                "wp/v2",
                "wp-site-health/v1",
                "wp-block-editor/v1",
            ],
            "authentication": {
                "application-passwords": {
                    "endpoints": {
                        "authorization": (
                            f"{base}/wp-admin/authorize-application.php"
                        )
                    }
                }
            },
            "routes": {
                "/wp/v2/posts": {
                    "namespace": "wp/v2",
                    "methods": ["GET", "POST"],
                },
                "/sfu/v1/upload": {
                    "namespace": "sfu/v1",
                    "methods": ["POST"],
                },
            },
            "site_logo": 0,
            "site_icon": 0,
            "site_icon_url": "",
        }
    )


def wp_json_users(cfg: Config, base: str) -> str:
    """User listing at /wp-json/wp/v2/users, leaks the login name."""
    del cfg  # same signature as wp_json_root
    return json.dumps(
        [
            {
                "id": 1,
                "name": "editor",
                "url": "",
                "description": "",
                "slug": "editor",
                "link": f"{base}/author/editor/",
                "avatar_urls": {
                    "24": "https://secure.gravatar.com/avatar/0?s=24&d=mm&r=g"
                },
            }
        ]
    )


def wp_readme(cfg: Config) -> str:
    """readme.html shipped with WordPress."""
    v = _ver(cfg)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta name="viewport" content="width=device-width" />
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>WordPress &#8250; ReadMe</title>\
<link rel="stylesheet" href="wp-admin/css/install.css?ver=20100228" \
type="text/css" />
</head><body>
<h1 id="logo"><a href="https://wordpress.org/">\
<img alt="WordPress" src="wp-admin/images/wordpress-logo.png" /></a></h1>
<p style="text-align: center">Semantic Personal Publishing Platform</p>
<h2>First Things First</h2>
<p>Welcome. WordPress is a very special project to me. Every developer and \
contributor adds something unique to the mix, and together we create \
something beautiful that I am proud to be a part of.</p>
<h2>System Requirements</h2>
<ul><li><a href="https://www.php.net/">PHP</a> version \
<strong>7.2.24</strong> or greater.</li>
<li><a href="https://www.mysql.com/">MySQL</a> version \
<strong>5.5.5</strong> or greater.</li></ul>
<!-- WordPress {v} --></body></html>"""


def xmlrpc_fault() -> str:
    """XML-RPC fault for wrong credentials."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>403</int></value></member>
<member><name>faultString</name><value><string>\
Incorrect username or password.</string></value></member>
</struct></value></fault></methodResponse>"""


def feed(cfg: Config, base: str) -> str:
    """RSS feed of the posts."""
    items = "".join(
        f"<item><title>{html.escape(t)}</title><link>{base}/{y}/</link>"
        "<dc:creator><![CDATA[editor]]></dc:creator>"
        f"<description><![CDATA[{x}]]></description></item>"
        for y, t, _, x in POSTS
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>\
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel><title>{html.escape(cfg.site_title)}</title><link>{base}</link>\
<description>{html.escape(cfg.site_tagline)}</description>
<language>en-US</language>\
<generator>https://wordpress.org/?v={_ver(cfg)}</generator>\
{items}</channel></rss>"""


def _iso(date: str) -> str:
    return datetime.strptime(date, "%B %d, %Y").strftime(
        "%Y-%m-%dT%H:%M:%S+00:00"
    )


def sitemap_index(base: str) -> str:
    """Index at /wp-sitemap.xml."""
    maps = "".join(
        f"<sitemap><loc>{base}/wp-sitemap-{name}-1.xml</loc></sitemap>"
        for name in SITEMAPS
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"{maps}</sitemapindex>\n"
    )


def sitemap(name: str, base: str) -> str | None:
    """Sub-sitemap by name, None if unknown."""
    if name == "posts-post":
        return urlset(
            [(f"{base}/{slug}/", _iso(d)) for slug, _, d, _ in POSTS]
        )
    if name == "posts-page":
        return urlset(
            [(f"{base}/", None)]
            + [(base + path, _iso(POSTS[-1][2])) for path in STATIC_PAGES]
        )
    if name == "users":
        return urlset([(f"{base}/author/editor/", None)])
    return None


def wp_404(cfg: Config) -> str:
    """Theme 404 page for unknown permalinks."""
    main = """<div class="cols"><div><h1 class="wp-block-post-title">\
Page not found</h1>
<p>This page could not be found.</p>
<form role="search" method="get" action="/"><input type="search" name="s" />\
 <button class="wp-element-button">Search</button></form>
</div><aside></aside></div>"""
    return _layout(cfg, "Page not found", "error404", main)


class WordPressPersona(Persona):
    """WordPress with the simple-file-upload plugin and its endpoints."""

    name = "wordpress"
    upload_endpoints = SCAN_UPLOAD_PATHS | {
        f"{PLUGIN}/upload.php",
        "/wp-json/sfu/v1/upload",
    }
    progress_paths = frozenset({"/progress.php", f"{PLUGIN}/progress.php"})
    login_forms = {"/wp-login.php": ("log", "pwd")}
    decoy_uploads = [
        "delivery_note_2026-1009.pdf",
        "resume_j_miller.pdf",
        "bill_of_lading_scan.jpg",
    ]
    robots = (
        "User-agent: *\nDisallow: /wp-admin/\n"
        "Allow: /wp-admin/admin-ajax.php\n\n"
        "Sitemap: {base}/wp-sitemap.xml\n"
    )

    def __init__(self, cfg: Config):
        super().__init__(cfg)
        self._routes: dict[str, Callable[[Request], Response]] = {
            "/": self._index,
            "/index.php": self._index,
            **{path: self._page for path in PAGES},
            "/author/editor/": self._author,
            AJAX_PATH: self._ajax,
            "/wp-login.php": self._login,
            **{path: self._to_login for path in LOGIN_REDIRECTS},
            "/wp-json": self._json_root,
            "/wp-json/": self._json_root,
            "/wp-json/wp/v2/users": self._json_users,
            "/wp-json/wp/v2/users/": self._json_users,
            "/xmlrpc.php": self._xmlrpc,
            "/wp-sitemap.xml": self._sitemap_index,
            "/feed": self._feed,
            "/feed/": self._feed,
            "/readme.html": self._readme,
            "/license.txt": self._license,
        }

    def uploads_dir(self) -> str:
        now = datetime.now(timezone.utc)
        return f"/wp-content/uploads/{now:%Y/%m}/"

    def _wp_headers(self, req: Request) -> dict[str, str]:
        return {
            **self.php_headers(),
            "Link": f'<{req.base_url}/wp-json/>; rel="https://api.w.org/"',
        }

    def upload_page(self, req: Request) -> Response:
        return Response(
            200,
            HTML,
            page(self.cfg, "Upload documents") + req.output,
            self._wp_headers(req),
        )

    def upload_done(self, req: Request) -> Response:
        if req.path.startswith("/wp-json/"):
            return self.upload_json(req)
        return Response(
            200,
            HTML,
            upload_ok(self.cfg, self.uploads_dir(), req.files, req.output),
            self._wp_headers(req),
        )

    def observe(self, req: Request, emit: Emit) -> None:
        if req.path == "/xmlrpc.php" and req.method == "POST":
            m = re.search(rb"<methodName>([^<]{1,100})</methodName>", req.body)
            emit(
                "xmlrpc_call",
                method=m.group(1).decode("utf-8", "replace") if m else None,
                body_preview=req.body[:2000].decode("utf-8", "replace"),
            )

    def route(self, req: Request) -> Response | None:
        handler = self._routes.get(req.path)
        if handler is not None:
            return handler(req)
        path = req.path
        m = re.fullmatch(r"/wp-sitemap-([a-z-]+)-1\.xml", path)
        if m and (body := sitemap(m.group(1), req.base_url)) is not None:
            return Response(200, XML, body, self.php_headers())
        if path.startswith(("/wp-includes/", "/wp-content/")):
            if path.endswith(".css"):
                return Response(200, "text/css", STATIC_CSS)
            if path.endswith(".js"):
                return Response(200, "application/javascript", STATIC_JS)
        r = super().route(req)
        if r is not None and path == "/robots.txt":
            r.headers = self.php_headers()  # generated by WordPress
        return r

    def _html(self, req: Request, body: str) -> Response:
        """Themed page with WordPress headers and the PHP output appended."""
        return Response(200, HTML, body + req.output, self._wp_headers(req))

    def _index(self, req: Request) -> Response:
        return self._html(req, index(self.cfg))

    def _page(self, req: Request) -> Response:
        return self._html(req, page(self.cfg, PAGES[req.path]))

    def _author(self, req: Request) -> Response:
        return self._html(req, author(self.cfg))

    def _ajax(self, req: Request) -> Response:
        if req.method == "POST":
            return self.upload_json(req)
        return Response(400, HTML, "0" + req.output, self.php_headers())

    def _login(self, req: Request) -> Response:
        post = req.method == "POST"
        user = (req.form.get("log") or [""])[0] if post else ""
        return Response(
            200,
            HTML,
            wp_login(self.cfg, error=post, user=user) + req.output,
            self.php_headers(),
        )

    def _to_login(self, req: Request) -> Response:
        base = req.base_url
        back = urllib.parse.quote(base + "/wp-admin/", safe="")
        loc = f"{base}/wp-login.php?redirect_to={back}&reauth=1"
        return Response(302, HTML, "", {**self.php_headers(), "Location": loc})

    def _json_root(self, req: Request) -> Response:
        body = wp_json_root(self.cfg, req.base_url)
        return Response(200, JSON, body, self._wp_headers(req))

    def _json_users(self, req: Request) -> Response:
        body = wp_json_users(self.cfg, req.base_url)
        return Response(200, JSON, body, self._wp_headers(req))

    def _xmlrpc(self, req: Request) -> Response:
        php = self.php_headers()
        if req.method == "POST":
            return Response(
                200,
                "text/xml; charset=UTF-8",
                xmlrpc_fault() + req.output,
                php,
            )
        return Response(
            405,
            "text/plain;charset=UTF-8",
            "XML-RPC server accepts POST requests only.",
            {**php, "Allow": "POST"},
        )

    def _sitemap_index(self, req: Request) -> Response:
        body = sitemap_index(req.base_url)
        return Response(200, XML, body, self.php_headers())

    def _feed(self, req: Request) -> Response:
        return Response(
            200,
            "application/rss+xml; charset=UTF-8",
            feed(self.cfg, req.base_url),
            self.php_headers(),
        )

    def _readme(self, _req: Request) -> Response:
        return Response(200, HTML, wp_readme(self.cfg))

    def _license(self, _req: Request) -> Response:
        return Response(
            200,
            "text/plain",
            "WordPress - Web publishing software\n\n"
            "Copyright 2011-2024 by the contributors\n",
        )

    def not_found(self, req: Request) -> Response:
        # files and wp-* get Apache's 404, the rest goes through permalinks
        if req.path.startswith(
            ("/wp-", "/static/")
        ) or "." in posixpath.basename(req.path):
            return super().not_found(req)
        return Response(404, HTML, wp_404(self.cfg), self._wp_headers(req))
