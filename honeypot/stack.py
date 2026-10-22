"""Pages that come from Apache/PHP itself.

Author: Markus Fritz (wirehack7)
"""

import html

from .config import Config

PHPINFO_PATHS = {
    "/phpinfo.php",
    "/info.php",
    "/php.php",
    "/test.php",
    "/i.php",
    "/pi.php",
}


def apache_error(
    cfg: Config, code: int, path: str = "/", port: int = 80
) -> str:
    """Render Apache's stock error page for `code`.

    `path` is accepted for API compatibility only: Apache 2.4 no longer
    echoes the requested URL on its error pages.
    """
    del path
    titles = {
        404: ("Not Found", "The requested URL was not found on this server."),
        403: (
            "Forbidden",
            "You don't have permission to access this resource.",
        ),
        500: (
            "Internal Server Error",
            "The server encountered an internal error or misconfiguration"
            " and was unable to complete your request."
            "</p>\n<p>Please contact the server administrator at"
            " webmaster@localhost to inform them of the time "
            "this error occurred, and the actions you performed just"
            " before this error.</p>\n<p>More information "
            "about this error may be available in the server error log.",
        ),
        503: (
            "Service Unavailable",
            "The server is temporarily unable to service your request.",
        ),
    }
    title, msg = titles.get(code, ("Error", ""))
    return f"""<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>{code} {title}</title>
</head><body>
<h1>{title}</h1>
<p>{msg}</p>
<hr>
{_address(cfg, port)}
</body></html>
"""


def _address(cfg: Config, port: int) -> str:
    """The `<address>` server signature line Apache appends to pages."""
    return (
        f"<address>{html.escape(cfg.server_header)} Server at"
        f" {html.escape(cfg.hostname)} Port {port}</address>"
    )


def directory_listing(
    cfg: Config, directory: str, names: list[str], port: int = 80
) -> str:
    """Render a mod_autoindex listing of `directory` containing `names`."""
    d = directory.rstrip("/")
    rows = "".join(
        '<tr><td valign="top">&nbsp;</td>'
        f'<td><a href="{html.escape(n)}">{html.escape(n)}</a></td>'
        '<td align="right">2026-10-08 09:14  </td>'
        '<td align="right">212K</td><td>&nbsp;</td></tr>\n'
        for n in names
    )
    return f"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head><title>Index of {d}</title></head><body>
<h1>Index of {d}</h1>
<table><tr><th>&nbsp;</th><th>Name</th><th>Last modified</th>\
<th>Size</th><th>Description</th></tr>
<tr><th colspan="5"><hr></th></tr>
<tr><td>&nbsp;</td><td><a href="../">Parent Directory</a></td>\
<td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
{rows}<tr><th colspan="5"><hr></th></tr>
</table>
{_address(cfg, port)}
</body></html>"""


def _phpinfo_table(rows) -> str:
    """Render (name, local, master) rows; master None means two columns."""
    return (
        "<table>"
        + "".join(
            f'<tr><td class="e">{html.escape(k)}</td>'
            f'<td class="v">{html.escape(a)}</td>'
            + (f'<td class="v">{html.escape(b)}</td>' if b is not None else "")
            + "</tr>"
            for k, a, b in rows
        )
        + "</table>"
    )


def phpinfo(cfg: Config) -> str:
    """Render a trimmed but plausible phpinfo() page for the persona."""
    v = html.escape(cfg.php_version)
    h = html.escape(cfg.hostname)
    tbl = _phpinfo_table

    general = [
        (
            "System",
            f"Linux {cfg.hostname} 6.8.0-45-generic"
            " #45-Ubuntu SMP PREEMPT_DYNAMIC x86_64",
            None,
        ),
        ("Build Date", "Apr 11 2024 20:23:38", None),
        ("Server API", "Apache 2.0 Handler", None),
        ("Virtual Directory Support", "disabled", None),
        ("Configuration File (php.ini) Path", "/etc/php/8.3/apache2", None),
        ("Loaded Configuration File", "/etc/php/8.3/apache2/php.ini", None),
        ("PHP API", "20230831", None),
        ("Zend Extension Build", "API420230831,NTS", None),
        ("Thread Safety", "disabled", None),
        (
            "Registered Stream Wrappers",
            "https, ftps, compress.zlib, php, file, glob, data, http, ftp,"
            " phar",
            None,
        ),
    ]
    core = [
        ("allow_url_fopen", "On", "On"),
        ("disable_functions", "no value", "no value"),
        ("display_errors", "Off", "Off"),
        ("file_uploads", "On", "On"),
        ("max_file_uploads", "20", "20"),
        ("max_input_vars", "1000", "1000"),
        ("memory_limit", "256M", "128M"),
        ("open_basedir", "no value", "no value"),
        ("post_max_size", "8M", "8M"),
        ("upload_max_filesize", "8M", "2M"),
        ("upload_tmp_dir", "no value", "no value"),
    ]
    session = [
        ("session.name", "PHPSESSID", "PHPSESSID"),
        ("session.save_handler", "files", "files"),
        (
            "session.save_path",
            "/var/lib/php/sessions",
            "/var/lib/php/sessions",
        ),
        ("session.serialize_handler", "php", "php"),
        ("session.sid_length", "32", "32"),
        ("session.upload_progress.cleanup", "On", "On"),
        ("session.upload_progress.enabled", "On", "On"),
        ("session.upload_progress.freq", "1%", "1%"),
        (
            "session.upload_progress.name",
            "PHP_SESSION_UPLOAD_PROGRESS",
            "PHP_SESSION_UPLOAD_PROGRESS",
        ),
        (
            "session.upload_progress.prefix",
            "upload_progress_",
            "upload_progress_",
        ),
        ("session.use_strict_mode", "Off", "Off"),
    ]
    apache = [
        ("Apache Version", cfg.server_header, None),
        ("Hostname:Port", f"{cfg.hostname}:80", None),
        ("User/Group", "www-data(33)/33", None),
        (
            "Loaded Modules",
            "core mod_so mod_watchdog http_core mod_log_config mod_logio"
            " mod_version mod_unixd "
            "mod_access_compat mod_alias mod_auth_basic mod_authn_core"
            " mod_authz_core mod_autoindex "
            "mod_deflate mod_dir mod_env mod_mime prefork mod_negotiation"
            " mod_php mod_reqtimeout "
            "mod_rewrite mod_setenvif mod_status",
            None,
        ),
    ]
    variables = [
        ("$_SERVER['SERVER_NAME']", h, None),
        ("$_SERVER['DOCUMENT_ROOT']", "/var/www/html", None),
    ]
    directive_hdr = (
        '<table><tr class="h"><th>Directive</th><th>Local Value</th>'
        "<th>Master Value</th></tr></table>"
    )
    return f"""<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" \
"DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<style type="text/css">
body {{background-color: #fff; color: #222; font-family: sans-serif;}}
table {{border-collapse: collapse; border: 0; width: 934px; \
box-shadow: 1px 2px 3px #ccc;}}
.center {{text-align: center;}} \
.center table {{margin: 1em auto; text-align: left;}}
td, th {{border: 1px solid #666; font-size: 75%; vertical-align: baseline; \
padding: 4px 5px;}}
h1 {{font-size: 150%;}} h2 {{font-size: 125%;}}
.p {{text-align: left;}} \
.e {{background-color: #ccf; width: 300px; font-weight: bold;}}
.h {{background-color: #99c; font-weight: bold;}} \
.v {{background-color: #ddd; max-width: 300px; overflow-x: auto; \
word-wrap: break-word;}}
</style>
<title>PHP {v} - phpinfo()</title>\
<meta name="ROBOTS" content="NOINDEX,NOFOLLOW,NOARCHIVE" /></head>
<body><div class="center">
<table><tr class="h"><td><h1 class="p">PHP Version {v}-1ubuntu1.2</h1>\
</td></tr></table>
{tbl(general)}
<h2>apache2handler</h2>{tbl(apache)}
<h2>Core</h2>{directive_hdr}{tbl(core)}
<h2>session</h2>{directive_hdr}{tbl(session)}
<h2>PHP Variables</h2>{tbl(variables)}
</div></body></html>"""
