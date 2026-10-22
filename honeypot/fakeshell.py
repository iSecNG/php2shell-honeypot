"""Fake shell and PHP.

Returns what an Ubuntu 24.04 web server would print, nothing is executed.

Author: Markus Fritz (wirehack7)
"""

import base64
import binascii
import hashlib
import re
import shlex
from dataclasses import dataclass, field
from typing import Callable

URL_RE = re.compile(r"""\b(?:https?|ftp|tftp)://[^\s'"<>`|;)]+""", re.I)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

SHELL_HINT_RE = re.compile(
    r"(?:^|[\s;|&`(])(?:wget|curl|sh|bash|busybox|chmod|nc|ncat|socat|tftp"
    r"|python3?|perl|base64|echo|id|uname|whoami|cat|ls|cd|rm|mkdir|nohup"
    r"|crontab|useradd|ps|kill|pkill|ifconfig|ip|hostname|printf|php|lscpu"
    r"|nproc|free|df|history|setsid|systemctl)(?=$|[\s;|&)])"
)
PHP_EXEC_RE = re.compile(
    r"\b(system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)"
    r"""\s*\(\s*(['"])(.*?)(?<!\\)\2""",
    re.I | re.S,
)
PHP_ECHO_MD5_RE = re.compile(
    r"""\b(?:echo|print|die|exit)\s*\(?\s*md5\s*\(\s*(['"])(.*?)\1\s*\)""",
    re.I | re.S,
)
PHP_ECHO_STR_RE = re.compile(
    r"""\b(?:echo|print|die|exit)\s*\(?\s*(['"])(.{1,200}?)\1""", re.I | re.S
)
PHP_B64_EVAL_RE = re.compile(
    r"""base64_decode\s*\(\s*(['"])([A-Za-z0-9+/=]+)\1""", re.I
)
PHP_WRITE_RE = re.compile(
    r"\b(file_put_contents|fopen|move_uploaded_file|copy)"
    r"""\s*\(\s*(['"])(.*?)\2""",
    re.I | re.S,
)
PHP_MARKERS = (
    "<?php",
    "<?=",
    "eval(",
    "assert(",
    "system(",
    "passthru(",
    "shell_exec(",
    "base64_decode(",
    "file_put_contents(",
    "phpinfo(",
    "proc_open(",
    "popen(",
    "create_function(",
    "$_GET",
    "$_POST",
    "$_REQUEST",
)

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
mysql:x:110:113:MySQL Server,,,:/nonexistent:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
deploy:x:1001:1001:,,,:/home/deploy:/bin/bash
"""

OS_RELEASE = """PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
UBUNTU_CODENAME=noble
"""


def looks_like_shell(s: str) -> bool:
    """True if s mentions a typical shell command."""
    return bool(SHELL_HINT_RE.search(s))


def looks_like_php(s: str) -> bool:
    """True if s contains a typical PHP code marker."""
    low = s.lower()
    return any(m.lower() in low for m in PHP_MARKERS)


def try_b64(token: str) -> str | None:
    """Decode a base64 token if the result is mostly printable text."""
    t = token.strip()
    if len(t) < 16:
        return None
    try:
        raw = base64.b64decode(t + "=" * (-len(t) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw)
    if printable / len(raw) < 0.92:
        return None
    return raw.decode("utf-8", "replace")


@dataclass
class Observation:
    """What an attacker's code did: commands, snippets and IOCs."""

    commands: list[str] = field(default_factory=list)
    php_snippets: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    write_targets: list[str] = field(default_factory=list)
    decoded_b64: list[str] = field(default_factory=list)

    def merge_iocs(self, text: str) -> None:
        """Collect new URLs and IPv4 addresses found in text."""
        for u in URL_RE.findall(text):
            if u not in self.urls:
                self.urls.append(u)
        for ip in IPV4_RE.findall(text):
            if ip not in self.ips:
                self.ips.append(ip)

    def as_dict(self) -> dict:
        """Non-empty fields as a dict."""
        return {k: v for k, v in self.__dict__.items() if v}


@dataclass
class _Call:
    """One simple command invocation handed to a command handler."""

    argv: list[str]
    name: str
    args: list[str]
    stdin: str
    obs: Observation
    depth: int


class FakeShell:
    """Emulates PHP and shell code, recording what it observes."""

    def __init__(
        self,
        hostname: str,
        php_version: str,
        on_download: Callable[[str], str | None] | None = None,
    ):
        self.hostname = hostname
        self.php_version = php_version
        self.on_download = on_download

    def run_php(self, code: str, obs: Observation, depth: int = 0) -> str:
        """Emulate PHP code: decode base64 evals, exec calls and echoes."""
        if depth > 4:
            return ""
        obs.php_snippets.append(code[:2000])
        obs.merge_iocs(code)
        out = []
        for m in PHP_B64_EVAL_RE.finditer(code):
            dec = try_b64(m.group(2))
            if dec:
                obs.decoded_b64.append(dec[:2000])
                out.append(
                    self.run_php(dec, obs, depth + 1)
                    if looks_like_php(dec)
                    else self.run_shell(dec, obs, depth + 1)
                )
        for m in PHP_WRITE_RE.finditer(code):
            obs.write_targets.append(m.group(3))
        for m in PHP_EXEC_RE.finditer(code):
            out.append(
                self.run_shell(
                    m.group(3).replace("\\'", "'").replace('\\"', '"'),
                    obs,
                    depth + 1,
                )
            )
        for m in PHP_ECHO_MD5_RE.finditer(code):
            out.append(hashlib.md5(m.group(2).encode()).hexdigest())
        if not out:
            for m in PHP_ECHO_STR_RE.finditer(code):
                out.append(m.group(2))
        return "".join(o for o in out if o)

    def run_shell(
        self, cmdline: str, obs: Observation, depth: int = 0
    ) -> str:
        """Emulate a shell command line and return its fake output."""
        if depth > 6 or not cmdline.strip():
            return ""
        obs.commands.append(cmdline[:4000])
        obs.merge_iocs(cmdline)
        out = []
        for segment in _split_sequence(cmdline):
            out.append(self._run_pipeline(segment, obs, depth))
        return "".join(out)

    def _run_pipeline(
        self, segment: str, obs: Observation, depth: int
    ) -> str:
        """Emulate one pipeline, special-casing decode/download | sh."""
        stages = [
            s.strip() for s in _split_unquoted(segment, "|") if s.strip()
        ]
        if not stages:
            return ""
        argv_list = [_argv(s) for s in stages]
        names = [os_basename(a[0]) if a else "" for a in argv_list]

        # echo <b64> | base64 -d | sh   -> decode and recurse
        echo_idx = next(
            (
                i
                for i, n in enumerate(names[:-1])
                if n in ("echo", "printf") and "base64" in names[i + 1:]
            ),
            None,
        )
        if echo_idx is not None:
            payload = " ".join(
                a for a in argv_list[echo_idx][1:] if not a.startswith("-")
            ).strip("'\"")
            dec = try_b64(payload)
            if dec:
                obs.decoded_b64.append(dec[:4000])
                if names[-1] in ("sh", "bash", "ash", "dash", "zsh"):
                    return self.run_shell(dec, obs, depth + 1)
                return dec
        # curl/wget URL | sh   -> optionally fetch script and recurse
        if (
            len(stages) >= 2
            and names[0] in ("curl", "wget")
            and names[-1] in ("sh", "bash", "ash", "dash")
        ):
            script = self._download(argv_list[0], obs)
            if script:
                return self.run_shell(script, obs, depth + 1)
            return ""

        data = ""
        for argv, name in zip(argv_list, names):
            data = self._run_simple(argv, name, data, obs, depth)
        return data

    def _download(self, argv: list[str], obs: Observation) -> str | None:
        """Record URLs in argv and fetch them; return a script if any."""
        urls = [a for a in argv if URL_RE.match(a)] or URL_RE.findall(
            " ".join(argv)
        )
        script = None
        for u in urls:
            if u not in obs.urls:
                obs.urls.append(u)
            if self.on_download:
                text = self.on_download(u)
                script = script or text
        return script

    def _run_simple(
        self,
        argv: list[str],
        name: str,
        stdin: str,
        obs: Observation,
        depth: int,
    ) -> str:
        """Emulate one simple command; stdin is the previous stage's output.

        A handler returning None falls through to the text filters, and
        anything unknown (chmod, rm, mkdir, cd, kill, crontab, ./binary
        ...) succeeds silently.
        """
        if not argv:
            return ""
        static = STATIC_OUTPUT.get(name)
        if static is not None:
            return static
        handler = self._HANDLERS.get(name)
        if handler is not None:
            call = _Call(argv, name, argv[1:], stdin, obs, depth)
            result = handler(self, call)
            if result is not None:
                return result
        if name in TEXT_FILTERS:
            return _filter(name, argv[1:], stdin)
        return ""

    def _cmd_sh(self, c: "_Call") -> str | None:
        """sh/bash/... -c CMD, also busybox -c and busybox APPLET."""
        if "-c" in c.args:
            i = c.args.index("-c")
            return self.run_shell(
                c.args[i + 1] if i + 1 < len(c.args) else "",
                c.obs,
                c.depth + 1,
            )
        if c.name == "busybox" and c.args:
            return self._run_simple(
                c.args, os_basename(c.args[0]), c.stdin, c.obs, c.depth
            )
        return None

    def _cmd_wrapper(self, c: "_Call") -> str | None:
        """nohup/setsid/timeout/sudo/exec/env: run the wrapped command."""
        if not c.args:
            return None
        rest = c.args[1:] if c.name == "timeout" else c.args
        return self._run_simple(
            rest, os_basename(rest[0]) if rest else "", c.stdin, c.obs, c.depth
        )

    def _cmd_interpreter(self, c: "_Call") -> str | None:
        """python/perl/php -c|-r|-e CODE; only PHP code is emulated."""
        flag = next((f for f in ("-c", "-r", "-e") if f in c.args), None)
        if flag is None:
            return None
        i = c.args.index(flag)
        code = c.args[i + 1] if i + 1 < len(c.args) else ""
        c.obs.merge_iocs(code)
        if c.name == "php":
            return self.run_php(code, c.obs, c.depth + 1)
        return ""

    def _cmd_php(self, c: "_Call") -> str | None:
        """php -r CODE or php -v."""
        result = self._cmd_interpreter(c)
        if result is not None:
            return result
        if "-v" in c.args or "--version" in c.args:
            return (
                f"PHP {self.php_version} (cli) "
                "(built: Apr 11 2024 20:23:38) (NTS)\n"
                "Copyright (c) The PHP Group\n"
            )
        return None

    def _cmd_echo(self, c: "_Call") -> str:
        """echo [-n|-e|-ne|-en] WORDS."""
        flags = {"-n", "-e", "-ne", "-en"}
        words = [a for a in c.args if a not in flags]
        no_newline = "-n" in c.args or "-ne" in c.args or "-en" in c.args
        return " ".join(words) + ("" if no_newline else "\n")

    def _cmd_printf(self, c: "_Call") -> str:
        """printf FORMAT, only \\n escapes are expanded."""
        return c.args[0].replace("\\n", "\n") if c.args else ""

    def _cmd_base64(self, c: "_Call") -> str:
        """base64 [-d|--decode] on stdin."""
        if "-d" in c.args or "--decode" in c.args:
            return try_b64(c.stdin.strip()) or ""
        return base64.b64encode(c.stdin.encode()).decode() + "\n"

    def _cmd_hostname(self, _c: "_Call") -> str:
        """hostname."""
        return self.hostname + "\n"

    def _cmd_uname(self, c: "_Call") -> str:
        """uname [-a|-m|-r]."""
        if "-a" in c.args:
            return (
                f"Linux {self.hostname} 6.8.0-45-generic #45-Ubuntu SMP "
                "PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024 "
                "x86_64 x86_64 x86_64 GNU/Linux\n"
            )
        if "-m" in c.args:
            return "x86_64\n"
        if "-r" in c.args:
            return "6.8.0-45-generic\n"
        return "Linux\n"

    def _cmd_cat(self, c: "_Call") -> str | None:
        """cat FILE for a few well-known files; plain cat filters stdin."""
        if not [a for a in c.args if not a.startswith("-")]:
            return None
        f = c.args[-1]
        if f == "/etc/hostname":
            return self.hostname + "\n"
        content = FAKE_FILES.get(f)
        if content is not None:
            return content
        return f"cat: {f}: No such file or directory\n"

    def _cmd_ls(self, c: "_Call") -> str:
        """ls [-l...] of the web root."""
        if any(a.startswith("-") and "l" in a for a in c.args):
            return LS_LONG
        return LS_SHORT

    def _cmd_ip(self, c: "_Call") -> str | None:
        """ip a|addr|address."""
        if c.args[:1] in (["a"], ["addr"], ["address"]):
            return IP_ADDR
        return None

    def _cmd_which(self, c: "_Call") -> str | None:
        """which NAME..., only for a few installed tools."""
        if not c.args:
            return None
        return "".join(WHICH[a] + "\n" for a in c.args if a in WHICH)

    def _cmd_download(self, c: "_Call") -> str:
        """wget/curl/tftp/ftpget: record URLs, maybe fetch the payload."""
        text = self._download(c.argv, c.obs)
        # curl without -o writes to stdout
        if c.name == "curl" and not any(
            a in ("-o", "-O", "--output", "--remote-name") for a in c.args
        ):
            return text or ""
        return ""

    _HANDLERS: dict[str, Callable[["FakeShell", "_Call"], str | None]] = {
        **dict.fromkeys(("sh", "bash", "ash", "dash", "zsh"), _cmd_sh),
        "busybox": _cmd_sh,
        **dict.fromkeys(
            ("nohup", "setsid", "timeout", "sudo", "exec", "env"),
            _cmd_wrapper,
        ),
        **dict.fromkeys(("python", "python3", "perl"), _cmd_interpreter),
        "php": _cmd_php,
        "echo": _cmd_echo,
        "printf": _cmd_printf,
        "base64": _cmd_base64,
        "hostname": _cmd_hostname,
        "uname": _cmd_uname,
        "cat": _cmd_cat,
        "ls": _cmd_ls,
        "ip": _cmd_ip,
        "which": _cmd_which,
        **dict.fromkeys(("wget", "curl", "tftp", "ftpget"), _cmd_download),
    }


LS_LONG = """total 64
drwxr-xr-x  5 www-data www-data 4096 Oct  8 09:14 .
drwxr-xr-x  3 root     root     4096 Mar 12  2025 ..
-rw-r--r--  1 www-data www-data  412 Mar 12  2025 config.inc.php
-rw-r--r--  1 www-data www-data 7810 Oct  8 09:14 index.php
-rw-r--r--  1 www-data www-data   20 Mar 12  2025 phpinfo.php
-rw-r--r--  1 www-data www-data  981 Mar 12  2025 progress.php
-rw-r--r--  1 www-data www-data 2304 Mar 12  2025 upload.php
drwxrwxr-x  3 www-data www-data 4096 Oct 22 11:02 uploads
drwxr-xr-x 14 www-data www-data 4096 Mar 12  2025 vendor
"""

LS_SHORT = (
    "index.php\nupload.php\nprogress.php\nphpinfo.php\nuploads\n"
    "config.inc.php\nvendor\n"
)

CPU_MODEL = "Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz"

IP_ADDR = (
    "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
    "    inet 10.20.4.17/24 brd 10.20.4.255 scope global eth0\n"
)

# commands whose output never depends on arguments or state
STATIC_OUTPUT = {
    "id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
    "whoami": "www-data\n",
    "pwd": "/var/www/html\n",
    "nproc": "4\n",
    "lscpu": (
        f"Architecture: x86_64\nCPU(s): 4\nModel name: {CPU_MODEL}\n"
    ),
    "free": (
        "               total        used        free      shared"
        "  buff/cache   available\n"
        "Mem:         8131224     2011548     3121004       40212"
        "     3285104     6119676\n"
        "Swap:        2097148           0     2097148\n"
    ),
    "df": (
        "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
        "/dev/sda1       81120924 14312208  66792332  18% /\n"
    ),
    "ps": (
        "    PID TTY          TIME CMD\n"
        "   1123 ?        00:00:03 apache2\n"
        "   1187 ?        00:00:00 apache2\n"
        "   1190 ?        00:00:00 apache2\n"
        "   2204 ?        00:00:00 sh\n"
        "   2205 ?        00:00:00 ps\n"
    ),
    "ifconfig": IP_ADDR,
}

# files `cat` knows (/etc/hostname is derived from the persona)
FAKE_FILES = {
    "/etc/passwd": PASSWD,
    "/etc/os-release": OS_RELEASE,
    "/usr/lib/os-release": OS_RELEASE,
    # 4 CPUs, matching nproc/lscpu
    "/proc/cpuinfo": "".join(
        f"processor\t: {i}\nvendor_id\t: GenuineIntel\n"
        f"model name\t: {CPU_MODEL}\n"
        "cpu cores\t: 4\n\n"
        for i in range(4)
    ),
    "/proc/version": (
        "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-115) "
        "(x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0) "
        "#45-Ubuntu SMP\n"
    ),
}

WHICH = {
    "curl": "/usr/bin/curl",
    "wget": "/usr/bin/wget",
    "python3": "/usr/bin/python3",
    "perl": "/usr/bin/perl",
    "php": "/usr/bin/php",
    "bash": "/usr/bin/bash",
    "nc": "/usr/bin/nc",
}

TEXT_FILTERS = {
    "cat",
    "head",
    "tail",
    "grep",
    "egrep",
    "wc",
    "sort",
    "uniq",
    "cut",
    "awk",
    "tr",
}


def _count_arg(args: list[str], default: int = 10) -> int:
    """-n N, -nN, -N"""
    for i, a in enumerate(args):
        if (
            a == "-n"
            and i + 1 < len(args)
            and args[i + 1].lstrip("-").isdigit()
        ):
            return int(args[i + 1].lstrip("-"))
        if re.fullmatch(r"-n?\d+", a):
            return int(a.lstrip("-n"))
    return default


def _tr_set(spec: str) -> str:
    """Expand tr ranges and classes: a-z, [:upper:]."""
    spec = (
        spec.replace("[:upper:]", "A-Z")
        .replace("[:lower:]", "a-z")
        .replace("[:digit:]", "0-9")
    )
    return re.sub(
        r"(.)-(.)",
        lambda m: "".join(chr(c) for c in range(ord(m[1]), ord(m[2]) + 1)),
        spec,
    )


def _f_cat(_args: list[str], stdin: str, _lines: list[str]) -> str:
    """cat with no file: pass stdin through."""
    return stdin


def _f_head(args: list[str], _stdin: str, lines: list[str]) -> str:
    """head [-n N]."""
    return "".join(lines[:_count_arg(args)])


def _f_tail(args: list[str], _stdin: str, lines: list[str]) -> str:
    """tail [-n N]."""
    n = _count_arg(args)
    return "".join(lines[-n:]) if n else ""


def _f_grep(args: list[str], _stdin: str, lines: list[str]) -> str:
    """grep/egrep [-i] [-v] [-c] PATTERN."""
    flags = "".join(
        a[1:] for a in args if a.startswith("-") and not a.startswith("--")
    )
    words = [a for a in args if not a.startswith("-")]
    if not words:
        return ""
    try:
        rx = re.compile(words[0], re.I if "i" in flags else 0)
    except re.error:
        rx = re.compile(re.escape(words[0]), re.I if "i" in flags else 0)
    hits = [
        line for line in lines if bool(rx.search(line)) != ("v" in flags)
    ]
    return f"{len(hits)}\n" if "c" in flags else "".join(hits)


def _f_wc(args: list[str], stdin: str, _lines: list[str]) -> str:
    """wc [-l] [-w] [-c]."""
    counts = {
        "l": stdin.count("\n"),
        "w": len(stdin.split()),
        "c": len(stdin.encode()),
    }
    sel = [
        k for k in "lwc" if any(a.startswith("-") and k in a for a in args)
    ] or ["l", "w", "c"]
    return (
        " ".join(str(counts[k]) for k in sel)
        if len(sel) == 1
        else " ".join(f"{counts[k]:7}" for k in sel)
    ) + "\n"


def _f_sort(args: list[str], _stdin: str, lines: list[str]) -> str:
    """sort [-r]."""
    return "".join(sorted(lines, reverse="-r" in args))


def _f_uniq(_args: list[str], _stdin: str, lines: list[str]) -> str:
    """uniq: drop adjacent duplicate lines."""
    out = [
        line
        for i, line in enumerate(lines)
        if i == 0 or line != lines[i - 1]
    ]
    return "".join(out)


def _f_cut(args: list[str], _stdin: str, lines: list[str]) -> str:
    """cut -d DELIM -f LIST."""
    delim = next(
        (
            a[2:] or (args[i + 1] if i + 1 < len(args) else "\t")
            for i, a in enumerate(args)
            if a.startswith("-d")
        ),
        "\t",
    )
    spec = next(
        (
            a[2:] or (args[i + 1] if i + 1 < len(args) else "1")
            for i, a in enumerate(args)
            if a.startswith("-f")
        ),
        "1",
    )
    fields = [int(f) for f in re.findall(r"\d+", spec)]
    return "".join(
        delim.join(p[f - 1] for f in fields if f <= len(p)) + "\n"
        for p in (line.rstrip("\n").split(delim) for line in lines)
    )


def _f_awk(args: list[str], stdin: str, lines: list[str]) -> str:
    """awk [-FSEP] '{print $N, ...}'."""
    prog = next((a for a in args if "print" in a), "")
    sep = next((a[2:] for a in args if a.startswith("-F")), None)
    cols = [int(c) for c in re.findall(r"\$(\d+)", prog)]
    if not cols:
        return stdin if "print" in prog else ""
    out = []
    for line in lines:
        parts = line.rstrip("\n").split(sep) if sep else line.split()
        out.append(
            " ".join(
                (
                    parts[c - 1]
                    if 0 < c <= len(parts)
                    else (line.rstrip("\n") if c == 0 else "")
                )
                for c in cols
            )
            + "\n"
        )
    return "".join(out)


def _f_tr(args: list[str], stdin: str, _lines: list[str]) -> str:
    """tr SET1 SET2 or tr -d SET."""
    words = [_tr_set(a) for a in args if not a.startswith("-")]
    if "-d" in args and words:
        return "".join(ch for ch in stdin if ch not in words[0])
    if len(words) == 2 and len(words[0]) == len(words[1]):
        return stdin.translate(str.maketrans(words[0], words[1]))
    return stdin


_FILTERS: dict[str, Callable[[list[str], str, list[str]], str]] = {
    "cat": _f_cat,
    "head": _f_head,
    "tail": _f_tail,
    "grep": _f_grep,
    "egrep": _f_grep,
    "wc": _f_wc,
    "sort": _f_sort,
    "uniq": _f_uniq,
    "cut": _f_cut,
    "awk": _f_awk,
    "tr": _f_tr,
}


def _filter(name: str, args: list[str], stdin: str) -> str:
    """Apply text filter `name` (one of TEXT_FILTERS) to stdin."""
    func = _FILTERS.get(name)
    if func is None:
        return ""
    return func(args, stdin, stdin.splitlines(keepends=True))


def os_basename(p: str) -> str:
    """Last path component, like basename(1)."""
    return p.rsplit("/", 1)[-1]


def _argv(s: str) -> list[str]:
    """Tokenize a simple command, dropping redirections."""
    s = re.sub(r"\s*(?:\d?>>?|2>&1|&>)\s*\S*", " ", s)  # drop redirections
    try:
        return shlex.split(s, posix=True)
    except ValueError:
        return s.split()


def _split_unquoted(s: str, sep: str) -> list[str]:
    """Split s on sep outside single/double quotes ("|" skips "||")."""
    out, buf, q = [], [], None
    i = 0
    while i < len(s):
        c = s[i]
        if q:
            if c == q:
                q = None
            buf.append(c)
        elif c in "'\"":
            q = c
            buf.append(c)
        elif s.startswith(sep, i) and not (
            sep == "|" and s.startswith("||", i)
        ):
            out.append("".join(buf))
            buf = []
            i += len(sep)
            continue
        else:
            buf.append(c)
        i += 1
    out.append("".join(buf))
    return out


def _split_sequence(s: str) -> list[str]:
    """Split a command line on newlines, ;, && and ||."""
    parts = [s]
    for sep in ("\n", ";", "&&", "||"):
        nxt = []
        for p in parts:
            nxt.extend(_split_unquoted(p, sep))
        parts = nxt
    # a trailing single "&" (background) is just stripped
    return [p.strip().rstrip("&").strip() for p in parts if p.strip()]
