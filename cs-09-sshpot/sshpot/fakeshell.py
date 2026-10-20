"""A fake shell. It interprets a handful of commands with canned output.

Nothing here executes a command, touches the real filesystem or opens a network
connection: output is built from constants and the (escaped) arguments. Pipes and
redirections are parsed and ignored. Anything unknown is "command not found".
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlparse

URL_RE = re.compile(r"(?:https?|ftp|tftp)://[^\s'\"<>;|&`]+", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MAX_COMMAND_LEN = 4096

PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "sshd:x:106:65534::/run/sshd:/usr/sbin/nologin\n"
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
)
OS_RELEASE = (
    'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
    'VERSION="22.04.3 LTS (Jammy Jellyfish)"\nID=ubuntu\nID_LIKE=debian\n'
)
CPUINFO = (
    "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\n"
    "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\ncpu MHz\t\t: 2399.998\n"
    "cache size\t: 35840 KB\n\n"
)
FILES = {
    "/etc/passwd": PASSWD,
    "/etc/hostname": "{host}\n",
    "/etc/os-release": OS_RELEASE,
    "/proc/cpuinfo": CPUINFO,
    "/proc/version": "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-045) "
    "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #101-Ubuntu SMP\n",
    "/root/.bash_history": "",
}
DIRS = {
    "/": "bin  boot  dev  etc  home  lib  opt  proc  root  run  tmp  usr  var",
    "/root": "",
    "/etc": "hostname  os-release  passwd  ssh  shadow",
    "/tmp": "",
    "/home": "ubuntu",
    "/home/ubuntu": "",
    "/var": "log  tmp  www",
    "/var/log": "auth.log  syslog",
    "/var/www": "html",
    "/proc": "cpuinfo  version  meminfo",
}
SILENT = {
    "chmod",
    "chown",
    "rm",
    "mkdir",
    "touch",
    "export",
    "sleep",
    "kill",
    "pkill",
    "killall",
    "crontab",
    "service",
    "systemctl",
    "nohup",
    "sh",
    "bash",
    "unset",
    "source",
    "mv",
    "cp",
    "ln",
    "clear",
    "reset",
    "set",
    "alias",
    "umask",
    "true",
    "nice",
    "setsid",
    "screen",
    "tmux",
    "iptables",
    "ulimit",
    "echo_off",
}


@dataclass
class ShellResult:
    output: str
    status: int = 0
    exit: bool = False
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)


def indicators(line: str) -> tuple[list[str], list[str]]:
    """URLs and IPv4 addresses mentioned in a command line (deduplicated, ordered)."""
    urls = list(dict.fromkeys(URL_RE.findall(line)))
    ips = [ip for ip in dict.fromkeys(IPV4_RE.findall(line)) if _valid_ip(ip)]
    return urls, ips


def _valid_ip(ip: str) -> bool:
    return all(int(p) <= 255 for p in ip.split("."))


OP_RE = re.compile(r"^[;&|<>]+$")


def _split(line: str) -> list[tuple[str, list[str], bool]]:
    """Tokenize into [(operator-before, argv, stdout_discarded)].

    Redirections are consumed (and a redirect of stdout discards the output, as a real
    shell would); pipelines keep only their first stage.
    """
    lex = shlex.shlex(line, posix=True, punctuation_chars=";&|<>")
    lex.whitespace_split = True
    tokens = list(lex)
    segments: list[tuple[str, list[str], bool]] = []
    op, argv, discard = ";", [], False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        i += 1
        if OP_RE.match(tok) and ("<" in tok or ">" in tok):
            fd = argv[-1] if argv and argv[-1].isdigit() else ""
            if fd:
                argv.pop()  # `2>file`: the 2 is a file descriptor, not an argument
            if fd != "2" and ">" in tok:
                discard = True
            i += 1  # the redirection target
        elif OP_RE.match(tok):
            if argv:
                segments.append((op, argv, discard))
            op = tok if tok in (";", "&&", "||", "|") else ";"
            argv, discard = [], False
        else:
            argv.append(tok)
    if argv:
        segments.append((op, argv, discard))
    return segments


class FakeShell:
    def __init__(self, hostname: str = "srv04", user: str = "root"):
        self.hostname = hostname
        self.user = user
        self.cwd = "/root" if user == "root" else f"/home/{user}"

    @property
    def prompt(self) -> str:
        sigil = "#" if self.user == "root" else "$"
        shown = "~" if self.cwd in ("/root", f"/home/{self.user}") else self.cwd
        return f"{self.user}@{self.hostname}:{shown}{sigil} "

    def run(self, line: str) -> ShellResult:
        urls, ips = indicators(line)
        result = ShellResult("", 0, False, urls, ips)
        line = line.strip()
        if not line:
            return result
        if len(line) > MAX_COMMAND_LEN:
            result.output, result.status = "bash: argument list too long\n", 126
            return result
        try:
            segments = _split(line)
        except ValueError:
            result.output = "bash: unexpected EOF while looking for matching quote\n"
            result.status = 2
            return result
        out, status = [], 0
        for op, argv, discard in segments:
            if op == "|":  # later pipeline stages are ignored
                continue
            if (op == "&&" and status != 0) or (op == "||" and status == 0):
                continue
            text, status, leave = self._command(argv)
            out.append("" if discard else text)
            if leave:
                result.exit = True
                break
        result.output = "".join(out)
        result.status = status
        return result

    # --- commands ---------------------------------------------------------------

    def _abs(self, path: str) -> str:
        if not path.startswith("/"):
            path = f"{self.cwd.rstrip('/')}/{path}"
        parts: list[str] = []
        for p in path.split("/"):
            if p in ("", "."):
                continue
            if p == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(p)
        return "/" + "/".join(parts)

    def _command(self, argv: list[str]) -> tuple[str, int, bool]:
        while argv and argv[0] in ("sudo", "nohup", "time", "env") and len(argv) > 1:
            argv = argv[1:]
        name, args = argv[0], argv[1:]
        handler = getattr(self, f"cmd_{name.replace('-', '_')}", None)
        if handler is not None and name.isidentifier():
            return handler(args)
        if name in SILENT:
            return "", 0, False
        if "/" in name:
            return f"bash: {name}: No such file or directory\n", 127, False
        return f"{name}: command not found\n", 127, False

    def cmd_exit(self, args):
        return "", 0, True

    cmd_logout = cmd_exit

    def cmd_whoami(self, args):
        return f"{self.user}\n", 0, False

    def cmd_id(self, args):
        if self.user == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n", 0, False
        return (
            f"uid=1000({self.user}) gid=1000({self.user}) groups=1000({self.user})\n",
            0,
            False,
        )

    def cmd_pwd(self, args):
        return f"{self.cwd}\n", 0, False

    def cmd_hostname(self, args):
        return f"{self.hostname}\n", 0, False

    def cmd_uname(self, args):
        full = (
            f"Linux {self.hostname} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 "
            "13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"
        )
        if not args:
            return "Linux\n", 0, False
        if "-r" in args:
            return "5.15.0-91-generic\n", 0, False
        if "-m" in args:
            return "x86_64\n", 0, False
        return full, 0, False

    def cmd_uptime(self, args):
        return (
            " 10:42:17 up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n",
            0,
            False,
        )

    def cmd_w(self, args):
        return (
            (
                " 10:42:17 up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n"
                "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                f"{self.user:<8} pts/0    10.0.0.2         10:41    0.00s  0.01s  0.00s w\n"
            ),
            0,
            False,
        )

    def cmd_who(self, args):
        return f"{self.user}   pts/0        2026-10-20 10:41 (10.0.0.2)\n", 0, False

    def cmd_ls(self, args):
        paths = [a for a in args if not a.startswith("-")]
        target = self._abs(paths[0]) if paths else self.cwd
        if target in DIRS:
            listing = DIRS[target]
            return (listing + "\n" if listing else ""), 0, False
        if target in FILES:
            return f"{target}\n", 0, False
        return f"ls: cannot access '{paths[0]}': No such file or directory\n", 2, False

    def cmd_cd(self, args):
        target = self._abs(args[0]) if args else "/root"
        if target in DIRS:
            self.cwd = target
            return "", 0, False
        return f"bash: cd: {args[0]}: No such file or directory\n", 1, False

    def cmd_cat(self, args):
        out, status = [], 0
        for a in args:
            if a.startswith("-"):
                continue
            path = self._abs(a)
            if path in FILES:
                out.append(FILES[path].format(host=self.hostname))
            elif path in DIRS:
                out.append(f"cat: {a}: Is a directory\n")
                status = 1
            else:
                out.append(f"cat: {a}: No such file or directory\n")
                status = 1
        return "".join(out), status, False

    def cmd_echo(self, args):
        args = [a for a in args if a not in ("-n", "-e")]
        return " ".join(args) + "\n", 0, False

    def cmd_ps(self, args):
        return (
            (
                "    PID TTY          TIME CMD\n"
                "      1 ?        00:00:03 systemd\n"
                "    522 ?        00:00:00 sshd\n"
                "   1311 pts/0    00:00:00 bash\n"
                "   1344 pts/0    00:00:00 ps\n"
            ),
            0,
            False,
        )

    def cmd_free(self, args):
        return (
            (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:         3929860      612304     2511228        1264      806328     3081412\n"
                "Swap:              0           0           0\n"
            ),
            0,
            False,
        )

    def cmd_df(self, args):
        return (
            (
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        39G  6.1G   31G  17% /\n"
                "tmpfs           1.9G     0  1.9G   0% /dev/shm\n"
            ),
            0,
            False,
        )

    def cmd_nproc(self, args):
        return "2\n", 0, False

    def cmd_ifconfig(self, args):
        return (
            (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n"
                "        ether 52:54:00:12:34:56  txqueuelen 1000  (Ethernet)\n"
            ),
            0,
            False,
        )

    cmd_ip = cmd_ifconfig

    def cmd_history(self, args):
        return "", 0, False

    def cmd_wget(self, args):
        return self._fetch("wget", args)

    def cmd_curl(self, args):
        return self._fetch("curl", args)

    def _fetch(self, tool: str, args: list[str]):
        """Never fetches anything: always a name-resolution failure."""
        url = next((a for a in args if not a.startswith("-")), "")
        host = urlparse(url if "://" in url else f"http://{url}").hostname or url
        if tool == "curl":
            return f"curl: (6) Could not resolve host: {host}\n", 6, False
        return f"wget: unable to resolve host address '{host}'\n", 4, False
