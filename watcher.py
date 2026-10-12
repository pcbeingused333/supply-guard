#!/usr/bin/env python3
"""supply-guard watcher: alert when something unexpected opens a secret file.

Watches credential files (gh, ssh keys, cloud/registry tokens, .env at project
roots) with inotify, which needs no root. inotify doesn't say *who* opened a
file, so on each open we look in /proc for (a) a process still holding it open
and (b) processes started in the last few seconds, and judge from those. That
attribution is best-effort and every alert says how it was made.

Known-good readers (gh, git, ssh, Claude Code, editors...) are silent. Anything
else is logged, shown as a Windows toast, and printed at the next zsh prompt.

  watcher.py run                 # foreground (systemd runs this)
  watcher.py alerts [--all]      # show unseen (or all) alerts and mark them seen
"""
from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import re
import select
import struct
import subprocess
import sys
import time
from pathlib import Path

HOME = Path.home()
STATE = Path(os.environ.get("XDG_STATE_HOME", HOME / ".local/state")) / "supply-guard"
ALERTS = STATE / "alerts.jsonl"
SEEN = STATE / "alerts.seen"

# Files and directories whose contents are credentials. Missing ones are skipped
# and re-checked every RESCAN seconds, so a token created later gets watched.
SECRET_FILES = [
    ".config/gh/hosts.yml", ".git-credentials", ".netrc", ".npmrc", ".pypirc",
    ".gem/credentials", ".docker/config.json", ".aws/credentials", ".aws/config",
    ".kube/config", ".claude/.credentials.json", ".config/hub", ".cargo/credentials.toml",
    ".config/gcloud/credentials.db", ".config/gcloud/application_default_credentials.json",
    ".azure/msal_token_cache.json", ".terraform.d/credentials.tfrc.json",
]
SECRET_DIRS = {  # dir -> filename predicate (True = secret)
    ".ssh": lambda n: n.startswith("id_") and not n.endswith(".pub") or n.endswith((".pem", ".key")),
    ".gnupg/private-keys-v1.d": lambda n: True,
}
ENV_ROOTS = [HOME / "projects", HOME / "tools", HOME / "job-search"]  # .env at <root>/<project>/
ENV_NAMES = lambda n: n == ".env" or n.startswith(".env.") and not n.endswith((".example", ".sample", ".template"))

# Who may read what, by category. A reader matches on comm, exe basename or the
# basename of argv[0]. Deliberately per category and never "any shell": a
# postinstall script runs under sh/node, often below an allowed parent.
CATEGORY = [  # (path predicate on the path relative to $HOME, category)
    (lambda r: r == ".config/gh/hosts.yml" or r == ".config/hub", "gh"),
    (lambda r: r.startswith(".ssh/"), "ssh"),
    (lambda r: r in (".git-credentials", ".netrc"), "git"),
    (lambda r: r == ".npmrc", "npm"),
    (lambda r: r == ".pypirc", "pypi"),
    (lambda r: r == ".gem/credentials", "gem"),
    (lambda r: r == ".docker/config.json", "docker"),
    (lambda r: r.startswith(".aws/"), "aws"),
    (lambda r: r == ".kube/config", "kube"),
    (lambda r: r.startswith((".config/gcloud/", ".azure/")), "cloud"),
    (lambda r: r == ".claude/.credentials.json", "claude"),
    (lambda r: r == ".cargo/credentials.toml", "cargo"),
    (lambda r: r == ".terraform.d/credentials.tfrc.json", "terraform"),
    (lambda r: r.startswith(".gnupg/"), "gpg"),
]
READERS = {
    "gh": {"gh", "git-credential-gh"},
    "ssh": {"ssh", "ssh-add", "ssh-keygen", "scp", "sftp", "ssh-agent", "sshd"},
    "git": {"git", "git-remote-https", "git-remote-http", "git-credential-store", "git-credential-netrc", "curl", "wget", "gh"},
    "npm": {"npm", "npm-cli.js", "npx", "npx-cli.js", "pnpm", "yarn", "corepack"},
    "pypi": {"twine", "uv", "hatch", "poetry", "flit", "pdm"},
    "gem": {"gem", "bundle", "bundler"},
    "docker": {"docker", "docker-credential-desktop.exe", "docker-credential-wincred.exe", "com.docker.cli"},
    "aws": {"aws", "terraform", "sam", "cdk"},
    "kube": {"kubectl", "helm", "k9s"},
    "cloud": {"gcloud", "az", "terraform"},
    "claude": {"claude"},
    "cargo": {"cargo"},
    "terraform": {"terraform"},
    "gpg": {"gpg", "gpg-agent", "gpg2"},
}
# Readers recognised by command line (node/python run both real tools and
# install scripts, so their name proves nothing).
READERS_CMDLINE = {
    "claude": ("@anthropic-ai/claude-code", "/.claude/local/", "/bin/claude", "/claude/versions/"),
    "cloud": ("/google-cloud-sdk/",),
    "aws": ("/aws-cli/",),
    "npm": ("/npm/bin/npm-cli.js", "/npm/bin/npx-cli.js"),
}
# Long-running processes that re-read their own token: if one is alive, an open
# we couldn't attribute is theirs.
OWNERS = {"claude": READERS_CMDLINE["claude"]}
INSTALL_MARKERS = re.compile(
    r"(?:^|/)(?:npm|pnpm|yarn)(?:-cli\.js)? (?:i|install|add|ci|update)\b|pip3? install|uv (?:pip install|add|sync|tool install)"
    r"|uvx |gem install|bundle(?: install)?$|node_modules/|site-packages/.*(?:setup|install)|postinstall|preinstall"
)
# A legit reader started this recently explains an open we couldn't pin exactly.
RECENT_S = 3.0
DEDUPE_S = float(os.environ.get("SG_DEDUPE_S", 60))
RESCAN = 300.0

IN_OPEN, IN_CREATE, IN_MOVED_TO = 0x20, 0x100, 0x80
IN_Q_OVERFLOW, IN_IGNORED, IN_NONBLOCK, IN_CLOEXEC = 0x4000, 0x8000, 0o4000, 0o2000000
EV = struct.Struct("iIII")
CLK_TCK = os.sysconf("SC_CLK_TCK")


# ------------------------------------------------------------------ /proc

def uptime() -> float:
    """Seconds since boot, on the same clock as /proc/<pid>/stat starttime.
    (btime + wall clock drifts by a second or more under WSL.)"""
    return float(Path("/proc/uptime").read_text().split()[0])


def proc_info(pid: int) -> dict | None:
    try:
        p = Path(f"/proc/{pid}")
        stat = (p / "stat").read_text()
        comm = stat[stat.index("(") + 1 : stat.rindex(")")]
        fields = stat[stat.rindex(")") + 2 :].split()
        ppid, start = int(fields[1]), int(fields[19]) / CLK_TCK
        cmd = (p / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
        try:
            exe = os.readlink(p / "exe")
        except OSError:
            exe = ""
        try:
            cwd = os.readlink(p / "cwd")
        except OSError:
            cwd = ""
        return {"pid": pid, "ppid": ppid, "comm": comm, "exe": exe, "cmd": cmd[:400], "cwd": cwd, "start": start}
    except (OSError, ValueError, IndexError):
        return None


def my_pids() -> list[int]:
    uid = os.getuid()
    out = []
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                if os.stat(f"/proc/{d}").st_uid == uid:
                    out.append(int(d))
            except OSError:
                pass
    return out


def holders(path: str, pids: list[int]) -> list[int]:
    out = []
    for pid in pids:
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                try:
                    if os.readlink(f"/proc/{pid}/fd/{fd}") == path:
                        out.append(pid)
                        break
                except OSError:
                    pass
        except OSError:
            pass
    return out


def ancestry(info: dict, limit: int = 6) -> list[dict]:
    chain, seen = [], set()
    cur = info
    while cur and cur["pid"] not in seen and len(chain) < limit:
        chain.append(cur)
        seen.add(cur["pid"])
        cur = proc_info(cur["ppid"]) if cur["ppid"] > 1 else None
    return chain


def category(path: str, home: Path = HOME) -> str:
    try:
        rel = str(Path(path).relative_to(home))
    except ValueError:
        return "env"
    for pred, cat in CATEGORY:
        if pred(rel):
            return cat
    return "env"


def names(info: dict) -> set[str]:
    return {n for n in (info["comm"], os.path.basename(info["exe"]), os.path.basename(info["cmd"].split(" ", 1)[0])) if n}


def is_reader(info: dict, cat: str) -> bool:
    if names(info) & READERS.get(cat, set()):
        return True
    return any(s in info["cmd"] or s in info["exe"] for s in READERS_CMDLINE.get(cat, ()))


def in_install(info: dict) -> bool:
    """Whether this process runs inside a package install. Computed while the
    process tree is still alive (attribute() stores it), since installs end fast."""
    if "during_install" in info:
        return info["during_install"]
    return any(INSTALL_MARKERS.search(a["cmd"]) or "node_modules" in a["cwd"] for a in ancestry(info, 10))


def attribute(path: str, home: Path = HOME) -> tuple[str, list[dict]] | None:
    """None = nothing to report. Otherwise (method, suspects):
    holder  = caught a process with the file open (exact),
    recent  = guessed from processes started in the last RECENT_S seconds,
    unknown = nothing to go on (something long-running read it and closed it)."""
    cat = category(path, home)
    now = uptime()
    me = os.getpid()
    pids = [p for p in my_pids() if p != me]
    infos = {p: i for p in pids if (i := proc_info(p))}
    held = [infos[p] for p in holders(path, list(infos)) if p in infos]
    if held:
        suspects = [i for i in held if not is_reader(i, cat)]
        method = "holder"
    else:
        recent = [i for i in infos.values() if now - i["start"] <= RECENT_S]
        if any(is_reader(i, cat) for i in recent):
            return None
        owners = OWNERS.get(cat, ())
        if owners and any(o in i["cmd"] or o in i["exe"] for i in infos.values() for o in owners):
            return None
        # Shells and our own ancestors started by the user aren't suspects by
        # themselves; keep them only if nothing more specific is there.
        recent.sort(key=lambda i: i["start"], reverse=True)  # newest first: likeliest culprit
        specific = [i for i in recent if i["comm"] not in ("sh", "bash", "zsh", "dash", "sleep", "tail", "head")
                    and not is_reader(i, "claude") and "/claude/versions/" not in i["exe"]]
        suspects, method = (specific or recent), ("recent" if recent else "unknown")
    if not suspects and method == "holder":
        return None
    for s in suspects:  # snapshot the tree now; it may be gone by the time we alert
        chain = ancestry(s, 10)
        s["chain"] = [f"{a['pid']} {a['comm']}: {a['cmd'][:120]}" for a in chain]
        s["during_install"] = any(INSTALL_MARKERS.search(a["cmd"]) or "node_modules" in a["cwd"] for a in chain)
    if cat == "env":
        # Apps reading their own .env is normal; only installs touching it isn't.
        suspects = [i for i in suspects if in_install(i)]
        if not suspects:
            return None
    return method, suspects


# --------------------------------------------------------------- inotify

class Inotify:
    def __init__(self) -> None:
        self.libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        self.fd = self.libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1")
        self.wd: dict[int, tuple[Path, str]] = {}  # wd -> (path, kind)

    def add(self, path: Path, mask: int, kind: str) -> None:
        wd = self.libc.inotify_add_watch(self.fd, os.fsencode(path), mask)
        if wd >= 0:
            self.wd[wd] = (path, kind)

    def read(self, timeout: float) -> list[tuple[int, int, str]]:
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return []
        try:
            buf = os.read(self.fd, 65536)
        except BlockingIOError:
            return []
        out, i = [], 0
        while i + EV.size <= len(buf):
            wd, mask, _cookie, ln = EV.unpack_from(buf, i)
            name = buf[i + EV.size : i + EV.size + ln].split(b"\0", 1)[0].decode(errors="replace")
            out.append((wd, mask, name))
            i += EV.size + ln
        return out


def setup(ino: Inotify, home: Path = HOME, env_roots: list[Path] = ENV_ROOTS) -> None:
    watched = {(p, k) for p, k in ino.wd.values()}
    for rel in SECRET_FILES:
        p = home / rel
        if p.is_file() and (p, "file") not in watched:
            ino.add(p, IN_OPEN, "file")
    for rel in SECRET_DIRS:
        p = home / rel
        if p.is_dir() and (p, rel) not in watched:
            ino.add(p, IN_OPEN, rel)
    for root in env_roots:
        if not root.is_dir():
            continue
        for proj in [root, *(d for d in root.iterdir() if d.is_dir() and not d.name.startswith("."))]:
            if (proj, "env") not in watched and any(ENV_NAMES(f.name) for f in proj.iterdir() if f.is_file()):
                ino.add(proj, IN_OPEN, "env")


def secret_path(path: Path, kind: str, name: str) -> str | None:
    if kind == "file":
        return str(path)
    if kind == "env":
        return str(path / name) if name and ENV_NAMES(name) else None
    pred = SECRET_DIRS.get(kind)
    return str(path / name) if name and pred and pred(name) else None


# ---------------------------------------------------------------- alerting

def toast(title: str, body: str) -> None:
    ps = (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null;"
        "$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
        "$x=$t.GetElementsByTagName('text');$x.Item(0).AppendChild($t.CreateTextNode($env:SG_T))|Out-Null;"
        "$x.Item(1).AppendChild($t.CreateTextNode($env:SG_B))|Out-Null;"
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('supply-guard').Show([Windows.UI.Notifications.ToastNotification]::new($t))"
    )
    try:
        subprocess.Popen(
            # conhost --headless: no console window flashes up (plain powershell.exe opens one)
            ["/mnt/c/WINDOWS/System32/conhost.exe", "--headless", "powershell.exe",
             "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps],
            env=dict(os.environ, SG_T=title, SG_B=body[:250], WSLENV="SG_T:SG_B"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError:
        pass


def alert(secret: str, method: str, suspects: list[dict], notify: bool = True) -> dict:
    top = suspects[0] if suspects else None
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "file": secret,
        "method": method,  # holder = caught with the file open; recent = guessed from what had just started
        "suspects": [{k: s[k] for k in ("pid", "comm", "cmd", "cwd")} for s in suspects[:5]],
        "chain": top["chain"][:6] if top else [],
        "during_install": any(in_install(s) for s in suspects),
    }
    STATE.mkdir(parents=True, exist_ok=True)
    with ALERTS.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    if notify and not os.environ.get("SG_NO_TOAST"):
        who = f"{top['comm']} (pid {top['pid']})" if top else "a long-running process (couldn't identify)"
        toast("supply-guard: secret read" + (" during a package install" if rec["during_install"] else ""), f"{who} opened {secret.replace(str(HOME), '~')}"
              + ("" if method == "holder" else " (attribution: best guess)"))
    return rec


def run() -> int:
    ino = Inotify()
    setup(ino)
    last_scan, recent_alerts = time.monotonic(), {}
    print(f"watching {len(ino.wd)} paths", flush=True)
    while True:
        events = ino.read(timeout=RESCAN)
        now = time.time()
        for wd, mask, name in events:
            if mask & IN_Q_OVERFLOW:
                print("inotify queue overflow", flush=True)
                continue
            if mask & IN_IGNORED:
                ino.wd.pop(wd, None)
                continue
            if wd not in ino.wd or not mask & IN_OPEN:
                continue
            path, kind = ino.wd[wd]
            secret = secret_path(path, kind, name)
            if not secret:
                continue
            verdict = attribute(secret)
            if verdict is None:
                continue
            method, suspects = verdict
            key = (secret, suspects[0]["comm"] if suspects else "")
            if now - recent_alerts.get(key, 0) < DEDUPE_S:
                continue
            recent_alerts[key] = now
            rec = alert(secret, method, suspects)
            print(json.dumps(rec), flush=True)
        if time.monotonic() - last_scan >= RESCAN:
            setup(ino)
            last_scan = time.monotonic()


def show(all_: bool) -> int:
    if not ALERTS.exists():
        return 0
    lines = ALERTS.read_text().splitlines()
    start = 0 if all_ else int(SEEN.read_text() or 0) if SEEN.exists() else 0
    for line in lines[start:]:
        r = json.loads(line)
        guess = {"holder": "", "recent": "  [best guess]", "unknown": "  [process not identified]"}[r["method"]]
        guess += "  DURING PACKAGE INSTALL" if r.get("during_install") else ""
        print(f"\033[31;1m[supply-guard] {r['ts']} {r['file'].replace(str(HOME), '~')} opened{guess}\033[0m")
        for s in r["suspects"][:3]:
            print(f"    pid {s['pid']} {s['comm']}: {s['cmd'][:160]}  (cwd {s['cwd']})")
        for c in r["chain"][1:]:
            print(f"      └ {c}")
    STATE.mkdir(parents=True, exist_ok=True)
    SEEN.write_text(str(len(lines)))
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "run":
        sys.exit(run())
    if cmd == "alerts":
        sys.exit(show("--all" in sys.argv))
    print(__doc__)
