#!/usr/bin/env python3
"""supply-guard: check packages against OSV malicious-package advisories (MAL-*)
before pip / uv / npm / gem / bundle install them.

Called by the shims in ./shims as `guard.py pre <tool> <args...>`.
Exit 0 = go ahead, 66 = malicious package found (install blocked).
Any other failure (network, parse) fails open with a loud warning: a guard
that breaks every install when OSV is down gets uninstalled.

Manual use:
  guard.py check PyPI requests==2.31.0 npm:left-pad
  guard.py lock [path]          # check uv.lock / package-lock.json / Gemfile.lock
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

BLOCK = 66
OSV = "https://api.osv.dev/v1"
LOG = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "supply-guard/log.jsonl"
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "supply-guard/clean.json"
CACHE_TTL = 6 * 3600  # MAL advisories land fast; don't trust a clean result for long
RED, YEL, DIM, RST = "\033[31;1m", "\033[33m", "\033[2m", "\033[0m"


@dataclass(frozen=True)
class Pkg:
    eco: str  # OSV ecosystem: PyPI | npm | RubyGems
    name: str
    version: str | None = None

    def __str__(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name


def say(msg: str) -> None:
    print(f"{DIM}[supply-guard]{RST} {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"{YEL}[supply-guard] {msg}{RST}", file=sys.stderr)


# --------------------------------------------------------------------- OSV

def _post(url: str, body: dict) -> dict:
    import urllib.request  # lazy: ~40 ms of imports the cached path doesn't need
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def _get(url: str) -> dict:
    import urllib.request
    with urllib.request.urlopen(url, timeout=20) as r:
        return json.load(r)


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def osv_malicious(pkgs: list[Pkg]) -> dict[Pkg, list[dict]]:
    """Return {pkg: [advisory, ...]} for packages with a live MAL- advisory."""
    pkgs = list(dict.fromkeys(pkgs))
    hits: dict[Pkg, list[str]] = {}
    for i in range(0, len(pkgs), 1000):
        chunk = pkgs[i : i + 1000]
        queries = []
        for p in chunk:
            q: dict = {"package": {"ecosystem": p.eco, "name": pep503(p.name) if p.eco == "PyPI" else p.name}}
            if p.version:
                q["version"] = p.version
            queries.append(q)
        results = _post(f"{OSV}/querybatch", {"queries": queries})["results"]
        for p, res in zip(chunk, results):
            ids = [v["id"] for v in res.get("vulns", []) if v["id"].startswith("MAL-")]
            # MAL entries are rare and a package with many CVEs may page them out;
            # follow the token with a single-package query when that happens.
            token = res.get("next_page_token")
            while token:
                q = dict(queries[chunk.index(p)], page_token=token)
                page = _post(f"{OSV}/query", q)
                ids += [v["id"] for v in page.get("vulns", []) if v["id"].startswith("MAL-")]
                token = page.get("next_page_token")
            if ids:
                hits[p] = ids
    out: dict[Pkg, list[dict]] = {}
    for p, ids in hits.items():
        advs = []
        for vid in ids:
            try:
                adv = _get(f"{OSV}/vulns/{vid}")
            except Exception:
                adv = {"id": vid, "summary": "(details unavailable)"}
            if adv.get("withdrawn"):
                continue
            advs.append(adv)
        if advs:
            out[p] = advs
    return out


# ------------------------------------------------------------- lockfiles

def find_up(names: list[str], start: Path | None = None) -> Path | None:
    d = (start or Path.cwd()).resolve()
    for cand in [d, *d.parents]:
        for n in names:
            if (cand / n).is_file():
                return cand / n
        if cand == Path.home():
            break
    return None


def parse_uv_lock(path: Path) -> list[Pkg]:
    import tomllib
    data = tomllib.loads(path.read_text())
    out = []
    for p in data.get("package", []):
        src = p.get("source", {})
        if "registry" in src:  # skip editable/path/git members of the workspace
            out.append(Pkg("PyPI", p["name"], p.get("version")))
    return out


def parse_package_lock(path: Path) -> list[Pkg]:
    data = json.loads(path.read_text())
    out = []
    for key, meta in (data.get("packages") or {}).items():
        if not key or meta.get("link") or "node_modules/" not in key:
            continue
        name = meta.get("name") or key.rsplit("node_modules/", 1)[1]
        if meta.get("version"):
            out.append(Pkg("npm", name, meta["version"]))
    if not out:  # lockfileVersion 1
        def walk(deps: dict) -> None:
            for name, meta in deps.items():
                out.append(Pkg("npm", name, meta.get("version")))
                walk(meta.get("dependencies") or {})
        walk(data.get("dependencies") or {})
    return out


GEM_SPEC = re.compile(r"^    ([A-Za-z0-9_.-]+) \(([^)\s]+)")


def parse_gemfile_lock(path: Path) -> list[Pkg]:
    out, in_gem = [], False
    for line in path.read_text().splitlines():
        if line and not line.startswith(" "):
            in_gem = line == "GEM"
        elif in_gem and (m := GEM_SPEC.match(line)):
            ver = m.group(2).split("-")[0] if re.search(r"-(x86|arm|aarch|java|universal)", m.group(2)) else m.group(2)
            out.append(Pkg("RubyGems", m.group(1), ver))
    return out


LOCK_KEYS: list[str] = []  # stat keys of lockfiles read for this command


def lock_pkgs(path: Path | None) -> list[Pkg]:
    """Parse a lockfile unless this exact file (path, mtime, size) was already
    checked clean recently: `uv run` hits this on every invocation."""
    if not path:
        return []
    st = path.stat()
    key = f"lock:{path.resolve()}:{st.st_mtime_ns}:{st.st_size}"
    if key in _cache_load():
        return []
    LOCK_KEYS.append(key)
    return parse_lock(path)


def parse_lock(path: Path) -> list[Pkg]:
    return {
        "uv.lock": parse_uv_lock,
        "package-lock.json": parse_package_lock,
        "npm-shrinkwrap.json": parse_package_lock,
        "Gemfile.lock": parse_gemfile_lock,
    }[path.name](path)


# -------------------------------------------------------- arg parsing

PY_SPEC = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:===?\s*([^\s;,]+))?")
PIP_VALUE_OPTS = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
    "--extra-index-url", "-t", "--target", "--prefix", "--root", "-f", "--find-links",
    "--python", "-p", "--platform", "--python-version", "--implementation", "--abi",
    "--src", "--upgrade-strategy", "--progress-bar", "--log", "--cache-dir", "--proxy",
    "--trusted-host", "--report", "--group", "--optional", "--extra", "--with",
    "--index", "--default-index", "--package", "--from", "--directory", "--project",
    "--python-platform", "--config-setting", "-C", "--overrides", "--build-constraints",
    "--exclude-newer", "--resolution", "--prerelease", "--index-strategy", "--keyring-provider",
    "--link-mode", "--compile-bytecode", "--script", "--env-file", "--marker", "--rev",
    "--tag", "--branch", "--bounds", "--with-requirements", "--with-editable",
}


def is_local(spec: str) -> bool:
    return (
        spec.startswith((".", "/", "~", "file:", "git+", "http:", "https:"))
        or "/" in spec
        or spec.endswith((".whl", ".tar.gz", ".zip"))
        or " @ " in spec
    )


def py_specs(args: list[str], value_opts: set[str] = PIP_VALUE_OPTS) -> tuple[list[str], list[str]]:
    """Split pip/uv args into (requirement lines, requirement files)."""
    reqs, files, skip = [], [], False
    for i, a in enumerate(args):
        if skip:
            skip = False
            continue
        if a in ("-r", "--requirement", "--with-requirements"):
            if i + 1 < len(args):
                files.append(args[i + 1])
            skip = True
        elif a in value_opts:
            skip = True
        elif a.startswith("-"):
            if a.startswith(("--requirement=", "--with-requirements=")):
                files.append(a.split("=", 1)[1])
            elif a.startswith("--with="):
                reqs.extend(a.split("=", 1)[1].split(","))
            continue
        elif not is_local(a):
            reqs.append(a)
    # `--with a,b` (uv run / uvx) adds packages too
    for i, a in enumerate(args[:-1]):
        if a == "--with":
            reqs.extend(args[i + 1].split(","))
    return reqs, files


def read_req_file(path: str, seen: set[str] | None = None) -> list[str]:
    seen = seen or set()
    p = Path(path).expanduser()
    if str(p.resolve()) in seen or not p.is_file():
        return []
    seen.add(str(p.resolve()))
    out = []
    for raw in p.read_text().splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ")):
            out += read_req_file(str(p.parent / line.split(None, 1)[1]), seen)
        elif line.startswith("-") or is_local(line):
            continue
        else:
            out.append(line)
    return out


def py_pkgs(reqs: list[str]) -> list[Pkg]:
    out = []
    for r in reqs:
        if m := PY_SPEC.match(r):
            out.append(Pkg("PyPI", m.group(1), m.group(2)))
    return out


def npm_pkg(spec: str) -> Pkg | None:
    if spec.startswith(("-", ".", "/", "~", "file:", "git", "http", "github:")) or spec.endswith(".tgz"):
        return None
    if spec.startswith("npm:"):
        spec = spec[4:]
    scoped = spec.startswith("@")
    body = spec[1:] if scoped else spec
    if "@" in body:
        name, ver = body.split("@", 1)
    else:
        name, ver = body, None
    if not scoped and "/" in name:  # user/repo GitHub shorthand
        return None
    name = ("@" if scoped else "") + name
    ver = ver if ver and re.fullmatch(r"\d+\.\d+\.\d+[\w.+-]*", ver) else None
    return Pkg("npm", name, ver)


NPM_VALUE_OPTS = {"--registry", "--prefix", "-w", "--workspace", "--tag", "--cache", "--userconfig", "-C", "-p", "--package", "--omit", "--include", "--install-strategy"}


def npm_specs(args: list[str]) -> list[str]:
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
        elif a in NPM_VALUE_OPTS:
            skip = True
        elif a == "--":
            break
        elif not a.startswith("-"):
            out.append(a)
    return out


# ------------------------------------------------------------ resolution

def real_bin(name: str) -> str | None:
    shims = str(Path(__file__).resolve().parent / "shims")
    path = os.pathsep.join(p for p in os.environ.get("PATH", "").split(os.pathsep) if os.path.realpath(p) != shims)
    return shutil.which(name, path=path)


def child_env() -> dict:
    return dict(os.environ, GUARD_OFF="1")


def resolve_py(reqs: list[str]) -> list[Pkg] | None:
    """Full dependency set via `uv pip compile --no-build` (never runs package
    code: no sdist builds). None if resolution failed."""
    uv = real_bin("uv")
    if not uv or not reqs:
        return None
    try:
        r = subprocess.run(
            [uv, "pip", "compile", "--no-build", "--quiet", "--no-header", "--no-annotate", "-"],
            input="\n".join(reqs), capture_output=True, text=True, timeout=120, env=child_env(),
        )
    except Exception:
        return None
    if r.returncode != 0:
        return None
    return py_pkgs([l for l in r.stdout.splitlines() if "==" in l])


def resolve_npm(specs: list[str]) -> list[Pkg] | None:
    """Resolve in a scratch dir with --package-lock-only --ignore-scripts, so
    no install script runs and the real project isn't touched."""
    npm = real_bin("npm")
    if not npm:
        return None
    with tempfile.TemporaryDirectory(prefix="supply-guard-") as tmp:
        t = Path(tmp)
        for f in ("package.json", "package-lock.json", ".npmrc"):
            if (Path.cwd() / f).is_file():
                shutil.copy(Path.cwd() / f, t / f)
        if not (t / "package.json").exists():
            (t / "package.json").write_text('{"name":"supply-guard-tmp","version":"0.0.0","private":true}')
        try:
            r = subprocess.run(
                [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--silent", *specs],
                cwd=t, capture_output=True, text=True, timeout=180, env=child_env(),
            )
        except Exception:
            return None
        if r.returncode != 0 or not (t / "package-lock.json").exists():
            return None
        return parse_package_lock(t / "package-lock.json")


# --------------------------------------------------------------- planning

def plan(tool: str, args: list[str]) -> tuple[list[Pkg], list[Pkg] | None, str]:
    """Return (direct packages, full resolved set or None, description)."""
    sub = args[0] if args else ""
    rest = args[1:]

    if tool in ("pip", "pip3") and sub == "install":
        reqs, files = py_specs(rest)
        for f in files:
            reqs += read_req_file(f)
        return py_pkgs(reqs), resolve_py(reqs) if reqs else [], "pip install"

    if tool == "uv":
        if sub == "pip" and rest[:1] == ["install"]:
            reqs, files = py_specs(rest[1:])
            for f in files:
                reqs += read_req_file(f)
            return py_pkgs(reqs), resolve_py(reqs) if reqs else [], "uv pip install"
        if sub in ("add", "tool", "run"):
            if sub == "tool":
                if rest[:1] not in (["install"], ["run"]):
                    return [], [], ""
                rest = rest[1:]
            if sub == "run":
                # only the --with extras; the command itself may be anything
                reqs = []
                for i, a in enumerate(rest[:-1]):
                    if a == "--with":
                        reqs += rest[i + 1].split(",")
                    elif a.startswith("--with="):
                        reqs += a.split("=", 1)[1].split(",")
                lock = find_up(["uv.lock"])
                locked = lock_pkgs(lock)
                if not reqs and not locked:
                    return [], [], ""
                return py_pkgs(reqs) + locked, (resolve_py(reqs) if reqs else []), "uv run"
            reqs, files = py_specs(rest)
            if sub == "tool":
                reqs = reqs[:1] + [r for r in reqs[1:] if PY_SPEC.match(r)]
            for f in files:
                reqs += read_req_file(f)
            return py_pkgs(reqs), resolve_py(reqs) if reqs else [], f"uv {sub}"
        if sub in ("sync", "lock"):
            lock = find_up(["uv.lock"])
            return (lock_pkgs(lock)), [], f"uv {sub} ({lock or 'no uv.lock'})"
        return [], [], ""

    if tool == "uvx":
        with_ = []
        for i, a in enumerate(args[:-1]):
            if a in ("--with", "--from"):
                with_ += args[i + 1].split(",")
        # first positional is the tool to run; everything after it is its own argv
        first = next((a for a in args if not a.startswith("-") and a not in with_), None)
        reqs = [r for r in ([first] if first and not is_local(first) else []) + with_ if r]
        return py_pkgs(reqs), resolve_py(reqs) if reqs else [], "uvx"

    if tool == "npm":
        if sub in ("install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "install-test", "it", "update", "up", "upgrade"):
            specs = npm_specs(rest)
            pkgs = [p for s in specs if (p := npm_pkg(s))]
            if pkgs:
                return pkgs, resolve_npm([s for s in specs if npm_pkg(s)]), "npm install"
            lock = find_up(["npm-shrinkwrap.json", "package-lock.json"])
            return (lock_pkgs(lock)), [], f"npm {sub} ({lock or 'no lockfile'})"
        if sub in ("ci", "clean-install", "install-clean", "ic"):
            lock = find_up(["npm-shrinkwrap.json", "package-lock.json"])
            return (lock_pkgs(lock)), [], f"npm ci ({lock or 'no lockfile'})"
        if sub in ("exec", "x"):
            return plan("npx", rest)
        return [], [], ""

    if tool == "npx":
        pkg_opts = [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-p", "--package")]
        pkg_opts += [a.split("=", 1)[1] for a in args if a.startswith("--package=")]
        first = None if pkg_opts else next((a for a in args if not a.startswith("-")), None)
        specs = pkg_opts + ([first] if first else [])
        pkgs = [p for s in specs if (p := npm_pkg(s))]
        # npx runs a local bin if one exists; only resolve when it would download
        if first and not pkg_opts and (Path.cwd() / "node_modules/.bin" / first).exists():
            return [], [], ""
        return pkgs, resolve_npm([str(p) for p in pkgs]) if pkgs else [], "npx"

    if tool == "gem" and sub == "install":
        names, ver, skip = [], None, False
        for i, a in enumerate(rest):
            if skip:
                skip = False
            elif a in ("-v", "--version"):
                ver = rest[i + 1] if i + 1 < len(rest) else None
                skip = True
            elif a in ("-i", "--install-dir", "-n", "--bindir", "-s", "--source", "-g", "--file", "--platform"):
                skip = True
            elif not a.startswith("-") and not a.endswith(".gem"):
                names.append(a)
        ver = ver if ver and re.fullmatch(r"[\d.]+", ver) else None
        return [Pkg("RubyGems", n, ver if len(names) == 1 else None) for n in names], None, "gem install"

    if tool == "bundle" and sub in ("", "install", "update"):
        lock = find_up(["Gemfile.lock"])
        return (lock_pkgs(lock)), [], f"bundle {sub or 'install'} ({lock or 'no Gemfile.lock'})"

    return [], [], ""


# ------------------------------------------------------------------ report

def log(event: dict) -> None:
    try:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open("a") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "cwd": os.getcwd(), **event}) + "\n")
    except OSError:
        pass


def report(hits: dict[Pkg, list[dict]], direct: set[Pkg]) -> None:
    print(f"\n{RED}[supply-guard] BLOCKED: malicious package(s) per OSV{RST}", file=sys.stderr)
    for p, advs in hits.items():
        how = "requested" if (p.eco, p.name) in {(d.eco, d.name) for d in direct} else "pulled in as a dependency"
        for a in advs:
            print(f"{RED}  {p} ({p.eco}, {how}){RST}  {a['id']}: {a.get('summary', '')}", file=sys.stderr)
            print(f"    https://osv.dev/vulnerability/{a['id']}", file=sys.stderr)
    print(f"{DIM}  Override once (only if you've checked it's a false positive): GUARD_FORCE=1 <command>{RST}\n", file=sys.stderr)


def _cache_key(pkgs: list[Pkg]) -> str:
    return hashlib.sha256("\n".join(sorted({f"{p.eco}:{p.name}:{p.version}" for p in pkgs})).encode()).hexdigest()


def _cache_load() -> dict:
    try:
        data = json.loads(CACHE.read_text())
    except (OSError, ValueError):
        return {}
    now = time.time()
    return {k: v for k, v in data.items() if now - v < CACHE_TTL}


def _cache_store(key: str) -> None:
    try:
        data = _cache_load()
        data[key] = time.time()
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(data))
    except OSError:
        pass


def dedupe(hits: dict[Pkg, list[dict]]) -> dict[Pkg, list[dict]]:
    """Drop a name-only hit when the same package also hit with a version."""
    versioned = {(p.eco, p.name) for p in hits if p.version}
    return {p: v for p, v in hits.items() if p.version or (p.eco, p.name) not in versioned}


def check(pkgs: list[Pkg], direct: list[Pkg], what: str) -> int:
    if not pkgs:
        return 0
    key = _cache_key(pkgs)
    if key in _cache_load():
        say(f"{what}: {len(set(pkgs))} packages, clean (cached)")
        for k in LOCK_KEYS:
            _cache_store(k)
        return 0
    t0 = time.monotonic()
    hits = dedupe(osv_malicious(pkgs))
    ms = int((time.monotonic() - t0) * 1000)
    log({"what": what, "checked": len(set(pkgs)), "ms": ms, "blocked": {str(p): [a["id"] for a in v] for p, v in hits.items()}})
    if not hits:
        say(f"{what}: {len(set(pkgs))} packages, no malicious advisories ({ms} ms)")
        _cache_store(key)
        for k in LOCK_KEYS:
            _cache_store(k)
        return 0
    report(hits, set(direct))
    if os.environ.get("GUARD_FORCE") == "1":
        warn("GUARD_FORCE=1 set: continuing anyway")
        return 0
    return BLOCK


def cmd_pre(tool: str, args: list[str]) -> int:
    direct, resolved, what = plan(tool, args)
    if not what:
        return 0
    if resolved is None and direct:
        warn(f"{what}: couldn't resolve dependencies without running package code; checking only the {len(direct)} named package(s)")
    return check(direct + (resolved or []), direct, what)


def cmd_check(args: list[str]) -> int:
    pkgs = []
    eco = "PyPI"
    for a in args:
        if a in ("PyPI", "npm", "RubyGems"):
            eco = a
            continue
        e, _, spec = a.rpartition(":") if a.split(":", 1)[0] in ("PyPI", "npm", "RubyGems") else (eco, "", a)
        if e == "npm":
            p = npm_pkg(spec)
        elif e == "PyPI":
            p = (py_pkgs([spec]) or [None])[0]
        else:
            n, _, v = spec.partition("@")
            p = Pkg("RubyGems", n, v or None)
        if p:
            pkgs.append(p)
    return check(pkgs, pkgs, "check")


def cmd_lock(args: list[str]) -> int:
    paths = [Path(a) for a in args] or [
        p for p in (find_up([n]) for n in ("uv.lock", "package-lock.json", "Gemfile.lock")) if p
    ]
    if not paths:
        warn("no lockfile found")
        return 0
    rc = 0
    for p in paths:
        rc = max(rc, check(parse_lock(p), [], f"lock {p}"))
    return rc


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "pre":
            return cmd_pre(rest[0], rest[1:])
        if cmd == "check":
            return cmd_check(rest)
        if cmd == "lock":
            return cmd_lock(rest)
    except Exception as e:  # fail open, loudly
        warn(f"check failed ({type(e).__name__}: {e}); NOT verified, continuing")
        log({"error": f"{type(e).__name__}: {e}", "argv": argv})
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
