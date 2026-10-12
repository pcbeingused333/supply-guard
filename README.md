# supply-guard

Guard for WSL against malicious packages. Defender barely sees inside WSL.

## 1. Install check (`guard.py` + `shims/`)
pip, pip3, uv, uvx, npm, npx, gem and bundle go through `shims/` (first in PATH, set in `~/.zshrc`).
Before an install runs, the packages, their resolved dependencies (resolved without running package code)
or the lockfile are checked against OSV `MAL-` advisories. A hit blocks the install with exit 66.
If OSV is down, the guard warns and lets the install continue.

- `GUARD_OFF=1 <cmd>`: skip the check
- `GUARD_FORCE=1 <cmd>`: install anyway after a block
- `guard.py check npm:reqests PyPI:credential-sdk`, `guard.py lock [path]`
- Log: `~/.local/state/supply-guard/log.jsonl`

## 2. Secret-read alerts (`watcher.py`, systemd user service)
inotify on credential files (gh, ssh keys, git/npm/pypi/gem/docker/cloud tokens, Claude) and on `.env`
files at project roots. Readers that are legitimate for each kind of secret stay silent. Anything else
is logged, raises a Windows toast and shows up at the next zsh prompt. A `.env` read only alerts when it
happens inside a package install.

- Attribution: `holder` = caught with the file open (exact); `recent` = best guess from processes started
  in the last 3 s; `unknown` = something long-running read it and closed it.
- `watcher.py alerts [--all]`, `systemctl --user status supply-guard-watcher`

## Tests
`python3 -m unittest test_guard test_watcher` (`GUARD_LIVE=1` also queries OSV)

## Limits
Only catches packages OSV already lists as malicious, with no typosquat heuristics. Dependencies of
`gem install` are not resolved. Detection only, nothing is blocked at kernel level: a read is reported
after it happens.
