"""Run: python3 -m unittest test_guard          (offline)
       GUARD_LIVE=1 python3 -m unittest test_guard   (also hits OSV)"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import guard
from guard import Pkg


class Parsers(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_uv_lock_skips_workspace_members(self):
        p = self.tmp / "uv.lock"
        p.write_text(
            'version = 1\n'
            '[[package]]\nname = "me"\nversion = "0.1.0"\nsource = { editable = "." }\n'
            '[[package]]\nname = "requests"\nversion = "2.32.3"\nsource = { registry = "https://pypi.org/simple" }\n'
        )
        self.assertEqual(guard.parse_uv_lock(p), [Pkg("PyPI", "requests", "2.32.3")])

    def test_package_lock_v3_nested_and_scoped(self):
        p = self.tmp / "package-lock.json"
        p.write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/@scope/a": {"version": "1.0.0"},
            "node_modules/@scope/a/node_modules/b": {"version": "2.0.0"},
            "node_modules/linked": {"link": True},
        }}))
        self.assertEqual(guard.parse_package_lock(p),
                         [Pkg("npm", "@scope/a", "1.0.0"), Pkg("npm", "b", "2.0.0")])

    def test_package_lock_v1(self):
        p = self.tmp / "package-lock.json"
        p.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}))
        self.assertEqual(guard.parse_package_lock(p),
                         [Pkg("npm", "a", "1.0.0"), Pkg("npm", "b", "2.0.0")])

    def test_gemfile_lock_only_gem_section_and_platform_suffix(self):
        p = self.tmp / "Gemfile.lock"
        p.write_text(
            "GIT\n  remote: x\n  specs:\n    local (0.1.0)\n\n"
            "GEM\n  remote: https://rubygems.org/\n  specs:\n"
            "    rack (3.1.8)\n      base64 (>= 0)\n"
            "    nokogiri (1.18.1-x86_64-linux-gnu)\n\n"
            "PLATFORMS\n  ruby\n"
        )
        self.assertEqual(guard.parse_gemfile_lock(p),
                         [Pkg("RubyGems", "rack", "3.1.8"), Pkg("RubyGems", "nokogiri", "1.18.1")])

    def test_requirements_nested_and_skips_local(self):
        (self.tmp / "base.txt").write_text("six==1.16.0\n")
        (self.tmp / "req.txt").write_text(
            "-r base.txt\n# comment\nrequests[socks]>=2 ; python_version>'3'\n-e .\n./pkg.whl\n"
            "--index-url https://x\nfoo @ https://x/foo.whl\n")
        self.assertEqual(guard.read_req_file(str(self.tmp / "req.txt")),
                         ["six==1.16.0", "requests[socks]>=2 ; python_version>'3'"])


class Planning(unittest.TestCase):
    def setUp(self):
        self.rp = mock.patch.object(guard, "resolve_py", return_value=["R"])
        self.rn = mock.patch.object(guard, "resolve_npm", return_value=["R"])
        self.rp.start(); self.rn.start()
        self.cwd = os.getcwd()
        os.chdir(tempfile.mkdtemp())

    def tearDown(self):
        mock.patch.stopall()
        os.chdir(self.cwd)

    def direct(self, tool, *args):
        return guard.plan(tool, list(args))[0]

    def test_pip_install_skips_option_values(self):
        self.assertEqual(
            self.direct("pip", "install", "-i", "https://idx", "--target", "dir", "Flask==3.0.0", "-e", ".", "x-y"),
            [Pkg("PyPI", "Flask", "3.0.0"), Pkg("PyPI", "x-y")])

    def test_non_install_commands_are_ignored(self):
        for tool, args in [("pip", ["list"]), ("uv", ["venv"]), ("npm", ["test"]), ("npm", ["run", "build"]),
                           ("gem", ["list"]), ("bundle", ["exec", "rspec"]), ("uv", ["tool", "list"])]:
            self.assertEqual(guard.plan(tool, args)[2], "", (tool, args))

    def test_uv_variants(self):
        self.assertEqual(self.direct("uv", "add", "--dev", "pytest"), [Pkg("PyPI", "pytest")])
        self.assertEqual(self.direct("uv", "pip", "install", "httpx==0.27.0"), [Pkg("PyPI", "httpx", "0.27.0")])
        self.assertEqual(self.direct("uv", "tool", "install", "ruff"), [Pkg("PyPI", "ruff")])
        self.assertEqual(self.direct("uv", "run", "--with", "rich,httpx", "python", "x.py"),
                         [Pkg("PyPI", "rich"), Pkg("PyPI", "httpx")])
        self.assertEqual(guard.plan("uv", ["run", "python", "x.py"])[2], "")  # no lock, no --with

    def test_uvx_checks_tool_not_its_args(self):
        self.assertEqual(self.direct("uvx", "--with", "rich", "pycowsay", "requests"),
                         [Pkg("PyPI", "pycowsay"), Pkg("PyPI", "rich")])

    def test_npm_specs(self):
        self.assertEqual(self.direct("npm", "i", "-D", "@types/node@20.1.0", "lodash@^4", "user/repo", "./local"),
                         [Pkg("npm", "@types/node", "20.1.0"), Pkg("npm", "lodash")])
        self.assertEqual(self.direct("npm", "install", "--registry", "https://r", "left-pad"), [Pkg("npm", "left-pad")])

    def test_npx_package_flag_and_local_bin(self):
        self.assertEqual(self.direct("npx", "-p", "typescript@5.6.2", "tsc"), [Pkg("npm", "typescript", "5.6.2")])
        Path("node_modules/.bin").mkdir(parents=True)
        Path("node_modules/.bin/tsc").touch()
        self.assertEqual(guard.plan("npx", ["tsc"])[2], "")

    def test_npm_install_without_args_reads_lock(self):
        Path("package-lock.json").write_text(json.dumps({"packages": {"node_modules/a": {"version": "1.0.0"}}}))
        self.assertEqual(self.direct("npm", "install"), [Pkg("npm", "a", "1.0.0")])
        self.assertEqual(self.direct("npm", "ci"), [Pkg("npm", "a", "1.0.0")])

    def test_gem_install(self):
        self.assertEqual(self.direct("gem", "install", "rails", "-v", "7.2.0"), [Pkg("RubyGems", "rails", "7.2.0")])
        self.assertEqual(self.direct("gem", "install", "a", "b"), [Pkg("RubyGems", "a"), Pkg("RubyGems", "b")])


class Verdict(unittest.TestCase):
    def setUp(self):
        d = Path(tempfile.mkdtemp())
        mock.patch.object(guard, "CACHE", d / "c.json").start()
        mock.patch.object(guard, "LOG", d / "l.jsonl").start()

    def tearDown(self):
        mock.patch.stopall()

    def test_blocks_on_hit_and_force_overrides(self):
        bad = Pkg("PyPI", "evil", "1.0")
        with mock.patch.object(guard, "osv_malicious", return_value={bad: [{"id": "MAL-1", "summary": "x"}]}):
            self.assertEqual(guard.check([bad], [bad], "t"), guard.BLOCK)
            with mock.patch.dict(os.environ, {"GUARD_FORCE": "1"}):
                self.assertEqual(guard.check([bad], [bad], "t"), 0)

    def test_hits_are_never_cached_clean_results_are(self):
        bad, ok = Pkg("PyPI", "evil"), Pkg("PyPI", "fine")
        with mock.patch.object(guard, "osv_malicious", return_value={bad: [{"id": "MAL-1"}]}) as m:
            guard.check([bad], [], "t"); guard.check([bad], [], "t")
            self.assertEqual(m.call_count, 2)
        with mock.patch.object(guard, "osv_malicious", return_value={}) as m:
            guard.check([ok], [], "t"); guard.check([ok], [], "t")
            self.assertEqual(m.call_count, 1)

    def test_network_failure_fails_open(self):
        with mock.patch.object(guard, "plan", return_value=([Pkg("PyPI", "x")], [], "t")), \
             mock.patch.object(guard, "osv_malicious", side_effect=OSError("down")):
            self.assertEqual(guard.main(["pre", "pip", "install", "x"]), 0)

    def test_dedupe_keeps_versioned(self):
        a, b = Pkg("npm", "x"), Pkg("npm", "x", "1.0.0")
        self.assertEqual(list(guard.dedupe({a: [1], b: [2]})), [b])


@unittest.skipUnless(os.environ.get("GUARD_LIVE"), "set GUARD_LIVE=1 to query OSV")
class Live(unittest.TestCase):
    def test_known_malicious_and_clean(self):
        hits = guard.osv_malicious([
            Pkg("PyPI", "credential-sdk"), Pkg("npm", "reqests"),
            Pkg("PyPI", "requests", "2.32.3"), Pkg("npm", "left-pad", "1.3.0"),
        ])
        self.assertEqual({p.name for p in hits}, {"credential-sdk", "reqests"})


if __name__ == "__main__":
    unittest.main()
