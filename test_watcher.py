"""Run: python3 -m unittest test_watcher
Real processes against a fake $HOME; nothing outside a temp dir is touched."""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import watcher

PY = sys.executable


class Watch(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.bin = self.home / "bin"
        self.bin.mkdir()
        for d in (".ssh", ".config/gh", "projects/app"):
            (self.home / d).mkdir(parents=True)
        self.key = self.home / ".ssh/id_ed25519"
        self.key.write_text("k")
        (self.home / ".ssh/id_ed25519.pub").write_text("p")
        self.hosts = self.home / ".config/gh/hosts.yml"
        self.hosts.write_text("t")
        self.env = self.home / "projects/app/.env"
        self.env.write_text("A=1")
        self.ino = watcher.Inotify()
        watcher.setup(self.ino, home=self.home, env_roots=[self.home / "projects"])
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            p.kill()
            p.wait()
        os.close(self.ino.fd)
        shutil.rmtree(self.home)

    def tool(self, name: str, body: str) -> Path:
        """An executable called `name` (so comm == name) running python `body`."""
        p = self.bin / name
        p.write_text(f"#!{PY}\nimport sys, time, subprocess\n{body}\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
        return p

    def spawn(self, *argv, **kw):
        p = subprocess.Popen([str(a) for a in argv], **kw)
        self.procs.append(p)
        return p

    def verdicts(self, timeout=3.0):
        out, end = [], time.time() + timeout
        while time.time() < end:
            for wd, mask, name in self.ino.read(0.3):
                if wd in self.ino.wd and mask & watcher.IN_OPEN:
                    path, kind = self.ino.wd[wd]
                    if s := watcher.secret_path(path, kind, name):
                        out.append((s, watcher.attribute(s, home=self.home)))
            if out and all(p.poll() is not None for p in self.procs):
                break
        return out

    def test_unknown_reader_holding_key_is_caught_exactly(self):
        self.spawn(PY, "-c", "import sys,time; f=open(sys.argv[1]); f.read(); time.sleep(1)", self.key)
        (path, (method, sus)), = self.verdicts()
        self.assertEqual((path, method), (str(self.key), "holder"))
        self.assertIn("python", sus[0]["comm"])

    def test_ssh_reading_its_key_is_silent(self):
        ssh = self.tool("ssh", "f=open(sys.argv[1]); f.read(); time.sleep(0.5)")
        self.spawn(ssh, self.key)
        self.assertEqual([v for _, v in self.verdicts()], [None])

    def test_gh_does_not_explain_an_ssh_key_read(self):
        gh = self.tool("gh", "time.sleep(1.5)")
        self.spawn(gh)
        self.spawn(PY, "-c", "import sys,time; open(sys.argv[1]).read(); time.sleep(0.5)", self.key)
        (_, verdict), = self.verdicts()
        self.assertIsNotNone(verdict)

    def test_public_key_is_not_a_secret(self):
        self.spawn("cat", self.home / ".ssh/id_ed25519.pub", stdout=subprocess.DEVNULL)
        self.assertEqual(self.verdicts(1.0), [])

    def test_app_reading_its_env_is_silent(self):
        self.spawn(PY, "-c", "import sys,time; open(sys.argv[1]).read(); time.sleep(0.5)", self.env)
        self.assertEqual([v for _, v in self.verdicts()], [None])

    def test_install_script_reading_env_and_key_is_flagged(self):
        child = "import sys,time; fs=[open(p) for p in sys.argv[1:]]; [f.read() for f in fs]; time.sleep(1)"
        npm = self.tool("npm", f"subprocess.run([{PY!r}, '-c', {child!r}, *sys.argv[2:]])")
        self.spawn(npm, "install", self.env, self.key)
        got = dict(self.verdicts())
        for p in (self.env, self.key):
            method, sus = got[str(p)]
            self.assertEqual(method, "holder")
            self.assertTrue(watcher.in_install(sus[0]))

    def test_category(self):
        self.assertEqual(watcher.category(str(self.hosts), self.home), "gh")
        self.assertEqual(watcher.category(str(self.key), self.home), "ssh")
        self.assertEqual(watcher.category(str(self.env), self.home), "env")


if __name__ == "__main__":
    unittest.main()
