#!/usr/bin/env bash
# Offline synthetic transport only; all installer HOME/PATH/destinations are disposable.
set -euo pipefail
umask 077
case $(uname -s) in Linux|Darwin) ;; *) echo "SKIP native Unix installer tests: Linux/macOS required"; exit 0 ;; esac
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP="$(mktemp -d)"
TMP="$(cd "$TMP" && pwd -P)"
trap 'chmod -R u+w "$TMP"; rm -rf "$TMP"' EXIT
mkdir "$TMP/source" "$TMP/home" "$TMP/build" "$TMP/modules" "$TMP/build-cache"
# The standalone fixture has no external modules; even compiler caches are disposable.
export HOME="$TMP/home" GOMODCACHE="$TMP/modules" GOCACHE="$TMP/build-cache"
cat >"$TMP/source/main.go" <<'GO'
package main
import ("fmt"; "os")
func main() {
    if len(os.Args) != 2 || os.Args[1] != "--version" { os.Exit(9) }
    fmt.Println("secret 0.5.0 (go)")
}
GO
sed 's/--version/version/; s/0.5.0/0.4.1/' "$TMP/source/main.go" >"$TMP/source/legacy.go"
HOME="$TMP/home" GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -o "$TMP/build/native" "$TMP/source/main.go"
HOME="$TMP/home" GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -o "$TMP/build/legacy" "$TMP/source/legacy.go"
# Distinct real builds, never byte-patched copies: editing a signed Mach-O
# invalidates its ad-hoc signature and macOS arm64 then kills it (SIGKILL).
for fixture in next:0.5.1 wrong:9.9.9; do
    sed "s/0.5.0/${fixture#*:}/" "$TMP/source/main.go" >"$TMP/source/${fixture%%:*}.go"
    HOME="$TMP/home" GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -buildvcs=false \
        -o "$TMP/build/${fixture%%:*}" "$TMP/source/${fixture%%:*}.go"
done
python3 -I - "$ROOT" "$TMP" <<'PY'
import ast
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ROOT, WORK = map(Path, sys.argv[1:])
PYTHON = sys.executable
SH = shutil.which('sh')
NATIVE = (WORK / 'build/native').read_bytes()
NEXT = (WORK / 'build/next').read_bytes()
WRONG = (WORK / 'build/wrong').read_bytes()
OS = {'Linux': 'linux', 'Darwin': 'darwin'}[os.uname().sysname]
ARCH = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[os.uname().machine]
ASSET = f'secret-v0.5.0-{OS}-{ARCH}'
COMMIT = 'a' * 40

CURL = r'''
import json, os, pathlib, sys, time
args = sys.argv[1:]
def value(flag): return args[args.index(flag) + 1]
assert value('--proto') == '=https' and value('--proto-redir') == '=https'
assert value('--max-redirs') == '0' and value('--connect-timeout') == '10'
assert value('--max-time') == '60' and '--location' not in args
limit = int(value('--max-filesize')); assert limit in (4096, 1048576, 67108864)
url = args[-1]
with open(os.environ['LOG'], 'a') as stream: stream.write(json.dumps(['curl'] + args) + '\n')
body = pathlib.Path(value('--output')); headers = pathlib.Path(value('--dump-header'))
assert not list(body.parent.iterdir()) and not list(headers.parent.iterdir())
mode = os.environ.get('MODE', '')
body.write_bytes(b''); headers.write_bytes(b'HTTP/1.1 200 OK\r\n\r\n')
if url.endswith('/latest'):
    headers.write_text('Location: ' + os.environ.get('LATEST', 'https://github.com/avhn/secret/releases/tag/v0.5.0') + '\r\n')
    if mode == 'latest-nul': headers.write_bytes(headers.read_bytes().replace(b'/tag/', b'/tag/\x00'))
    print('302', end=''); sys.exit()
if mode in ('interrupt', 'kill'):
    pathlib.Path(os.environ['READY']).touch()
    while True: time.sleep(.1)
if mode in ('network', 'truncated'): body.write_bytes(b'partial'); sys.exit(28)
if mode == 'oversize': body.write_bytes(b'x' * (limit + 1)); print('200', end=''); sys.exit()
if mode == 'header-size': headers.write_bytes(b'x' * 65537); print('200', end=''); sys.exit()
if mode in ('redirect', 'redirect-loop', 'redirect-user', 'redirect-http', 'redirect-duplicate'):
    location = {'redirect': 'https://attacker.invalid/asset',
                'redirect-loop': 'https://release-assets.githubusercontent.com/asset',
                'redirect-user': 'https://release-assets.githubusercontent.com@attacker.invalid/asset',
                'redirect-http': 'http://release-assets.githubusercontent.com/asset',
                'redirect-duplicate': 'https://release-assets.githubusercontent.com/asset'}[mode]
    headers.write_text('Location: ' + location + '\r\n' +
                       ('Location: https://attacker.invalid/asset\r\n' if mode == 'redirect-duplicate' else ''))
    print('302', end=''); sys.exit()
name = url.rsplit('/', 1)[1]
if name.startswith('sha256-'): body.write_text('synthetic bundle')
else:
    body.write_bytes((pathlib.Path(os.environ['FIXTURES']) / name).read_bytes())
    if mode == 'corrupt' and name == os.environ['ASSET']: body.write_bytes(b'corruption')
print('200', end='')
'''
class Install(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='case ', dir=WORK))
        self.home = self.work / 'home'
        self.home.mkdir(mode=0o700)
        self.tools = self.work / 'tools'
        self.tools.mkdir(mode=0o700)
        self.fixtures = self.work / 'fixtures'
        self.fixtures.mkdir(mode=0o700)
        self.destination = self.home / 'bin with spaces and \'single "double'
        self.target = self.destination / 'secret'
        self.log = self.work / 'log'
        self.ready = self.work / 'ready'
        self.env = dict(HOME=str(self.home), PATH=str(self.tools), INSTALL_DIR=str(self.destination),
                        FIXTURES=str(self.fixtures), LOG=str(self.log), ASSET=ASSET, READY=str(self.ready))
        for tool in ('uname', 'id', 'stat', 'awk', 'wc', 'cmp', 'chmod', 'mv', 'rm', 'rmdir', 'mkdir', 'mktemp', 'sleep', 'od', 'tr', 'cat', 'sha256sum', 'shasum'):
            source = shutil.which(tool)
            if source: (self.tools / tool).symlink_to(source)
        self.script('curl', CURL)
        for system in ('linux', 'darwin', 'windows'):
            for arch in ('amd64', 'arm64'):
                name = f'secret-v0.5.0-{system}-{arch}' + ('.exe' if system == 'windows' else '')
                (self.fixtures / name).write_bytes(NATIVE)
        (self.fixtures / 'secret-v0.5.0-desktop.mcpb').write_bytes(b'synthetic bundle')
        (self.fixtures / 'server.json').write_bytes(b'{}\n')
        self.manifest = self.fixtures / 'checksums-v0.5.0.txt'
        self.rehash()

    def script(self, name, body):
        path = self.tools / name
        if path.is_symlink(): path.unlink()
        path.write_text('#!' + PYTHON + ' -I\n' + body)
        path.chmod(0o700)

    def rehash(self):
        self.manifest.write_bytes(b''.join(hashlib.sha256(p.read_bytes()).hexdigest().encode() + b'  ' + p.name.encode() + b'\n'
                                          for p in sorted(self.fixtures.iterdir()) if p != self.manifest))

    def run_install(self, *args):
        return subprocess.run([SH, ROOT / 'install.sh', *args], env=self.env, cwd=self.work,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)

    def failure(self, *args):
        result = self.run_install(*args)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.target.exists())
        self.assertNotIn(b'provider diagnostic', result.stderr)
        if self.destination.exists():
            self.assertEqual(list(self.destination.glob('.secret-install-*')), [])
            self.assertFalse((self.destination / '.secret.install-lock').exists())
        return result

    def test_install_and_quoted_registration(self):
        result = self.run_install()
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        self.assertEqual(self.target.read_bytes(), NATIVE)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o500)
        self.assertIn(b'Installed secret 0.5.0 at ', result.stdout)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(sum(c[-1].endswith('/latest') for c in calls), 1)
        self.assertTrue(all(c[0] == 'curl' for c in calls))
        self.assertFalse((self.home / '.profile').exists())
        self.assertEqual(list(self.destination.iterdir()), [self.target])

    def test_help_unknown_and_pin_validation(self):
        for args in [('--help',), ('-h',)]:
            self.assertEqual(self.run_install(*args).returncode, 0)
        for args in [('--wat',), ('--help', '--wat'), ('--version',), ('--commit',), ('--dir',),
                     ('--version', '0.5.0', '--version', '0.5.0')]:
            self.failure(*args)
        for version in ('latest', '0.03.0', '1.2', '1.2.3-rc1', '../0.5.0', 'v', 'vv0.5.0', '0.5.0\n'):
            self.env['SECRET_VERSION'] = version
            self.failure()
        self.env['SECRET_VERSION'] = '0.5.0'
        self.failure('--version', '9.9.9')
        for commit in ('latest', 'a' * 39, 'A' * 40, 'a' * 40 + '\n'):
            self.env['SECRET_RELEASE_COMMIT'] = commit
            self.failure()
        self.assertFalse(self.log.exists())

    def test_matching_pin_and_flags(self):
        self.env['SECRET_VERSION'] = 'v0.5.0'
        result = self.run_install('--version', '0.5.0', '--dir', str(self.destination))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('/latest', self.log.read_text())

    def test_checksum_and_transport_failures(self):
        for mode in ('corrupt', 'network', 'truncated', 'oversize', 'header-size', 'redirect', 'redirect-loop', 'redirect-user', 'redirect-http', 'redirect-duplicate', 'latest-nul'):
            with self.subTest(mode=mode):
                self.env['MODE'] = mode
                self.failure()

    def test_latest_redirect_validation(self):
        for url in ('http://github.com/avhn/secret/releases/tag/v0.5.0',
                    'https://github.com/other/secret/releases/tag/v0.5.0',
                    'https://github.com/avhn/secret/releases/tag/v01.2.3',
                    'https://github.com/avhn/secret/releases/tag/v0.5.0?x=1',
                    'https://github.com/avhn/secret/releases/tag/v0.5.0-rc1',
                    'https://github.com@evil.invalid/avhn/secret/releases/tag/v0.5.0',
                    'https://github.com/avhn/secret/releases/tag/v0.5.0\r\nLocation: https://evil.invalid/'):
            self.env['LATEST'] = url
            self.failure()

    def test_pipe_and_noop(self):
        result = subprocess.run([SH], input=(ROOT / 'install.sh').read_bytes(), env=self.env,
                                cwd=self.work, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        before = self.target.stat()
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'is already installed at', result.stdout)
        after = self.target.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))

    def test_upgrade_rollback_repair_and_failed_update(self):
        self.assertEqual(self.run_install().returncode, 0)
        original = self.target.read_bytes()
        newer = NEXT
        self.assertNotEqual(original, newer, 'release fixtures must differ')
        next_fixtures = self.work / 'next-fixtures'
        next_fixtures.mkdir(mode=0o700)
        for source in self.fixtures.iterdir():
            if source == self.manifest: continue
            name = source.name.replace('v0.5.0', 'v0.5.1')
            (next_fixtures / name).write_bytes(newer if source.name == ASSET else source.read_bytes())
        (next_fixtures / 'checksums-v0.5.1.txt').write_bytes(b''.join(
            hashlib.sha256(p.read_bytes()).hexdigest().encode() + b'  ' + p.name.encode() + b'\n'
            for p in sorted(next_fixtures.iterdir())))
        self.env.update(FIXTURES=str(next_fixtures), LATEST='https://github.com/avhn/secret/releases/tag/v0.5.1',
                        ASSET=ASSET.replace('v0.5.0', 'v0.5.1'), MODE='corrupt')
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertEqual(self.target.read_bytes(), original)
        self.env.pop('MODE')
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_bytes(), newer)
        self.env.update(FIXTURES=str(self.fixtures), SECRET_VERSION='v0.5.0', ASSET=ASSET)
        self.assertEqual(self.run_install('--version', '0.5.0').returncode, 0)
        self.assertEqual(self.target.read_bytes(), original)
        self.target.chmod(0o700); self.target.write_bytes(b'corrupt installed executable'); self.target.chmod(0o500)
        self.assertEqual(self.run_install().returncode, 0)
        self.assertEqual(self.target.read_bytes(), original)

    def test_pre_alias_release_rollback(self):
        self.assertEqual(self.run_install().returncode, 0)
        legacy = self.work / 'legacy-fixtures'; legacy.mkdir(mode=0o700)
        data = (WORK / 'build/legacy').read_bytes()
        for source in self.fixtures.iterdir():
            if source == self.manifest: continue
            (legacy / source.name.replace('v0.5.0', 'v0.4.1')).write_bytes(data if source.name == ASSET else source.read_bytes())
        (legacy / 'checksums-v0.4.1.txt').write_bytes(b''.join(
            hashlib.sha256(p.read_bytes()).hexdigest().encode() + b'  ' + p.name.encode() + b'\n'
            for p in sorted(legacy.iterdir())))
        self.env.update(FIXTURES=str(legacy), SECRET_VERSION='0.4.1')
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_bytes(), data)

    def test_missing_release_asset(self):
        (self.fixtures / ASSET).unlink()
        self.failure()

    def test_truncated_pipe_does_not_execute(self):
        result = subprocess.run([SH], input=(ROOT / 'install.sh').read_bytes().rsplit(b'secret_install "$@"', 1)[0],
                                env=self.env, cwd=self.work, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.log.exists())

    def test_manifest_grammar(self):
        original = self.manifest.read_bytes()
        lines = original.splitlines(keepends=True)
        for data in (original[:-1], original.replace(b'\n', b'\r\n'), b''.join(reversed(lines)), b''.join(lines[:-1]),
                     original + lines[0], b''.join([lines[0], *lines[:-1]]), original.replace(b'  ', b' ', 1),
                     original.replace(b'\n', b'\0\n', 1)):
            self.manifest.write_bytes(data)
            self.failure()

    def test_wrong_architecture_and_version(self):
        native = self.fixtures / ASSET
        data = bytearray(NATIVE)
        if OS == 'linux': data[18:20] = (183 if ARCH == 'amd64' else 62).to_bytes(2, 'little')
        else: data[4:8] = (0x100000c if ARCH == 'amd64' else 0x1000007).to_bytes(4, 'little')
        native.write_bytes(data); self.rehash(); self.failure()
        native.write_bytes(WRONG)
        self.rehash(); self.failure()

    def test_unsupported_platform(self):
        self.script('uname', "print('Unsupported')")
        self.failure()
        self.assertFalse(self.log.exists())

    def test_existing_destination_preserved_and_replaced(self):
        self.destination.mkdir(mode=0o700)
        # Classified CLI-only change: a safe existing Bash executable is replaced.
        # Verification failure must preserve it byte-for-byte.
        self.target.write_bytes(b'original Bash secret'); self.target.chmod(0o500)
        self.env['MODE'] = 'corrupt'
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.target.read_bytes(), b'original Bash secret')
        self.env.pop('MODE')
        self.assertEqual(self.run_install().returncode, 0)
        self.assertEqual(self.target.read_bytes(), NATIVE)

    def test_existing_default_directory_modes_and_symlink(self):
        # Existing ~/.local/bin is commonly 0755. Do not repair it or require 0700.
        self.env.pop('INSTALL_DIR')
        self.destination = self.home / '.local/bin'
        self.destination.mkdir(mode=0o700, parents=True)
        self.destination.chmod(0o755)
        self.target = self.destination / 'secret'
        result = self.run_install()
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o500)
        self.assertEqual(self.target.read_bytes(), NATIVE)
        self.target.unlink()
        self.log.unlink()
        diagnostic = (b'secret: unsafe install directory; use a user-owned directory '
                      b'and chmod go-w DIR\n')
        for mode in (0o775, 0o757):
            with self.subTest(mode=oct(mode)):
                self.destination.chmod(mode)
                result = self.failure()
                self.assertEqual(result.stderr, diagnostic)
                self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), mode)
                self.assertFalse(self.log.exists())
        self.destination.chmod(0o755)
        saved = self.destination.with_name('real-bin')
        self.destination.rename(saved)
        self.destination.symlink_to(saved)
        result = self.failure()
        self.assertEqual(result.stderr, diagnostic)
        self.assertTrue(self.destination.is_symlink())
        self.assertFalse(self.log.exists())

    def test_symlinked_ancestor_binds_physical_parent(self):
        # macOS /var and /tmp are symlinks. Bind the physical parent once;
        # a final symlinked install directory is still rejected above.
        real = self.work / 'real-parent'
        real.mkdir(mode=0o700)
        linked = self.work / 'linked-parent'
        linked.symlink_to(real)
        self.env['INSTALL_DIR'] = str(linked / 'bin')
        self.destination = real / 'bin'
        self.target = self.destination / 'secret'
        result = self.run_install()
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        self.assertEqual(self.target.read_bytes(), NATIVE)
        self.assertTrue(linked.is_symlink())
        # /tmp is root-owned and sticky everywhere, and a symlink on macOS.
        # BSD stat %Lp hides the sticky bit, which once rejected this parent.
        sticky = Path(tempfile.mkdtemp(prefix='secret-install-sticky-', dir='/tmp'))
        try:
            self.env['INSTALL_DIR'] = str(sticky / 'bin')
            self.destination = Path(os.path.realpath(sticky)) / 'bin'
            self.target = self.destination / 'secret'
            self.log.unlink(missing_ok=True)
            result = self.run_install()
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            self.assertEqual(self.target.read_bytes(), NATIVE)
        finally:
            shutil.rmtree(sticky)

    def test_aliases_and_unsafe_modes(self):
        self.destination.mkdir(mode=0o700)
        self.target.symlink_to(self.work / 'absent')
        self.failure(); self.target.unlink()
        self.target.write_bytes(b'old'); self.target.chmod(0o500)
        alias = self.work / 'alias'; os.link(self.target, alias)
        result = self.run_install(); self.assertNotEqual(result.returncode, 0)
        self.target.unlink(); alias.unlink()
        self.destination.chmod(0o777)
        self.failure()
        self.destination.chmod(0o700)
        saved = self.destination.with_name('saved')
        self.destination.rename(saved); self.destination.symlink_to(saved)
        self.failure()

    def test_lock_never_stolen(self):
        self.destination.mkdir(mode=0o700)
        lock = self.destination / '.secret.install-lock'
        lock.mkdir(mode=0o700); (lock / 'owner').write_text('stale')
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((lock / 'owner').read_text(), 'stale')
        self.assertFalse(self.target.exists())

    def test_interrupted_download(self):
        self.env['MODE'] = 'interrupt'
        process = subprocess.Popen([SH, ROOT / 'install.sh'], env=self.env, cwd=self.work,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            deadline = time.monotonic() + 10
            while not self.ready.exists() and time.monotonic() < deadline: time.sleep(.02)
            self.assertTrue(self.ready.exists())
            # Installer owns a separate curl process group and must reap it.
            process.terminate(); process.communicate(timeout=10)
            self.assertNotEqual(process.returncode, 0)
            self.assertFalse(self.target.exists())
            self.assertEqual(list(self.destination.iterdir()), [])
        finally:
            if process.poll() is None: process.kill(); process.communicate()


unittest.main(argv=['test-install'], verbosity=2)
PY
