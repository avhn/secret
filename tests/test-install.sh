#!/usr/bin/env bash
# Offline synthetic transport only; all installer HOME/PATH/destinations are disposable.
set -euo pipefail
umask 077
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
    if len(os.Args) != 2 || os.Args[1] != "version" { os.Exit(9) }
    fmt.Println("secret 0.3.4 (go)")
}
GO
HOME="$TMP/home" GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -o "$TMP/build/native" "$TMP/source/main.go"
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
OS = {'Linux': 'linux', 'Darwin': 'darwin'}[os.uname().sysname]
ARCH = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[os.uname().machine]
ASSET = f'secret-v0.3.4-{OS}-{ARCH}'
COMMIT = 'a' * 40

CURL = r'''
import json, os, pathlib, sys, time
args = sys.argv[1:]
def value(flag): return args[args.index(flag) + 1]
assert value('--proto') == '=https' and value('--proto-redir') == '=https'
assert value('--max-redirs') == '0' and value('--connect-timeout') == '10'
assert value('--max-time') == '60' and '--location' not in args
limit = int(value('--max-filesize')); assert limit in (4096, 1048576, 67108864)
url = args[-1]; assert '/latest' not in url
with open(os.environ['LOG'], 'a') as stream: stream.write(json.dumps(['curl'] + args) + '\n')
body = pathlib.Path(value('--output')); headers = pathlib.Path(value('--dump-header'))
assert not list(body.parent.iterdir()) and not list(headers.parent.iterdir())
mode = os.environ.get('MODE', '')
body.write_bytes(b''); headers.write_bytes(b'HTTP/1.1 200 OK\r\n\r\n')
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
GH = r'''
import base64, hashlib, json, os, pathlib, sys
args = sys.argv[1:]
def value(flag): return args[args.index(flag) + 1]
with open(os.environ['LOG'], 'a') as stream: stream.write(json.dumps(['gh'] + args) + '\n')
mode = os.environ.get('MODE', '')
if args[:2] == ['auth', 'status']:
    assert args == ['auth', 'status', '--hostname', 'github.com']
    if mode == 'unauthenticated':
        print('provider diagnostic must not escape', file=sys.stderr)
        sys.exit(4)
    if mode == 'slow-auth':
        import time
        time.sleep(11)
    print('synthetic authenticated status')
    sys.exit()
fixtures = pathlib.Path(os.environ['FIXTURES'])
commit, source, tag_sha, blob = 'a' * 40, 'c' * 40, 'd' * 40, 'e' * 40
if args[0] == 'api':
    assert value('--hostname') == 'github.com' and value('--method') == 'GET'
    endpoint = args[-1]
    assert endpoint.startswith('repos/avhn/secret/')
    endpoint = endpoint[len('repos/avhn/secret/'):]
    if mode == 'api-error': sys.exit(1)
    if mode == 'api-size': print('{"padding":"' + 'x' * 16384 + '"}'); sys.exit()
    if endpoint == 'git/ref/tags/v0.3.4':
        result = {'ref': 'refs/tags/v0.3.4', 'object': {'type': 'tag', 'sha': tag_sha}}
        if mode == 'lightweight-tag': result['object'] = {'type': 'commit', 'sha': commit}
    elif endpoint == 'git/tags/' + tag_sha:
        result = {'sha': tag_sha, 'tag': 'v0.3.4', 'object': {'type': 'commit', 'sha': commit}}
        if mode == 'wrong-tag-commit': result['object']['sha'] = 'b' * 40
    elif endpoint == 'commits/' + commit + '?per_page=100':
        result = {'sha': commit, 'parents': [{'sha': source}],
                  'files': [{'filename': 'dist/checksums-v0.3.4.txt', 'status': 'added', 'sha': blob}]}
        if mode == 'two-parents': result['parents'].append({'sha': 'b' * 40})
        if mode == 'extra-file': result['files'].append({'filename': 'README.md', 'status': 'modified', 'sha': 'f' * 40})
        if mode == 'modified-checksums': result['files'][0]['status'] = 'modified'
    elif endpoint == 'contents/dist/checksums-v0.3.4.txt?ref=' + commit:
        data = (fixtures / 'checksums-v0.3.4.txt').read_bytes()
        if mode == 'committed-mismatch': data += b'committed bytes differ\n'
        result = {'type': 'file', 'path': 'dist/checksums-v0.3.4.txt', 'sha': blob, 'encoding': 'base64',
                  'size': len(data), 'content': base64.b64encode(data).decode('ascii')}
    else: raise AssertionError(endpoint)
    if mode == 'api-nonfinite': result['unexpected'] = float('nan')
    text = json.dumps(result)
    if mode == 'api-duplicate': text = text.replace('"ref":', '"ref":"wrong", "ref":')
    print(text); sys.exit()
assert args[:2] == ['attestation', 'verify']
assert value('--repo') == 'avhn/secret' and '--owner' not in args and '--signer-workflow' not in args
assert value('--source-ref') == 'refs/tags/v0.3.4'
assert value('--cert-identity') == 'https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/v0.3.4'
assert value('--cert-oidc-issuer') == 'https://token.actions.githubusercontent.com'
assert '--deny-self-hosted-runners' in args and value('--format') == 'json'
assert pathlib.Path(value('--bundle')).read_text() == 'synthetic bundle'
if mode == 'attestation': print('provider diagnostic must not escape', file=sys.stderr); sys.exit(1)
if mode == 'empty': print('[]'); sys.exit()
path = pathlib.Path(args[2])
if mode == 'inconsistent' and path.name == os.environ['ASSET']: commit = 'b' * 40
if '--source-digest' in args:
    if value('--source-digest') != commit or value('--signer-digest') != commit: sys.exit(1)
# The workflow emits one statement for all eight payloads and the checksum file.
subjects = [{'name': p.name, 'digest': {'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}}
            for p in sorted(fixtures.iterdir())]
assert len(subjects) == 9
matching = next(subject for subject in subjects if subject['name'] == path.name)
if mode == 'subject': matching['name'] = 'wrong-name'
if mode == 'subject-duplicate' or (mode == 'binary-subject-duplicate' and path.name == os.environ['ASSET']):
    subjects.append(dict(matching))
if mode == 'subject-digest' or (mode == 'binary-subject-digest' and path.name == os.environ['ASSET']):
    matching['digest'] = {'sha256': '0' * 64}
statement = {'predicateType': 'https://slsa.dev/provenance/v1', 'subject': subjects,
    'predicate': {'buildDefinition': {'externalParameters': {'workflow': {
        'repository': 'https://github.com/avhn/secret', 'ref': 'refs/tags/v0.3.4', 'path': '.github/workflows/release.yml'}},
        'resolvedDependencies': [{'uri': 'git+https://github.com/avhn/secret@refs/tags/v0.3.4', 'digest': {'gitCommit': commit}}]}}}
if mode == 'workflow': statement['predicate']['buildDefinition']['externalParameters']['workflow']['path'] = 'wrong.yml'
if mode == 'source': statement['predicate']['buildDefinition']['resolvedDependencies'] = []
result = json.dumps([{'verificationResult': {'statement': statement}}])
if mode == 'duplicate': result = result.replace('"predicateType":', '"predicateType":"wrong", "predicateType":')
print(result)
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
        self.target = self.destination / 'secret-go'
        self.log = self.work / 'log'
        self.ready = self.work / 'ready'
        self.env = dict(HOME=str(self.home), PATH=str(self.tools), INSTALL_DIR=str(self.destination),
                        FIXTURES=str(self.fixtures), LOG=str(self.log), ASSET=ASSET, READY=str(self.ready))
        (self.tools / 'python3').symlink_to(PYTHON)
        self.script('curl', CURL)
        self.script('gh', GH)
        for system in ('linux', 'darwin', 'windows'):
            for arch in ('amd64', 'arm64'):
                name = f'secret-v0.3.4-{system}-{arch}' + ('.exe' if system == 'windows' else '')
                (self.fixtures / name).write_bytes(NATIVE)
        (self.fixtures / 'secret-v0.3.4-desktop.mcpb').write_bytes(b'synthetic bundle')
        (self.fixtures / 'server.json').write_bytes(b'{}\n')
        self.manifest = self.fixtures / 'checksums-v0.3.4.txt'
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
            self.assertFalse((self.destination / '.secret-go.install-lock').exists())
        return result

    def test_install_and_quoted_registration(self):
        result = self.run_install()
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        self.assertEqual(self.target.read_bytes(), NATIVE)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o500)
        line = next(line for line in result.stdout.decode().splitlines() if line.startswith('claude '))
        self.assertEqual(shlex.split(line), ['claude', 'mcp', 'add', '--scope', 'user', '--transport', 'stdio', 'secret', '--',
                                          str(self.target), 'mcp', '--store', 'file:/ABSOLUTE/STORE'])
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(calls[0], ['gh', 'auth', 'status', '--hostname', 'github.com'])
        attestations = [c for c in calls if c[:2] == ['gh', 'attestation']]
        api_calls = [c for c in calls if c[:2] == ['gh', 'api']]
        self.assertEqual(len(attestations), 3)
        self.assertIn('--source-digest', attestations[1])
        self.assertEqual([c[-1] for c in api_calls], [
            'repos/avhn/secret/git/ref/tags/v0.3.4',
            'repos/avhn/secret/git/tags/' + 'd' * 40,
            'repos/avhn/secret/commits/' + COMMIT + '?per_page=100',
            'repos/avhn/secret/contents/dist/checksums-v0.3.4.txt?ref=' + COMMIT])
        binary_download = next(c for c in calls if c[0] == 'curl' and c[-1].endswith('/' + ASSET))
        self.assertGreater(calls.index(binary_download), calls.index(api_calls[-1]))
        self.assertFalse((self.home / '.profile').exists())
        self.assertEqual(list(self.destination.iterdir()), [self.target])

    def test_help_unknown_and_pin_validation(self):
        for args in [('--help',), ('-h',)]:
            self.assertEqual(self.run_install(*args).returncode, 0)
        for args in [('--wat',), ('--help', '--wat'), ('--version',), ('--commit',), ('--dir',),
                     ('--version', '0.3.4', '--version', '0.3.4')]:
            self.failure(*args)
        for version in ('', 'latest', '0.03.0', '1.2', '1.2.3-rc1', '../0.3.4', 'v', 'vv0.3.4', '0.3.4\n'):
            self.env['SECRET_VERSION'] = version
            self.failure()
        self.env['SECRET_VERSION'] = '0.3.4'
        self.failure('--version', '0.4.0')
        for commit in ('latest', 'a' * 39, 'A' * 40, 'a' * 40 + '\n'):
            self.env['SECRET_RELEASE_COMMIT'] = commit
            self.failure()
        self.assertFalse(self.log.exists())

    def test_matching_pin_and_flags(self):
        self.env['SECRET_VERSION'] = 'v0.3.4'
        self.env['SECRET_RELEASE_COMMIT'] = COMMIT
        result = self.run_install('--version', '0.3.4', '--commit', COMMIT, '--dir', str(self.destination))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_gh(self):
        (self.tools / 'gh').unlink()
        result = self.failure()
        self.assertIn(b'trusted package channel', result.stderr)
        self.assertFalse(self.log.exists())

    def test_unauthenticated_gh_fails_before_download_or_directory_creation(self):
        self.env['MODE'] = 'unauthenticated'
        result = self.failure()
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'secret: GitHub CLI is not authenticated; '
                         b'run gh auth login or set GH_TOKEN, then retry\n')
        self.assertFalse(self.destination.exists())
        self.assertEqual([json.loads(line) for line in self.log.read_text().splitlines()],
                         [['gh', 'auth', 'status', '--hostname', 'github.com']])

    def test_auth_status_has_a_sixty_second_bound(self):
        source = (ROOT / 'install.sh').read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        calls = [node for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                 and isinstance(node.func.value, ast.Name) and node.func.value.id == 'authentication'
                 and node.func.attr == 'wait' and node.keywords]
        self.assertEqual(len(calls), 1)
        self.assertEqual([(item.arg, ast.literal_eval(item.value)) for item in calls[0].keywords],
                         [('timeout', 60)])

    def test_cold_authenticated_gh_can_exceed_ten_seconds(self):
        self.env['MODE'] = 'slow-auth'
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b'synthetic authenticated status', result.stdout + result.stderr)

    def test_attestation_checksum_and_transport_failures(self):
        for mode in ('attestation', 'empty', 'subject', 'workflow', 'source', 'duplicate', 'inconsistent', 'corrupt',
                     'network', 'truncated', 'oversize', 'header-size', 'redirect', 'redirect-loop', 'redirect-user',
                     'redirect-http', 'redirect-duplicate'):
            with self.subTest(mode=mode):
                self.env['MODE'] = mode
                self.failure()

    def test_nine_subject_attestation_rejects_ambiguous_name_and_wrong_digest(self):
        # All successful installs use the nine-subject release-workflow fixture.
        # Reject checksum and binary collisions independently, even with eight
        # unrelated subjects carrying otherwise valid digests.
        for mode in ('subject-duplicate', 'subject-digest', 'binary-subject-duplicate', 'binary-subject-digest'):
            with self.subTest(mode=mode):
                self.env['MODE'] = mode
                self.failure()

    def test_authenticated_source_boundary_failures(self):
        for mode in ('lightweight-tag', 'wrong-tag-commit', 'two-parents', 'extra-file',
                     'modified-checksums', 'committed-mismatch', 'api-error', 'api-duplicate', 'api-nonfinite', 'api-size'):
            with self.subTest(mode=mode):
                self.env['MODE'] = mode
                self.failure()
                calls = [json.loads(line) for line in self.log.read_text().splitlines()]
                self.assertFalse(any(c[0] == 'curl' and c[-1].endswith('/' + ASSET) for c in calls))
                self.log.unlink()

    def test_wrong_commit_and_conflicting_pin(self):
        self.env['SECRET_RELEASE_COMMIT'] = 'b' * 40
        self.failure()
        self.log.unlink()
        self.failure('--commit', COMMIT)
        self.assertFalse(self.log.exists())

    def test_manifest_grammar(self):
        original = self.manifest.read_bytes()
        lines = original.splitlines(keepends=True)
        for data in (original[:-1], original.replace(b'\n', b'\r\n'), b''.join(reversed(lines)), b''.join(lines[:-1]),
                     original + lines[0], b''.join([lines[0], *lines[:-1]]), original.replace(b'  ', b' ', 1)):
            self.manifest.write_bytes(data)
            self.failure()

    def test_wrong_architecture_and_version(self):
        native = self.fixtures / ASSET
        data = bytearray(NATIVE)
        if OS == 'linux': data[18:20] = (183 if ARCH == 'amd64' else 62).to_bytes(2, 'little')
        else: data[4:8] = (0x100000c if ARCH == 'amd64' else 0x1000007).to_bytes(4, 'little')
        native.write_bytes(data); self.rehash(); self.failure()
        native.write_bytes(NATIVE.replace(b'secret 0.3.4 (go)', b'secret 9.9.9 (go)'))
        self.rehash(); self.failure()

    def test_unsupported_platform(self):
        self.script('python3', '''import os, sys
os.uname = lambda: type('U', (), {'sysname': 'Unsupported', 'machine': 'x86_64'})()
exec(compile(sys.stdin.read(), '<installer>', 'exec'))
''')
        self.failure()
        self.assertFalse(self.log.exists())

    def test_existing_destination_preserved_and_replaced(self):
        self.destination.mkdir(mode=0o700)
        bash = self.destination / 'secret'
        bash.write_bytes(b'original Bash secret')
        self.target.write_bytes(b'old Go install'); self.target.chmod(0o500)
        self.env['MODE'] = 'corrupt'
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.target.read_bytes(), b'old Go install')
        self.env.pop('MODE')
        self.assertEqual(self.run_install().returncode, 0)
        self.assertEqual(self.target.read_bytes(), NATIVE)
        self.assertEqual(bash.read_bytes(), b'original Bash secret')

    def test_existing_default_directory_modes_and_symlink(self):
        # Existing ~/.local/bin is commonly 0755. Do not repair it or require 0700.
        self.env.pop('INSTALL_DIR')
        self.destination = self.home / '.local/bin'
        self.destination.mkdir(mode=0o700, parents=True)
        self.destination.chmod(0o755)
        self.target = self.destination / 'secret-go'
        result = self.run_install()
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o500)
        self.assertEqual(self.target.read_bytes(), NATIVE)
        self.target.unlink()
        self.log.unlink()
        diagnostic = (b'secret: unsafe install directory; use a real user-owned directory '
                      b'and run chmod go-w DIR\n')
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
        lock = self.destination / '.secret-go.install-lock'
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
