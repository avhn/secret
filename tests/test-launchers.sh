#!/usr/bin/env bash
# Disposable fixture checkouts and cross-built synthetic assets only.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# Resolve caller caches before replacing HOME; Go module directories are read-only.
GOMODCACHE="$(go env GOMODCACHE)"
GOCACHE="$(go env GOCACHE)"
export GOMODCACHE GOCACHE
TMP="$(mktemp -d)"
cleanup() {
    # Only this suite's owned scratch may have its permissions repaired.
    chmod -R u+w "$TMP"
    rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/assets" "$TMP/home" "$TMP/cache"
export HOME="$TMP/home" XDG_CACHE_HOME="$TMP/cache" GOTOOLCHAIN=local
export CGO_ENABLED=0 GOAMD64=v1 GOARM64=v8.0 GOFLAGS=''
for target in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do
    GOOS="${target%-*}" GOARCH="${target#*-}" go -C "$ROOT" build \
        -trimpath -buildvcs=false -ldflags='-buildid= -s -w -X main.version=0.2.2' \
        -o "$TMP/assets/secret-v0.2.2-$target" ./cmd/secret
done
# An authenticated digest can still point at a wrongly versioned candidate.
go -C "$ROOT" build -trimpath -buildvcs=false -o "$TMP/wrong-version" ./cmd/secret
python3 -I - "$ROOT" "$TMP" <<'PY'
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ROOT, WORK = (Path(value).resolve() for value in sys.argv[1:])
ASSETS = WORK / 'assets'
OS_NAME = {'Linux': 'linux', 'Darwin': 'darwin'}[os.uname().sysname]
ARCH = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[os.uname().machine]
ASSET = f'secret-v0.2.2-{OS_NAME}-{ARCH}'
DENY = (b'{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",'
        b'"permissionDecisionReason":"secret: verified binary unavailable; run scripts/install-release.sh"}}\n')
GUIDANCE = b'secret: verified binary unavailable; run scripts/install-release.sh\n'
VERSION = b'secret 0.2.2 (go)\n'
REAL_PATH = os.environ['PATH']
REAL_CP = shutil.which('cp')
REAL_GIT = shutil.which('git')


def run(argv, env, cwd, data=b'', timeout=30, **kwargs):
    return subprocess.run(list(map(str, argv)), input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=env, cwd=cwd, timeout=timeout, **kwargs)


class Launchers(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='case ', dir=WORK))
        self.root = self.work / 'trusted checkout with spaces'
        self.root.mkdir(mode=0o700)
        for relative in ('hooks/guard-go', 'bin/secret-go', 'scripts/install-release.sh'):
            dst = self.root / relative
            dst.parent.mkdir(mode=0o700, exist_ok=True)
            shutil.copyfile(ROOT / relative, dst)
            dst.chmod(0o700)
        self.assets = ASSETS
        self.manifest = self.root / 'dist/checksums-v0.2.2.txt'
        self.manifest.parent.mkdir(mode=0o700)
        self.manifest.write_bytes(b''.join(
            hashlib.sha256(p.read_bytes()).hexdigest().encode() + b'  ' + p.name.encode() + b'\n'
            for p in sorted(ASSETS.iterdir())))
        self.manifest.chmod(0o600)
        self.original_manifest = self.manifest.read_bytes()
        self.marker = self.root / '.secret-release-test-fixture'
        self.marker.touch(mode=0o600)
        # HOME is the private trust boundary. Its parents belong to the harness.
        self.home = self.work
        self.base = self.work / 'cache root'
        self.base.mkdir(mode=0o700)
        self.cache = self.base / 'secret/v0.2.2'
        self.cwd = self.work / 'other cwd'
        self.cwd.mkdir(mode=0o700)
        self.tools = self.work / 'tools'
        self.tools.mkdir(mode=0o700)
        self.env = dict(os.environ, HOME=str(self.home), XDG_CACHE_HOME=str(self.base),
                        SECRET_RELEASE_TEST_ROOT=str(self.base), PATH=REAL_PATH,
                        BASH_ENV='', ENV='', GIT_CONFIG_GLOBAL='/dev/null',
                        GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0')
        self.install = self.root / 'scripts/install-release.sh'
        self.cli = self.root / 'bin/secret-go'
        self.hook = self.root / 'hooks/guard-go'
        self.lock = Path(str(self.cache) + '.lock')
        self.witness = self.work / 'unexpected-execution'
        for fallback in (self.root / 'bin/secret', self.tools / 'secret'):
            self.script(fallback, f'printf fallback >"{self.witness}"\nexit 0\n')

    def tearDown(self):
        # Some cases deliberately make files unwritable or leave a stale lock.
        shutil.rmtree(self.work)

    def script(self, path, body):
        path.write_text('#!/bin/sh\n' + body)
        path.chmod(0o700)

    def invoke(self, argv, **kwargs):
        return run(argv, self.env, self.cwd, **kwargs)

    def installed(self, *extra):
        result = self.invoke([self.install, '--from-dir', self.assets, *extra])
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))
        self.assertEqual(stat.S_IMODE(self.cache.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.cache / 'secret').stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE((self.cache / 'verified').stat().st_mode), 0o600)
        self.assertEqual(hashlib.sha256((self.cache / 'secret').read_bytes()).digest(),
                         hashlib.sha256((self.assets / ASSET).read_bytes()).digest())
        self.assertEqual(len((self.cache / 'verified').read_text().splitlines()), 5)
        self.assertFalse(self.lock.exists())

    def denial(self):
        result = self.invoke([self.hook], data=b'synthetic request remains unread')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, DENY, b''))
        result = self.invoke([self.cli, 'version'])
        self.assertEqual((result.returncode, result.stdout, result.stderr), (70, b'', GUIDANCE))
        self.assertFalse(self.witness.exists())

    def tools_first(self):
        self.env['PATH'] = str(self.tools) + os.pathsep + REAL_PATH

    def test_cold_offline_and_no_fallback(self):
        self.tools_first()
        before = time.monotonic()
        self.denial()
        self.assertLess(time.monotonic() - before, 5)
        self.assertFalse(self.cache.exists())
        self.assertEqual(self.invoke([self.install, '--offline']).returncode, 1)
        self.assertFalse(self.cache.exists())

    def test_warm_offline_and_stdin(self):
        self.installed('--offline')
        # If a launcher tries networking or providers, fail loudly and witness it.
        for name in ('curl', 'gh', 'secret-tool', 'security'):
            self.script(self.tools / name, f'printf forbidden >"{self.witness}"\nprintf leak >&2\nexit 1\n')
        self.tools_first()
        result = self.invoke([self.cli, 'version'])
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, VERSION, b''))
        envelope = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': 'cat ~/.secrets/demo'}}).encode()
        result = self.invoke([self.hook], data=envelope)
        direct = self.invoke([self.cache / 'secret', 'hook', 'claude'], data=envelope)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (direct.returncode, direct.stdout, direct.stderr))
        self.assertEqual(json.loads(result.stdout)['hookSpecificOutput']['permissionDecision'], 'deny')
        self.assertFalse(self.witness.exists())
        self.assertEqual(self.invoke([self.install, '--offline']).returncode, 0)

    def test_relative_and_absolute_link_chains_other_cwd(self):
        self.installed()
        links = self.cwd / 'links with spaces'
        links.mkdir(mode=0o700)
        for launcher in (self.cli, self.hook, self.install):
            a, b = links / (launcher.name + '-a'), links / (launcher.name + '-b')
            b.symlink_to(os.path.relpath(launcher, links))
            a.symlink_to(b)
            args = ['version'] if launcher == self.cli else ['--offline'] if launcher == self.install else []
            data = b'{"tool_name":"Bash","tool_input":{"command":"true"}}' if launcher == self.hook else b''
            got = self.invoke([a, *args], data=data)
            direct = self.invoke([launcher, *args], data=data)
            self.assertEqual((got.returncode, got.stdout, got.stderr),
                             (direct.returncode, direct.stdout, direct.stderr))

    def test_overlong_links_and_dangling_links_reject(self):
        self.installed()
        # Linux accepts 35 links; Darwin's kernel rejects before bootstrap at 32.
        previous = self.cli
        for i in range(35):
            path = self.cwd / f'link-{i}'
            path.symlink_to(previous)
            previous = path
        try:
            result = self.invoke([previous, 'version'])
        except OSError as error:
            if OS_NAME != 'darwin' or error.errno != errno.ELOOP:
                raise
        else:
            self.assertEqual((result.returncode, result.stderr), (70, GUIDANCE))
        # Supply the real launcher body and chain as $0, avoiding kernel exec
        # traversal while still exercising the launcher's own 32-link bound.
        result = self.invoke(['/bin/sh', '-c', self.cli.read_text(), previous, 'version'])
        self.assertEqual((result.returncode, result.stdout, result.stderr), (70, b'', GUIDANCE))
        dangling = self.cwd / 'dangling'
        dangling.symlink_to(self.cwd / 'absent')
        got = self.invoke(['/bin/sh', dangling])
        self.assertNotEqual(got.returncode, 0)
        cycle_a, cycle_b = self.cwd / 'cycle-a', self.cwd / 'cycle-b'
        cycle_a.symlink_to(cycle_b)
        cycle_b.symlink_to(cycle_a)
        got = self.invoke(['/bin/sh', cycle_a])
        self.assertNotEqual(got.returncode, 0)
        self.assertFalse(self.witness.exists())

    def test_unsafe_parent_modes(self):
        self.installed()
        for parent in (self.root, self.root / 'scripts', self.base, self.cache.parent):
            with self.subTest(parent=parent.name):
                before = stat.S_IMODE(parent.stat().st_mode)
                parent.chmod(0o777)
                self.denial()
                parent.chmod(before)

    def test_unsafe_owners_if_privileged(self):
        # Owner validation is exercised without needing chown by a stat fault.
        self.installed()
        real_stat = shutil.which('stat')
        self.script(self.tools / 'stat', f'case "$1" in -c|-f) printf "123456789 700\\n" ;; *) exec "{real_stat}" "$@" ;; esac\n')
        self.tools_first()
        self.denial()

    def test_manifest_and_cache_aliases(self):
        self.installed()
        candidates = (self.manifest, self.manifest.parent, self.cache,
                      self.cache.parent, self.cache / 'secret', self.cache / 'verified')
        for target in candidates:
            with self.subTest(target=target.name):
                backup = target.with_name(target.name + '.saved')
                target.rename(backup)
                target.symlink_to(backup, target_is_directory=backup.is_dir())
                self.denial()
                self.assertNotEqual(self.invoke([self.install, '--from-dir', self.assets]).returncode, 0)
                target.unlink()
                backup.rename(target)

    def test_hardlinked_trust_files_reject(self):
        self.installed()
        for target in (self.manifest, self.cache / 'secret', self.cache / 'verified', self.install):
            with self.subTest(target=target.name):
                alias = self.work / 'hardlink-alias'
                os.link(target, alias)
                self.denial()
                alias.unlink()

    def test_manifest_modes_and_malformed_grammar(self):
        self.installed()
        self.manifest.chmod(0o666)
        self.denial()
        self.manifest.chmod(0o600)
        lines = self.original_manifest.splitlines(keepends=True)
        variants = [b'', b''.join(lines[:3]), b''.join(lines + [lines[0]]),
                    b''.join([lines[0], lines[0], *lines[2:]]), b''.join(reversed(lines)),
                    self.original_manifest[:-1], self.original_manifest + b'\n',
                    self.original_manifest.replace(b'  secret', b' secret', 1),
                    self.original_manifest.replace(b'  secret', b'  ../secret', 1),
                    b'G' + self.original_manifest[1:],
                    self.original_manifest.replace(b'v0.2.2', b'v9.9.9', 1),
                    self.original_manifest.replace(b'amd64', b'ppc64', 1),
                    self.original_manifest.replace(b'\n', b'\r\n')]
        for index, data in enumerate(variants):
            with self.subTest(variant=index):
                self.manifest.write_bytes(data)
                self.denial()
                self.assertEqual(self.invoke([self.install, '--from-dir', self.assets]).returncode, 1)
        self.manifest.write_bytes(self.original_manifest)

    def test_rehash_and_private_cache_modes(self):
        self.installed()
        for target, good_mode in ((self.cache, 0o700), (self.cache / 'secret', 0o500),
                                  (self.cache / 'verified', 0o600)):
            target.chmod(0o777)
            self.denial()
            target.chmod(good_mode)
        executable = self.cache / 'secret'
        executable.chmod(0o700)
        with executable.open('ab') as stream:
            stream.write(b'corruption')
        executable.chmod(0o500)
        self.denial()
        self.installed()
        metadata = self.cache / 'verified'
        metadata.write_bytes(metadata.read_bytes().replace(b'version=0.2.2', b'version=9.9.9'))
        self.denial()

    def test_wrong_digest_version_and_architecture(self):
        self.assets = self.work / 'bad assets'
        shutil.copytree(ASSETS, self.assets)
        native = self.assets / ASSET
        native.write_bytes(b'truncated')
        self.assertEqual(self.invoke([self.install, '--from-dir', self.assets]).returncode, 1)
        self.denial()
        other_arch = 'arm64' if ARCH == 'amd64' else 'amd64'
        for source in (WORK / 'wrong-version', ASSETS / f'secret-v0.2.2-{OS_NAME}-{other_arch}'):
            with self.subTest(source=source.name):
                shutil.copyfile(source, native)
                sha = hashlib.sha256(native.read_bytes()).hexdigest().encode()
                self.manifest.write_bytes(b''.join(sha + line[64:] if line[66:].rstrip() == ASSET.encode() else line
                                                  for line in self.original_manifest.splitlines(keepends=True)))
                self.assertEqual(self.invoke([self.install, '--from-dir', self.assets]).returncode, 1)
                self.assertFalse((self.cache / 'secret').exists())

    def test_fixture_requires_both_marker_and_root(self):
        self.marker.unlink()
        result = self.invoke([self.install, '--from-dir', self.assets])
        self.assertEqual(result.returncode, 1)
        self.denial()
        self.assertFalse(self.cache.exists())
        self.marker.touch(mode=0o600)
        self.marker.chmod(0o666)
        self.assertEqual(self.invoke([self.install, '--from-dir', self.assets]).returncode, 1)
        self.marker.chmod(0o600)
        self.marker.unlink()
        self.marker.symlink_to(self.manifest)
        self.assertEqual(self.invoke([self.install, '--from-dir', self.assets]).returncode, 1)

    def test_missing_dependencies_and_unsupported_platform(self):
        isolated = self.work / 'isolated tools'
        isolated.mkdir(mode=0o700)
        names = ('dirname', 'readlink', 'uname', 'id', 'stat', 'awk', 'wc', 'cmp', 'chmod',
                 'mv', 'cp', 'rm', 'rmdir', 'mkdir', 'mktemp', 'sleep', 'git', 'python3')
        for name in names:
            location = shutil.which(name)
            self.assertIsNotNone(location, name)
            (isolated / name).symlink_to(location)
        self.env['PATH'] = str(isolated)
        result = self.invoke([self.install, '--from-dir', self.assets])
        self.assertEqual(result.returncode, 4)
        self.denial()
        (isolated / 'sha256sum').symlink_to(shutil.which('sha256sum') or shutil.which('shasum'))
        (isolated / 'uname').unlink()
        self.script(isolated / 'uname', 'printf "unsupported\\n"\n')
        self.assertEqual(self.invoke([self.install, '--from-dir', self.assets]).returncode, 4)
        self.denial()

    def test_missing_cold_install_tools_have_fixed_status(self):
        self.production()
        names = ('dirname', 'readlink', 'uname', 'id', 'stat', 'awk', 'wc', 'cmp', 'chmod',
                 'mv', 'cp', 'rm', 'rmdir', 'mkdir', 'mktemp', 'sleep', 'git', 'python3',
                 'sha256sum', 'shasum', 'gh', 'curl')
        for missing in ('readlink', 'python3', 'gh', 'curl'):
            with self.subTest(missing=missing):
                isolated = self.work / ('without-' + missing)
                isolated.mkdir(mode=0o700)
                for name in names:
                    location = shutil.which(name, path=REAL_PATH)
                    if name != missing and location:
                        (isolated / name).symlink_to(location)
                self.env['PATH'] = str(isolated)
                args = [] if missing == 'curl' else ['--from-dir', self.assets]
                got = self.invoke([self.install, *args])
                self.assertEqual((got.returncode, got.stdout, got.stderr),
                                 (4, b'', b'secret: unsupported platform or missing dependency\n'))
                self.denial()
        self.env['PATH'] = REAL_PATH

    def test_usage_codes(self):
        for args in (['--wat'], ['--from-dir'], ['--from-dir', '--offline'],
                     ['--offline', '--offline'], ['--from-dir', 'a', '--from-dir', 'b']):
            with self.subTest(args=args):
                got = self.invoke([self.install, *args])
                self.assertEqual(got.returncode, 2)
                self.assertEqual(got.stdout, b'')

    def test_json_write_failure(self):
        if not Path('/dev/full').exists():
            self.skipTest('/dev/full unavailable on this OS; closed-fd test runs below')
        with open('/dev/full', 'wb') as full:
            got = subprocess.run([self.hook], env=self.env, cwd=self.cwd, stdout=full,
                                 stderr=subprocess.PIPE, timeout=10)
        self.assertEqual((got.returncode, got.stderr), (2, b'secret: verified binary unavailable\n'))

    def test_closed_json_output(self):
        commands = [[self.hook], ['/bin/sh', self.hook]]
        for name, flags in (('dash', []), ('bash', ['--posix'])):
            shell = shutil.which(name)
            if shell:
                commands.append([shell, *flags, self.hook])
        for command in commands:
            with self.subTest(command=command):
                got = self.invoke(['/bin/sh', '-c', 'exec 1>&-; exec "$@"', 'fixture', *command])
                self.assertEqual((got.returncode, got.stdout, got.stderr),
                                 (2, b'', b'secret: verified binary unavailable\n'))

    def test_lock_timeout_never_steals(self):
        self.cache.mkdir(mode=0o700, parents=True)
        self.lock.mkdir(mode=0o700)
        owner = self.lock / 'owner'
        owner.write_bytes(b'pid=999999\ntoken=synthetic-stale\n')
        owner.chmod(0o600)
        before = time.monotonic()
        got = self.invoke([self.install, '--from-dir', self.assets])
        self.assertEqual(got.returncode, 3)
        self.assertLess(time.monotonic() - before, 6)
        self.assertEqual(owner.read_bytes(), b'pid=999999\ntoken=synthetic-stale\n')
        self.denial()
        self.assertFalse((self.cache / 'secret').exists())

    def test_concurrent_first_install(self):
        self.script(self.tools / 'cp', f'sleep 1\nexec "{REAL_CP}" "$@"\n')
        self.tools_first()
        command = [str(self.install), '--from-dir', str(self.assets)]
        processes = [subprocess.Popen(command, env=self.env, cwd=self.cwd,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        for process in processes:
            out, err = process.communicate(timeout=20)
            self.assertEqual((process.returncode, out, err), (0, b'', b''))
        self.installed()
        self.assertEqual(list(self.cache.parent.glob('.install.*')), [])

    def interrupted_install(self, sig):
        ready = self.work / 'copy-started'
        self.script(self.tools / 'cp', f'printf ready >"{ready}"\nwhile :; do sleep 1; done\n')
        self.tools_first()
        process = subprocess.Popen([str(self.install), '--from-dir', str(self.assets)],
                                   env=self.env, cwd=self.cwd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        try:
            deadline = time.monotonic() + 10
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(ready.exists(), 'installer never reached locked copy')
            self.assertTrue((self.lock / 'owner').is_file())
            os.killpg(process.pid, sig)
            process.communicate(timeout=10)
            self.assertNotEqual(process.returncode, 0)
            self.assertFalse((self.cache / 'secret').exists())
            self.denial()
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
        return self.lock.exists()

    def test_interrupted_install_owned_cleanup(self):
        self.assertFalse(self.interrupted_install(signal.SIGTERM))
        self.assertEqual(list(self.cache.parent.glob('.install.*')), [])

    def test_killed_install_keeps_lock(self):
        self.assertTrue(self.interrupted_install(signal.SIGKILL))
        self.assertEqual(self.invoke([self.install, '--from-dir', self.assets]).returncode, 3)
        self.assertTrue((self.lock / 'owner').is_file())

    def production(self):
        self.marker.unlink()
        self.env.pop('SECRET_RELEASE_TEST_ROOT')
        self.env.update(GIT_AUTHOR_NAME='fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
                        GIT_COMMITTER_NAME='fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid')
        for args in (['init', '-q', str(self.root)], ['-C', str(self.root), 'add', '.'],
                     ['-C', str(self.root), '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture'],
                     ['-C', str(self.root), '-c', 'tag.gpgsign=false', 'tag', '-a',
                      'v0.2.2', '-m', 'synthetic annotated release']):
            got = self.invoke([REAL_GIT, *args])
            self.assertEqual(got.returncode, 0, got.stderr)
        commit = self.invoke([REAL_GIT, '-C', self.root, 'rev-parse', 'HEAD']).stdout.strip().decode()
        sha = hashlib.sha256((ASSETS / ASSET).read_bytes()).hexdigest()
        self.assets = self.work / 'preloaded assets'
        self.assets.mkdir(mode=0o700)
        shutil.copyfile(ASSETS / ASSET, self.assets / ASSET)
        (self.assets / f'sha256:{sha}.jsonl').write_text('synthetic bundle\n')
        self.expected_commit = commit
        self.sha = sha
        log = self.work / 'gh-args'
        # This stub tests policy wiring, not cryptographic provenance or TUF.
        self.script(self.tools / 'gh', f'''printf '%s\\n' "$*" >>"{log}"
case "$1 $2" in
'attestation trusted-root') printf 'synthetic trust root\\n' ;;
'attestation verify')
    case " $* " in
    *" --source-digest {commit} "*) ;; *) exit 1 ;; esac
    case " $* " in
    *" --signer-digest {commit} "*) ;; *) exit 1 ;; esac
    case " $* " in
    *" --deny-self-hosted-runners "*) ;; *) exit 1 ;; esac
    case " $* " in
    *" --source-ref refs/tags/v0.2.2 "*) ;; *) exit 1 ;; esac
    case " $* " in
    *" --repo avhn/secret "*) ;; *) exit 1 ;; esac
    case " $* " in
    *" --cert-identity https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/v0.2.2 "*) ;; *) exit 1 ;; esac
    case " $* " in
    *" --cert-oidc-issuer https://token.actions.githubusercontent.com "*) ;; *) exit 1 ;; esac
    case " $* " in *" --bundle "*) ;; *) exit 1 ;; esac
    case " $* " in *" --custom-trusted-root "*) ;; *) exit 1 ;; esac
    printf '%s\\n' '[{{"verificationResult":{{"statement":{{"predicateType":"https://slsa.dev/provenance/v1","subject":[{{"name":"{ASSET}","digest":{{"sha256":"{sha}"}}}}]}}}}}}]'
    ;;
*) printf 'synthetic provider output must not escape\\n' >&2; exit 1 ;;
esac
''')
        self.tools_first()
        return log

    def test_production_policy_and_offline_trust_root(self):
        log = self.production()
        # Neither a bundle nor an attacker-provided trust root grants offline trust.
        (self.assets / 'trusted_root.jsonl').write_text('untrusted root\n')
        got = self.invoke([self.install, '--offline', '--from-dir', self.assets])
        self.assertEqual(got.returncode, 1)
        self.assertFalse(log.exists())
        self.installed()
        self.assertTrue((self.cache / 'attestation.jsonl').is_file())
        self.assertTrue((self.cache / 'trusted_root.jsonl').is_file())
        log.unlink()
        # A damaged binary can be restored offline using authenticated cached roots.
        (self.cache / 'secret').unlink()
        self.installed('--offline')
        calls = log.read_text()
        self.assertNotIn('trusted-root', calls.split('--custom-trusted-root')[0])
        self.assertIn('--bundle ', calls)
        self.assertIn('--custom-trusted-root ', calls)
        self.assertNotIn('attestation download', calls)
        log.unlink()
        self.assertEqual(self.invoke([self.cli, 'version']).stdout, VERSION)
        self.assertFalse(log.exists())

    def test_production_requires_trusted_tag_and_committed_manifest(self):
        self.production()
        got = self.invoke([REAL_GIT, '-C', self.root, 'tag', '-d', 'v0.2.2'])
        self.assertEqual(got.returncode, 0)
        self.assertEqual(self.invoke([self.install, '--from-dir', self.assets]).returncode, 1)
        self.assertEqual(self.invoke([REAL_GIT, '-C', self.root, '-c', 'tag.gpgsign=false',
                                      'tag', 'v0.2.2']).returncode, 0)
        self.assertEqual(self.invoke([self.install, '--from-dir', self.assets]).returncode, 1)
        self.assertFalse((self.work / 'gh-args').exists(), 'lightweight tag reached provenance')
        self.assertEqual(self.invoke([REAL_GIT, '-C', self.root, '-c', 'tag.gpgsign=false',
                                      'tag', '-f', '-a', 'v0.2.2', '-m',
                                      'synthetic annotated release']).returncode, 0)
        # Keep grammar valid but differ from the trusted committed manifest.
        data = bytearray(self.manifest.read_bytes())
        data[0] = ord('0') if data[0] != ord('0') else ord('1')
        self.manifest.write_bytes(data)
        self.assertEqual(self.invoke([self.install, '--from-dir', self.assets]).returncode, 1)

    def test_bad_provenance_and_subject_do_not_leak(self):
        self.production()
        for body in ('printf downloader-output\nprintf provider-output >&2\nexit 1\n',
                     'case "$2" in trusted-root) printf root ;; verify) printf "[]" ;; esac\n',
                     'case "$2" in trusted-root) printf root ;; verify) printf \'[{"verificationResult":{"statement":{"predicateType":"https://slsa.dev/provenance/v1","subject":[]}}}]\' ;; esac\n'):
            self.script(self.tools / 'gh', body)
            got = self.invoke([self.install, '--from-dir', self.assets])
            self.assertEqual((got.returncode, got.stdout, got.stderr),
                             (1, b'', b'secret: release installation failed\n'))
            self.denial()
            self.assertFalse((self.cache / 'secret').exists())

    def test_downloader_rejects_redirects_truncation_stalls_and_errors(self):
        self.production()
        for body in ('printf leak >&2\nexit 28\n',
                     'while [ "$#" -gt 0 ]; do if [ "$1" = --output ]; then shift; : >"$1"; fi; shift; done\nprintf 200\n',
                     'while [ "$#" -gt 0 ]; do if [ "$1" = --dump-header ]; then shift; printf "Location: https://attacker.invalid/asset\\r\\n" >"$1"; fi; shift; done\nprintf 302\n'):
            self.script(self.tools / 'curl', body)
            got = self.invoke([self.install])
            self.assertEqual((got.returncode, got.stdout, got.stderr),
                             (1, b'', b'secret: release installation failed\n'))
            self.assertFalse((self.cache / 'secret').exists())
        # Assert bounds and HTTPS-only handling on the actual curl invocation.
        self.script(self.tools / 'curl', '''case " $* " in
*" --connect-timeout 10 --max-time 60 --max-filesize 67108864 "*) ;; *) exit 99 ;; esac
case " $* " in *" --proto =https --proto-redir =https --max-redirs 0 "*) ;; *) exit 99 ;; esac
printf bounds-checked >"''' + str(self.witness) + '''"
exit 28
''')
        self.assertEqual(self.invoke([self.install]).returncode, 1)
        self.assertEqual(self.witness.read_text(), 'bounds-checked')


unittest.main(argv=['test-launchers'], verbosity=2)
PY
