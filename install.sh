#!/bin/sh
# Pinned standalone installer. The script itself is trusted before payload verification.
# Download/review/run or a reviewed checkout is stronger than piping HTTPS to sh.
set -f
umask 077
command -v python3 >/dev/null 2>&1 || {
    printf '%s\n' 'secret: Python 3 is required from a trusted package channel' >&2
    exit 4
}
exec python3 -I - "$@" <<'PY'
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

REPO = 'avhn/secret'
WORKFLOW = 'https://github.com/' + REPO + '/.github/workflows/release.yml'
LIMIT = 64 * 1024 * 1024


class InstallError(Exception):
    pass


def require(condition):
    if not condition:
        raise InstallError()


def invalid_constant(value):
    raise InstallError()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def main():
    version = os.environ.get('SECRET_VERSION', '0.3.2')
    commit = os.environ.get('SECRET_RELEASE_COMMIT', '')
    destination = os.environ.get('INSTALL_DIR', '')
    options = {'--version': version, '--commit': commit, '--dir': destination}
    seen = set()
    show_help = False
    args = iter(sys.argv[1:])
    for arg in args:
        if arg in ('--help', '-h'):
            show_help = True
            continue
        if arg not in options or arg in seen:
            raise InstallError('invalid arguments (use --help)')
        value = next(args, '')
        if not value or value.startswith('--'):
            raise InstallError('invalid arguments (use --help)')
        old = options[arg]
        # Environment and flag pins may agree, but must not silently conflict.
        if arg != '--dir' and old and (arg != '--version' or 'SECRET_VERSION' in os.environ):
            old_pin = old[1:] if arg == '--version' and old.startswith('v') else old
            new_pin = value[1:] if arg == '--version' and value.startswith('v') else value
            require(old_pin == new_pin)
        options[arg] = value
        seen.add(arg)
    if show_help:
        print('Usage: sh install.sh [--version V] [--commit C] [--dir DIR] [--help]')
        print('SECRET_VERSION defaults to 0.3.2; SECRET_RELEASE_COMMIT is an optional full SHA.')
        print('INSTALL_DIR defaults to ~/.local/bin. gh, curl and Python 3 are required.')
        print('Existing install directories must be user-owned and not group/other-writable (chmod go-w DIR).')
        print('No source build, PATH/profile edits, stores or client configuration changes.')
        return
    version = options['--version']
    if version.startswith('v'):
        version = version[1:]
    require(re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version))
    commit = options['--commit']
    require(not commit or re.fullmatch('[0-9a-f]{40}', commit))
    for tool in ('gh', 'curl'):
        if not shutil.which(tool):
            raise InstallError(tool + ' is required; install it through a trusted package channel')
    os_name = {'Linux': 'linux', 'Darwin': 'darwin'}.get(os.uname().sysname)
    arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(os.uname().machine)
    require(os_name and arch)
    tag = 'v' + version
    asset = 'secret-' + tag + '-' + os_name + '-' + arch
    manifest_name = 'checksums-' + tag + '.txt'
    uid = os.getuid()

    def safe(path, private=False, directory=True):
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode))
        require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        require(info.st_uid in (0, uid))
        require(not info.st_mode & 0o022 or (directory and info.st_uid == 0 and info.st_mode & stat.S_ISVTX))
        if not directory:
            require(info.st_nlink == 1)
        if private:
            require(info.st_uid == uid and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o500))

    def chain(path):
        for node in [*reversed(path.parents), path]:
            safe(node)

    def make(path):
        if not path.exists() and not path.is_symlink():
            make(path.parent)
            path.mkdir(mode=0o700)
        chain(path)

    def safe_destination(path):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022):
            raise InstallError('unsafe install directory; use a real user-owned directory and run chmod go-w DIR')

    raw_dir = options['--dir'] or os.path.join(os.environ['HOME'], '.local', 'bin')
    require(not any(ord(char) < 32 or ord(char) == 127 for char in raw_dir))
    require('..' not in Path(raw_dir).parts and '.' not in raw_dir.split('/'))
    directory = Path(os.path.abspath(raw_dir))
    if directory.exists() or directory.is_symlink():
        safe_destination(directory)
    auth_message = 'GitHub CLI is not authenticated; run gh auth login or set GH_TOKEN, then retry'
    try:
        # Discard status diagnostics, never inspect credentials or put them in argv.
        # Do not create a destination or scratch before gh succeeds.
        with subprocess.Popen(['gh', 'auth', 'status', '--hostname', 'github.com'],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, start_new_session=True) as authentication:
            try:
                status = authentication.wait(timeout=60)
            finally:
                if authentication.poll() is None:
                    os.killpg(authentication.pid, signal.SIGKILL)
                    authentication.wait()
    except (OSError, subprocess.SubprocessError):
        raise InstallError(auth_message)
    if status != 0:
        raise InstallError(auth_message)
    make(directory)
    safe_destination(directory)
    target = directory / 'secret-go'

    def check_target():
        if target.exists() or target.is_symlink():
            safe(target, private=True, directory=False)

    check_target()
    scratch = Path(tempfile.mkdtemp(prefix='.secret-install-', dir=directory))
    lock = directory / '.secret-go.install-lock'
    token = 'pid=' + str(os.getpid()) + '\ntoken=' + secrets.token_hex(24) + '\n'
    owned = False
    try:
        for attempt in range(4):
            try:
                lock.mkdir(mode=0o700)
                owned = True
                (lock / 'owner').write_text(token, encoding='ascii')
                break
            except FileExistsError:
                safe(lock, private=True)
                if attempt == 3:
                    raise InstallError('installation lock timeout; verify and remove stale lock manually')
                time.sleep(1)
        counter = 0

        def run(argv, limit=1024 * 1024, timeout=90, watched=None):
            nonlocal counter
            counter += 1
            control = scratch / ('control-' + str(counter))
            control.mkdir(mode=0o700)
            output = control / 'stdout'
            error = control / 'stderr'
            with output.open('wb') as out, error.open('wb') as err:
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                           start_new_session=True,
                                           env=dict(os.environ, GH_PROMPT_DISABLED='1', GH_NO_UPDATE_NOTIFIER='1'))
                deadline = time.monotonic() + timeout
                try:
                    while process.poll() is None:
                        require(time.monotonic() < deadline)
                        require(output.stat().st_size <= limit and error.stat().st_size <= 1048576)
                        for watched_path, maximum in watched or ():
                            if watched_path.exists():
                                require(watched_path.stat().st_size <= maximum)
                        time.sleep(0.02)
                    require(process.returncode == 0)
                    require(output.stat().st_size <= limit and error.stat().st_size <= 1048576)
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
            return output.read_bytes()

        def download(name, limit):
            url = 'https://github.com/' + REPO + '/releases/download/' + tag + '/' + name
            for redirect in range(4):
                request_id = secrets.token_hex(8)
                body_dir = scratch / ('body-' + request_id)
                header_dir = scratch / ('headers-' + request_id)
                body_dir.mkdir(mode=0o700)
                header_dir.mkdir(mode=0o700)
                body, headers = body_dir / name, header_dir / 'response'
                code = run(['curl', '--silent', '--proto', '=https', '--proto-redir', '=https',
                            '--max-redirs', '0', '--connect-timeout', '10', '--max-time', '60',
                            '--max-filesize', str(limit), '--dump-header', str(headers), '--output', str(body),
                            '--write-out', '%{http_code}', url], watched=((body, limit), (headers, 65536)))
                require(body.is_file() and body.stat().st_size <= limit)
                require(headers.is_file() and headers.stat().st_size <= 65536)
                if code == b'200':
                    return body
                require(code in (b'301', b'302', b'303', b'307', b'308') and redirect < 3)
                locations = re.findall(rb'^location:[ \t]*([^\r\n]+)\r?$', headers.read_bytes(), re.I | re.M)
                require(len(locations) == 1)
                url = locations[0].decode('ascii')
                parsed = urlsplit(url)
                require(parsed.scheme == 'https' and parsed.netloc == 'release-assets.githubusercontent.com')
                require(not any(ord(c) <= 32 or c == '\\' for c in url))
            raise InstallError()

        def digest(path):
            with path.open('rb') as stream:
                return hashlib.sha256(stream.read(LIMIT + 1)).hexdigest()

        def verify(path, name, expected_commit=''):
            sha = digest(path)
            bundle = download('sha256-' + sha + '.jsonl', 1048576)
            argv = ['gh', 'attestation', 'verify', str(path), '--repo', REPO,
                    '--source-ref', 'refs/tags/' + tag,
                    '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com',
                    '--cert-identity', WORKFLOW + '@refs/tags/' + tag,
                    '--deny-self-hosted-runners', '--bundle', str(bundle), '--format', 'json']
            if expected_commit:
                argv += ['--source-digest', expected_commit, '--signer-digest', expected_commit]
            result = json.loads(run(argv), object_pairs_hook=unique, parse_constant=invalid_constant)
            require(isinstance(result, list) and result)
            commits = set()
            for item in result:
                statement = item['verificationResult']['statement']
                require(statement['predicateType'] == 'https://slsa.dev/provenance/v1')
                subjects = statement['subject']
                require(isinstance(subjects, list) and subjects)
                require(all(isinstance(subject, dict) for subject in subjects))
                matches = [subject for subject in subjects if subject.get('name') == name]
                require(len(matches) == 1 and matches[0].get('digest') == {'sha256': sha})
                definition = statement['predicate']['buildDefinition']
                workflow = definition['externalParameters']['workflow']
                require(workflow == {'repository': 'https://github.com/' + REPO,
                                     'ref': 'refs/tags/' + tag, 'path': '.github/workflows/release.yml'})
                dependencies = definition['resolvedDependencies']
                source = [dep for dep in dependencies if dep.get('uri') in (
                    'git+https://github.com/' + REPO + '@refs/tags/' + tag,
                    'https://github.com/' + REPO + '@refs/tags/' + tag)]
                require(len(source) == 1)
                value = source[0]['digest']['gitCommit']
                require(re.fullmatch('[0-9a-f]{40}', value))
                commits.add(value)
            require(len(commits) == 1)
            value = commits.pop()
            require(not expected_commit or value == expected_commit)
            return value

        def api(endpoint, limit=16384):
            response = run(['gh', 'api', '--hostname', 'github.com', '--method', 'GET',
                            'repos/' + REPO + '/' + endpoint], limit=limit)
            result = json.loads(response, object_pairs_hook=unique, parse_constant=invalid_constant)
            require(isinstance(result, dict))
            return result

        def source_boundary(authenticated, manifest):
            reference = api('git/ref/tags/' + tag)
            require(reference['ref'] == 'refs/tags/' + tag)
            target = reference['object']
            require(target['type'] == 'tag')  # Lightweight tags never establish C.
            visited = set()
            for depth in range(8):
                sha = target['sha']
                require(re.fullmatch('[0-9a-f]{40}', sha) and sha not in visited)
                visited.add(sha)
                annotated = api('git/tags/' + sha)
                require(annotated['sha'] == sha)
                if depth == 0:
                    require(annotated['tag'] == tag)
                target = annotated['object']
                if target['type'] == 'commit':
                    require(target['sha'] == authenticated)
                    break
                require(target['type'] == 'tag')
            else:
                raise InstallError()
            # The commit endpoint reports the diff against the sole parent. Do
            # not paginate or accept a partial multi-file result as a one-file C.
            final = api('commits/' + authenticated + '?per_page=100', limit=1048576)
            require(final['sha'] == authenticated)
            parents = final['parents']
            require(isinstance(parents, list) and len(parents) == 1)
            require(re.fullmatch('[0-9a-f]{40}', parents[0]['sha']))
            require(parents[0]['sha'] != authenticated)
            changed = final['files']
            require(isinstance(changed, list) and len(changed) == 1)
            checksum_path = 'dist/' + manifest_name
            require(changed[0]['filename'] == checksum_path and changed[0]['status'] == 'added')
            require('previous_filename' not in changed[0])
            blob = changed[0]['sha']
            require(re.fullmatch('[0-9a-f]{40}', blob))
            contents = api('contents/' + checksum_path + '?ref=' + authenticated)
            require(contents['type'] == 'file' and contents['path'] == checksum_path)
            require(contents['sha'] == blob and contents['encoding'] == 'base64')
            size, encoded = contents['size'], contents['content']
            require(type(size) is int and 0 <= size <= 4096)
            require(isinstance(encoded, str) and len(encoded) <= 8192)
            require(re.fullmatch('[A-Za-z0-9+/=\\r\\n]*', encoded))
            committed = base64.b64decode(encoded.replace('\r', '').replace('\n', ''), validate=True)
            require(len(committed) == size and committed == manifest.read_bytes())

        manifest = download(manifest_name, 4096)
        authenticated = verify(manifest, manifest_name, commit)
        # First verification authenticates C; the second also pins signer/source C.
        verify(manifest, manifest_name, authenticated)
        source_boundary(authenticated, manifest)
        names = sorted(['secret-' + tag + '-' + system + '-' + cpu + ('.exe' if system == 'windows' else '')
                        for system in ('darwin', 'linux', 'windows') for cpu in ('amd64', 'arm64')] +
                       ['secret-' + tag + '-desktop.mcpb', 'server.json'])
        lines = manifest.read_bytes().splitlines(keepends=True)
        require(len(lines) == len(names))
        entries = {}
        for name, line in zip(names, lines):
            require(re.fullmatch(rb'[0-9a-f]{64}  ' + re.escape(name.encode()) + rb'\n', line))
            entries[name] = line[:64].decode('ascii')
        binary = download(asset, LIMIT)
        sha = entries[asset]
        require(digest(binary) == sha)
        require(verify(binary, asset, authenticated) == authenticated)
        with binary.open('rb') as stream:
            header = stream.read(32)
        if os_name == 'linux':
            require(header[:6] == b'\x7fELF\x02\x01')
            require(struct.unpack_from('<H', header, 18)[0] == {'amd64': 62, 'arm64': 183}[arch])
        else:
            require(header[:4] == b'\xcf\xfa\xed\xfe')
            require(struct.unpack_from('<I', header, 4)[0] == {'amd64': 0x1000007, 'arm64': 0x100000c}[arch])
        binary.chmod(0o500)
        require(run([str(binary), 'version'], limit=256, timeout=10) == ('secret ' + version + ' (go)\n').encode())
        require(digest(binary) == sha)
        safe_destination(directory)
        chain(directory)
        check_target()
        os.replace(binary, target)
        print('Installed ' + str(target))
        quoted = "'" + str(target).replace("'", "'\\''") + "'"
        print("claude mcp add --scope user --transport stdio secret -- " + quoted + " mcp --store 'file:/ABSOLUTE/STORE'")
        print('Raw executable only: no per-exec checkout rehash, MCP registration or hook activation.')
    finally:
        if owned and not lock.is_symlink():
            owner_path = lock / 'owner'
            try:
                safe(lock, private=True)
                safe(owner_path, directory=False)
                require(owner_path.stat().st_size <= 128)
                if owner_path.read_text(encoding='ascii') == token:
                    owner_path.unlink()
                    lock.rmdir()
            except (InstallError, OSError, UnicodeError):
                pass  # A changed owner/lock requires manual recovery, never stealing.
        shutil.rmtree(scratch)


# Catchable termination cleans owned scratch/locks; SIGKILL leaves a manual lock.
def terminate(signum, frame):
    raise InstallError()


for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
    signal.signal(sig, terminate)
try:
    main()
except Exception as error:
    message = str(error) if isinstance(error, InstallError) and str(error) else 'release installation failed'
    print('secret: ' + message, file=sys.stderr)
    sys.exit(1)
PY
