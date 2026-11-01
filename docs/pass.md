# Optional pass backend (staged Go CLI)

The opt-in Go CLI supports `pass:NAME` on Linux and macOS with upstream pass
1.7.4. Provider support does not activate hooks: the Bash guard,
hook configuration and plugin manifests are unchanged. Native GitHub runner
results remain a milestone gate; local synthetic tests are not native evidence.
Windows rejects pass value operations before launching a provider.

## Explicit configuration and use

Install pass 1.7.4 and GnuPG yourself and initialize your chosen private password
store in your own terminal. The CLI never initializes a password store, creates
keys, discovers arbitrary entries, unlocks keys or launches pinentry for you.
Choose `PASSWORD_STORE_DIR` (otherwise `$HOME/.password-store`) and optionally
`GNUPGHOME`. The password store root and all managed directories must be direct
private directories (0700); policy and ciphertext files must be private regular
files (0600). Normal operating-system aliases in parent paths are accepted,
but aliases at the root or within managed descendants are rejected.

With your opt-in Go executable, use the usual commands with `pass:team` in place
of a file reference:

```sh
secret stash pass:team TOKEN
secret show pass:team
secret run -f pass:team -- consumer
```

`stash` reads hidden terminal input or stdin, not a value argument. `get` remains
human-terminal-only; `clip` uses the existing clipboard boundary. `exec` is
unfiltered and is not an agent transport. `run` loads every registered account
before launch, strips inherited registered keys that are not selected, and
redacts every loaded literal from both output streams. A missing account,
including an unselected account, aborts before the child starts. Transformed
values and arbitrary child behavior are outside this accident-prevention model.

Human-only import, export, rotate, rename and delete use the existing terminal
and exact-consent boundary. Export requires `--on-conflict=fail`; import and
export are insert-only. Rotation requires an existing identity. Agent-side
operator denials are unchanged; do not invoke operator commands through an
agent tool. Dry runs are names-only, not evidence that ciphertext is readable.

## Inventory and identity

`SECRETS_DIR/NAME.pass-keys` is a names-only `secret-manifest-v1` inventory with
`backend=pass`, keys, canonical labels and random 32-lowercase-hex accounts.
`NAME.pass-keys.recovery` is the associated private names-only recovery intent.
Keychain and libsecret retain `NAME.keys`; the active Bash CLI ignores the pass
suffix. Go discovery finds both namespaces. `pass:team` and `libsecret:team`
can coexist and export in either direction; keychain and libsecret with the
same NAME still collide because their centralized manifest paths are identical.
No schema v2, provider-wide listing or arbitrary pass registration is introduced.

An account maps only to `secret/NAME/ACCOUNT/value.gpg` in the chosen password
store. Labels are manifest-only. Reads and deletes first require that exact
ciphertext to be a private regular file, avoiding pass's directory-list fallback.
Accepted values are nonempty bytes up to 64 KiB, including invalid UTF-8, with
no NUL, CR, internal LF, boundary whitespace or matching surrounding quotes.
Stash removes one terminal LF once. Provider reads do not silently trim bytes.
JSON, diff, completion, MCP and doctor read metadata without fetching values;
doctor's executable presence check is not a version or unlock probe.

## Provider process contract

The provider captures configuration once. Its complete environment contract is:

- Ambient `HOME` and `PATH`, and `GNUPGHOME` and `TMPDIR` when set. Home and
  selected directory variables must be absolute paths. Executable selection
  uses the captured PATH, with relative and empty search components removed
  from both executable lookup and the child environment.
- `LC_ALL=C`, `PASSWORD_STORE_DIR` set to the captured selected root,
  `PASSWORD_STORE_UMASK=077`, and `PASSWORD_STORE_ENABLE_EXTENSIONS=false`.
- Provider-owned `PASSWORD_STORE_GPG_OPTS` fixed to
  `--no-options --batch --no-tty --pinentry-mode error --status-fd 2 --logger-fd 2`.
  GPG configuration output/status directives cannot redirect plaintext or
  contaminate the value stream. Diagnostics remain on captured private stderr.
- `PASSWORD_STORE_SIGNING_KEY`, if configured, is preserved only when it is one
  or more uppercase 40-hex fingerprints separated by single spaces. Invalid
  configuration rejects; configured policy is never silently discarded. pass
  verifies the selected `.gpg-id` signature before encryption.

No other ambient variable is inherited. In particular shell startup, exported
functions, tracing, recipient overrides, GPG option overrides and extension
configuration are dropped. pass and GnuPG executables and provider configuration
remain trusted dependencies, not a sandbox boundary.

Only fixed argv is used: `pass version`, `pass insert --multiline -- ENTRY`,
`pass show -- ENTRY`, and `pass rm --force -- ENTRY`. Values are stdin/private
memory only, never argv, JSON, audit or error text. Provider output and prompts
are captured, bounded and cleared best-effort. Calls share the existing
15-second process-group deadline, 250 ms inherited-pipe wait and 1 MiB capture
bound; the accepted value bound is separately 64 KiB. Locked or unavailable
keys fail with fixed diagnostics instead of an interactive prompt.

## Writes, collisions and manual recovery

Every pass stash and operator write holds the shared secrets-directory lock,
persists recovery intent before provider mutation, allocates a fresh account,
reserves its directory atomically, inserts via stdin, verifies exact readback,
publishes the whole manifest once, then deletes obsolete exact accounts. The
reservation rejects pre-existing accounts, files, symlinks and sibling
ciphertext without insertion or deletion. Omitting `--force` is not an overwrite
guard: pass 1.7.4 automatically approves its overwrite prompt on non-TTY stdin.
Direct external pass writers are outside this concurrency guarantee.

pass 1.7.4 ignores `rm` failures and can exit zero without deleting ciphertext.
Cleanup therefore verifies exact absence through the anchored root after every
delete. Remaining ciphertext or uncertain filesystem state keeps recovery.
Git add/commit outcomes are outside the transaction contract and are not
claimed as detected. Publication and provider writes are not jointly atomic.

After any tracked failure, later mutations are blocked by recovery. In your
own terminal, use names-only doctor output, compare current manifest accounts
with the prepared/obsolete candidates, then verify the exact synthetic or real
provider entries yourself. An intent is not proof that an entry is orphaned.
Never blindly delete candidates, remove foreign collided entries, auto-clear
recovery or steal a tokened `.write-lock`. A killed writer's lock requires manual
owner verification before removal. Never copy values into a recovery record.

## Native gate, provenance and licensing

The required GitHub Actions pass matrix installs Linux prerequisites or macOS
`gnupg`, `bash`, and `gnu-getopt`. `scripts/install-test-pass.sh` installs upstream
commit `1078f2514d579178d5df7042c6a790e9c9b731ad` via its Makefile into a disposable
prefix, including the Darwin platform file. `testdata/pass/upstream.sha256`
pins the snapshot archive to
`5bd4dd44d2d5980b9dcbecd0348038d8241df61809cc258b522f6fec5c144593`.
This digest was computed with `sha256sum` after downloading the commit-addressed
`.tar.xz` snapshot from git.zx2c4.com into a new empty directory; extraction was
into a separate new empty directory. Source archives are not shipped or vendored.

`python3 -I tests/test-pass.py ABSOLUTE_GO_BINARY` is a GitHub-runner-only driver.
It verifies the staged executable, version, selected Bash and Darwin getopt
behavior before generating disposable keys. It owns private HOME, GNUPGHOME,
password store, secrets, cache and temporary roots. Only isolated children receive
`SECRET_REQUIRE_PASS=1`; missing required setup fails instead of skipping.
The driver exercises native transport, signatures, config isolation, locked keys,
recovery, operators and PTY confirmation, samples provider argv, and kills only
its disposable agents. Never enable this gate locally or use real stores for tests.

pass is an optional external GPLv2+ program. This project invokes it as a
subprocess; it is not linked, bundled or vendored. GnuPG and pass distribution,
key policy, agent lifetime and store backups remain the operator's responsibility.
