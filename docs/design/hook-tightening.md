# Hook tightening decisions for M2

## Scope and limits

The default Go build analyzes Bash tool calls through a bounded AST policy. The
installed hook remains `hooks/guard-secrets`; no plugin manifest or `hooks.json`
has changed. Synthetic tests do not establish installed-hook containment, host
shell-dialect coverage, or failure-blocking behavior.

The security model is accident prevention, not a sandbox. The analyzer does not
execute Git, a shell interpreter, child commands, or provider value APIs while
making a decision. It reads only the bounded metadata described below. Real-host
failure tests, dialect evidence, and supported-platform CI remain separate gates.

## Current policy

- P0 recovers panics from decoding or analysis and emits a fixed denial without
  the panic payload. Output errors still propagate, so an unwritable host channel
  is not a failure-blocking guarantee.
- P1 denies Git subcommands outside the case-sensitive built-in table, including
  custom aliases and inline `-c alias.*`, without reading Git configuration for
  aliases. Users can run an alias's expanded built-in command instead. It applies
  exact global-option arities, inert-key allowlisting, index gates, and
  command-running surface checks. Unknown options, subcommands, and ambiguous
  repository locations deny.
- P1 content checks use a bounded resolved index, rather than the work tree.
  Protected index entries, protected path arguments, and indeterminate
  repositories deny. Ignored and untracked `.env` files do not block `git log
-p`; deleted-only history remains an exclusion. Index parsing supports versions
  2, 3, and 4 under byte, entry, path-length, and checksum limits. Unsupported,
  inaccessible, malformed, split, sparse, SHA-256, or otherwise indeterminate
  index states deny.
- P2 analyzes `find` children after wrapper handling. Only listed metadata
  children are exempt from bounded scope inspection; unknown children, including
  `echo`, are readers. Symlinks, uncertified operand streams, and unsupported
  `parallel` grammar deny. A supplied non-protected `xargs` argument-list file is
  a modeled operand source, while stdin-fed readers inspect the cwd scope.
- P3 uses archive option and mode tables. Creation inspects bounded input scopes,
  including symlinks. Stdout and extraction-to-command forms always deny.
  Listing is metadata-only, including protected-looking member names. `cpio` and
  `7z` model listing only; other forms deny. Literal safe compressor and
  checkpoint commands are analyzed as shell text.
- P4 and P5 invalidate later relative reads after ambiguous directory changes,
  special tilde directories, `CDPATH`, relevant `shopt` settings, dynamic
  `/proc` paths, and descriptor-directory aliases. Only specified harmless proc
  files are exempt.
- P6 models jq program-file selection, sed file and execution forms, and awk
  literal file or system operands. Sed script files are inspected only through a
  non-protected alias as bounded regular files of at most 8 KiB. Missing,
  non-regular, unreadable, oversized, computed, or otherwise indeterminate
  scripts deny. Sed script-file lookup uses native absolute paths on Windows,
  preserving the regular-file and symlink checks.
- P9 analyzes `-c` text for additional shell dialects and BusyBox or ToyBox shell
  applets. P10 validates complete sed scripts before classifying file and
  execution surfaces. P11 normalizes Bash option words before invalidating
  uncertain path semantics. P12 tracks indirect assignment to environment names
  consulted by later Git, shell, or ripgrep commands.
- P13 expands single-element glob braces under explicit nesting and alternative
  limits. P14 treats `apply_patch` heredocs as patches, rather than inert prose;
  protected or malformed patches deny and safe framed patches remain allowed.
- Inline Git configuration outside the inert `gitConfigInert` key allowlist
  always denies, including `-c`, `--config-env`, `GIT_CONFIG_COUNT`, and
  `GIT_CONFIG_PARAMETERS`. Inline editor and pager assignments accept only named
  editor or pager programs and literal arguments; inline SSH, askpass, proxy,
  and external-diff assignments deny. Inherited editor and pager settings are
  not analyzed.
- Shell hook code in `BASH_ENV` and `ENV` is treated as a file input. An
  inline `BASH_ENV` pointing to an unprotected script also denies because its
  sourced code is not certified. Inline `BASHOPTS` and `SHELLOPTS` with
  path-changing options invalidate child shell directories. Other hook variables remain bounded shell fragments. Interpreter
  environment access is denied for recognized environment reads in interpreter
  arguments. No interpreter runs during analysis.
- Sed uses a safe-subset allowlist: simple addresses, inert commands, bounded
  labels, final one-line text commands, and final-line literal read/write
  filenames. Execution commands and substitution execution/write flags always
  deny. A positional script before `-e` or `-f`, or an inline assignment to
  `POSIXLY_CORRECT`, denies. Multiple explicit scripts join with newlines.
- Shell invocations without `-c` or a script file deny, including here-doc and
  here-string input. Script-file operands and shell startup files must be
  non-protected regular files. The scanner peels `setsid` and `script -qc`,
  consumes shell option values, and rejects descriptor-based `source`. Inline `LESS*` settings
  other than inert `LESS`, and append assignments to sensitive names, deny.
- P17 checks known-command suffixes and shell-like arguments of unmodelled wrappers,
  recognizes versioned shell names and option clusters around `-c`, and analyzes
  fish initialization and coprocess bodies. Scriptless shells and sudo login or
  shell mode without a command deny. Git commit messages remain operands, not
  shell text, because Git is explicitly modelled.
- P15 rejects non-read-only commands that touch Git configuration paths,
  including directory options and in-place sed or perl abbreviations. Write
  targets with unknown variables or globs, and relative targets after ambiguous
  directory changes, deny. Literal assignments and HOME or XDG home paths are
  resolved before deciding. P1e denies `git submodule foreach` outright.
- Git helper names classify only when dispatched by bare name or from a
  `git-core` directory; protected operands deny even for those helpers. Git
  content commands deny for `.gitmodules` or submodule expansion. Command names
  classify case-insensitively. Writes to Git configuration, `.gitmodules`,
  worktree gitdirs, and global configuration deny, including redirected output,
  command destinations, and in-place edits.

The policy intentionally excludes simulated copy, link, and extraction state;
computed script literals and `eval`; object-content reads; and claims about host
installation or containment. Seven Bash-only external dependency fault cases are
covered by Go scanner fault-injection tests, not command-text variants.

## Current reviewed divergences

Every row in `testdata/inventory/go-hook-divergence.tsv` has a named entry below.
`deliberate-find-shim` is an injected dependency failure that Go does not execute,
not a permission bypass. `deliberate-tightening` is an owner-approved
indeterminate-input or audited input/output policy tightening.

| Cases                                                                                                                                                                              | Category              | Reason                                                                                                                                                                                       |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audit-arithmetic-unknown`                                                                                                                                                         | deliberate-tightening | `(( $(cat file) ))` contains a content-producing substitution and cannot be certified from arithmetic syntax.                                                                                |
| `audit-cases5-6`                                                                                                                                                                   | deliberate-tightening | Ripgrep names mode with `--pre cat` invokes a content-producing child and cannot use the names-only shortcut.                                                                                |
| `audit-cases6-7`                                                                                                                                                                   | deliberate-tightening | Clustered xargs `-0a` consumes a protected argument-list file before invoking its child.                                                                                                     |
| `audit-cases7-2`                                                                                                                                                                   | deliberate-tightening | A symlinked ancestor can reach an actual credential file before `..`; a final-symlink alias exception cannot certify that input.                                                             |
| `malformed_safe`, `oversized_safe`                                                                                                                                                 | deliberate-tightening | An absent framing pair, ambiguous header, or patch above the 40 KiB limit cannot certify safe target paths. Recognized protected headers deny even without framing.                          |
| `active_safe_command`                                                                                                                                                              | deliberate-tightening | `$c package.json` does not establish the executable or its input and output roles.                                                                                                           |
| `deep_safe`                                                                                                                                                                        | deliberate-tightening | Six nested `shell -c` layers exceed the Go analysis depth and deny.                                                                                                                          |
| `audit6_sed_comment`, `audit6_sed_text_line`, `audit6_sed_insert_line`, `audit6_sed_change_line`                                                                                   | deliberate-tightening | GNU sed reads these as a comment or as a/i/c text, so Bash allows them; Go denies any script whose later commands follow a comment or text command on one line.                              |
| `policy_v2_sed_script_clean`                                                                                                                                                       | deliberate-tightening | A `-f` script file holding `code` is a final one-line `c` command to GNU sed; Go certifies only scripts whose file text matches the safe subset exactly, so it denies.                       |
| `grep_find_exit`, `grep_find_exit_count`, `grep_timeout`, `grep_timeout_count`, `rg_find_exit`, `rg_timeout`                                                                       | deliberate-find-shim  | Bash denies when the injected `find` exits or times out. Go does not execute `find`; its walk errors, permissions, loops, budgets, and deadlines deny under dedicated fault-injection tests. |
| `unresolved_file_safe`, `unresolved_listing_safe`, `unresolved_literal_safe`, `unresolved_no_eval`, `unresolved_positional_safe`, `unresolved_redirect_safe`, `unresolved_wc_safe` | deliberate-tightening | Unknown parameter or substitution output cannot certify a non-protected content-producing input. The analyzer never executes a substitution to decide.                                       |

## Permanent synthetic evidence

Audit fixtures are synthetic and permanent in `testdata/hook/audit-cases.json`
and `internal/hook/policy/testdata/audit3.json`. They cover JSON adapters,
Git, archive, directory, find, xargs, parallel, jq, script, and patch decisions.
Fixtures contain fabricated files, symlinks, and generated indexes only. The
variant corpus preserves literal quoting, escaping, brace, and wrapper forms;
active expansions are not made inert, heredoc delimiters are not changed to
disable substitution, and invalid arithmetic rewrites are excluded.

## Measurement and regeneration

The default path uses bounded AST analysis with envelopes up to 1 MiB plus
framing overhead. Ordinary shell text has an 8 KiB limit; inert heredoc bodies
are excluded from that text limit but capped at 1 MiB overall. Word, brace, recursion, glob, and scan limits remain
bounded. The timing wrapper measures process launch plus decision, not an
installed host callback.

Regenerate with `python3 -I tests/gen-go-hook-divergence.py ABSOLUTE_BINARY`.
It runs the shell suites and both implementations on audit fixtures, refuses
unreviewed suite categories or missing tightening-table entries, and writes the
inventory mechanically. Run `bash tests/go-hook.sh guard ABSOLUTE_BINARY claude`
and the corresponding Codex command for exact inventory checks.

`tests/trial-go-hook.py` builds a disposable default binary and prints grouped
counts and p99. Regenerate denied-command metadata fixtures with
`python3 -I tests/gen-hook-variants.py`; it keeps Bash-only injected dependency
faults out of command-text variants and tests their Go scanner boundary through
fault injection.

## Audit 10 addenda: Go hook

The Go policy now treats attached Git tokens in non-reader operands and inline
interpreter text as protected, and normalizes command-text Git directories and
separate gitdirs for write checks. Shell `-c` option parsing stops at `-` or
`--`, nested wrappers inspect command slots and option values, and interactive
launchers without certifiable command text deny. `git submodule foreach` and
unchecked `git apply` deny; a cwd listing piped to `xargs echo` denies only
when its scope contains a protected file.

Audit 10b distinguishes strict execution slots from best-effort ordinary
arguments. Invalid shell syntax in titles, prose, JSON, SQL, and label filters
is not a reason to deny; command slots such as `npm exec -c`, `make --eval`,
`rsync -e`, and `gh alias set !...` must be certifiable. The `find` read-only
allowlist excludes output-to-file primaries, and names modified after a static
assignment no longer certify a write target. Synthetic fixtures under
`internal/hook/policy/` and `internal/hook/paths/` pair the denials with
ordinary Git metadata, safe file names, and public command forms. These are
policy checks, not evidence that the installed Bash hook was replaced.

## Audit 11a and 11b: Go hook

Git configuration writes now include the destination itself, both bare and
separate gitdirs, the effective working directory, attached destination options,
and roots created by `git init` or `git clone` within the command. `git apply`
passes only explicit check and summary modes with options from the reviewed
allowlist; templates and command-running Git config do not pass. Static write
variables are invalidated by subsequent identifier uses and indirect assignments.

Make recipe and stdin sources, npm and npx call options, alias shells, launcher
stdin, and abbreviated or clustered command slots are denied when execution
cannot be certified. Heredocs fed to interpreters are not inert data. A command
substitution containing only `cat` of an inert quoted heredoc is acceptable as
Git or GitHub message data, and ordinary writes of a large inert heredoc remain
acceptable. The Go envelope permits up to 1 MiB of such input; structural
limits and internal failures still deny. The command corpus retains the audited
allowances for public archive extraction, benign build tools, and literal copy
and loop forms. Neither this policy nor synthetic tests assert installed-hook
protection. The xargs reader with a named safe argument file now denies, because
contents of that file are not certified to contain only safe paths.

Additional unreviewed shell-suite divergence names from concurrent audit 11
fixtures cannot be added to the inventory from this scope. Existing reviewed
`sudo_shell_safe` and xargs argument-file permits now tighten under audit 11a;
`heredoc_commit` supplies a protected token in a Git stdin message file and
now denies under the revised P18 body rule; a `-m` cat heredoc substitution
remains a valid inert message and must be permitted.

Quoted shell wildcard metacharacters use private sentinel runes against bounded
native directory entries instead of platform-dependent backslash escaping.
This keeps quoted JSON, label filters, and prose literal on Windows while
retaining unquoted wildcard expansion and protected-name checks. Invalid
Windows fixture names are skipped; Windows runtime CI remains necessary.

## P18 revised: Go backstop

The revised backstop checks protected name tokens in interpreter heredoc and
here-string bodies, literal interpreter code-option values, strict command
slots, and arguments to commands without a classified model. Cat and tee
bodies remain inert only when their output does not target a protected file;
Cat heredocs inside Git commit message substitutions retain their previously
classified data role; Git stdin message-file bodies still undergo P18 scanning.
Existing Git configuration
write checks still apply independently.

Modelled operands retain their role classifications: secret transports,
env-file consumers, metadata tools, Git messages, GitHub titles and bodies,
reader patterns, and copy destinations are not raw-token denials. GitHub
message operands are excluded from generic file-input checks without
excluding other GitHub arguments. The synthetic P18 table covers both
protected inline and unmodelled input and the documented safe forms. Sudo
shell-option clusters continue to deny even with a command argument. The
installed Bash hook remains separate from this Go policy.

## P19 audit 12b Go fixes

The bounded matcher now supports negated and POSIX bracket classes, directory
wildcards, and globstar without treating quoted metacharacters as live on
Windows. Inert heredoc substitutions are restricted to Git or GitHub message
values, not file-option operands. Interpreter inline and stdin text receives
Git directory and path checks, including separate and bare Git directories.
Docker volume sources and GitHub API field-file inputs have file roles; Docker
Compose configuration and dotenv listing are printers. Git configuration
variables assigned in command text, make recipe prefixes and stdin makefiles,
and interactive shell launchers deny. Safe build globs, metadata Git forms,
Kubernetes secret creation, and public recursive grep trees remain available.
`internal/hook/policy/p19_test.go` records these synthetic decisions. These
checks do not execute any of their source commands.

## Audit 13: Go hook

The Go policy now rejects Compose configuration printers, dotenv/dotenvx
printers through named package runners, credential configuration getters, PHP
environment dumps, Docker environment inspection, and Kubernetes secret
output with a Kubernetes printer reason. It denies credential-reading file URLs
and zip inputs without evaluating source commands. Bounded glob expansion and
recursive search check files actually in scope, while Git patterns and code
identifiers are not mistaken for input paths. Ordinary unresolved non-reader
operands, inert empty write arguments, static cwd changes in `&&` chains, and
Docker PID pipelines remain available. Default rg excludes hidden files and
simple root-level exact gitignored names; explicit hidden/no-ignore searches
still deny. Windows native volume glob matching and quoted non-path operands
have focused synthetic tests. Inert large heredocs skip content scans when
their destination is already certified safe; non-inert bodies still receive
protected-name checks. None of this changes the installed Bash hook.

The `credential_glob` synthetic fixture now includes an actual matching home
file. A glob over a missing credential file must allow under audit 13 even if
the previous Bash guard denied its protected-looking spelling; this is a
reviewed flipped expectation, not a weakening of a real protected read.

The retained shell audit-13 fixture for `grep -rn --include='*.ts' foo .`
contains `.secrets/nested.ts` under its reused cwd. Go correctly denies that
read even though the new Bash suite expects allow. A clean fixture without a
matching protected file allows. The Bash fixture or expectation must be
corrected before this case can have honest parity.

## Audit 14 decisions

Git commit/tag stdin message files and GitHub stdin bodies from inert heredocs
are data, not readers. This flips the older `git stdin message body` and
`git commit -F -` prose expectations to allow. Clustered `-am` messages are
likewise data. Explicit search roots are scanned even when hidden; recursively
encountered hidden paths are skipped by default, and `.gitignore` exemptions
require a work tree. The older denied `rg TOKEN src sub` corpus fixture now
contains a visible `sub/app.env`, because its earlier hidden-only `sub/.env`
would be skipped by default. An unmatched private-name glob denies if a later
write could create a protected match, flipping the previous unmatched
`~/.ssh/id_*` allowance. Conditional directory changes retain the original
cwd as an alternative for later statements. Git cached removal, names-only
searches, grep quiet/count output, and env-file consumers do not print values.

Kubernetes `get secret -o custom-columns=...` selectors that target secret
data and curl uploads of unresolved shell variables remain outside the
syntactically certified subset. Neither guard provides containment against
arbitrary transformed output or unobserved process behavior. macOS and Windows
runtime CI remains necessary for native glob behavior.

## Audit 15 Go decisions

R1/R3 and L2 restore environment printers in launcher slots, peel leading
package-manager options and local `run` binaries, and remove npm's argument
separator before analyzing its selected command. Known venv/test/search data
operands retain their non-command roles. R2/R8 analyze substitutions in
unquoted message heredocs and keep interpreter heredocs scoped to their own
statement. R4 derives future protected-name witnesses from the selector's
literal structure, including arbitrary environment suffixes. R6 propagates
success/failure cwd sets once per statement, with 32-directory and 4096-step
caps; AST word budgets count each word once across alternative directories.

L1 models fd execution as a child consuming the selected names. L3/L4 cover
Kubernetes attached output values and comma-separated resource lists. L5/L6
respect the selected Git worktree roots and effective ripgrep configuration;
unsafe hidden/ignore settings cannot receive the default-skip exemption.
L7 treats funzip as an uncertified archive stdout printer. L8 adds `.envrc`
to path roles and the shipped ripgrep exclusions. O1/O2 keep grep output-only
clusters and explicit-file rg counts/names available. O3/O4 use bounded,
filter-aware walks for tool and shell searches. O5 certifies only pure filtered
find name streams into xargs; formatted, disjunctive or otherwise unmodeled
streams keep the conservative policy. O6 scopes no-index Git grep to its
explicit roots. The older denied-corpus Git root fixtures now contain a
visible `src/app.env`, preserving denied protected reads instead of retaining
an over-denial of a public-only source tree. The old `grep -rl` role expectation
flips to allow because names-only output is not a content read.

W1 classifies Win32 invalid-name, bad-pathname, non-directory and filesystem
invalid-argument errors as absent operand paths on Windows only. Permission
and I/O errors are unchanged. Injected error tests run on Linux; native invalid
filename cases still require Windows CI. R5/R7 and O7-O10 are Bash-specific;
Go retains focused tests for the shared directory and search behavior without
changing the installed Bash implementation from this workstream.

Audit 15 completion also retains parent-directory and symlink checks for
unmatched credential globs such as `~/.docker/c*.json`, in addition to deriving
arbitrary environment-name witnesses from the selector. Repeated fd extension
filters are alternatives: a later public extension cannot erase an earlier
protected extension. Ripgrep JSON output does not gain the explicit-file
count exemption when `--count` appears later in its arguments. Synthetic Go
cases cover these regressions and the two Windows non-path data operands.
The default-search proof accepts simple root-name Git ignore patterns, but a
negation invalidates that proof: dropping `!app.env` after `*.env` could
otherwise certify a file the search really reads. Both plain rg and untracked
Git grep have a permanent synthetic negation case.

## Audit 16 Go decisions and cross-platform regressions

The initial cwd now goes through the same canonicalization as every subsequent
flow state. Previously a future bare/clone Git root retained the original cwd
alias, while a later redirect used the physical cwd and missed that protected
root. A permanent Linux symlink-root reproducer covers all three creation forms.
Unmatched credential-glob witnesses are slash-qualified before the shell callback,
including on Windows, so an absent credential cannot enter the bare-name metadata
exception merely because filepath.Join returned backslashes.

A1 never uses negative glob alternatives as a narrowing proof, including mixed
brace alternatives. Pure exclusions retain the ordinary rg default-scope/config
proof; mixed positive/negative braces cannot reuse a protected config certificate.
A2 normalizes shell negated classes in both selector and filesystem matching.
A3 refuses the simple Git-ignore proof in the presence of .ignore/.rgignore files
at the root, scanned descendant directories or ancestors through the worktree.
Slash-free Git ignore patterns apply below the root as well; nested .gitignore
files refuse that proof rather than silently overriding their negations.

A4 models fd -g/--glob as boolean flags. A5 checks every positional/search-path
root under the effective base directory for both fd execution and fd-to-xargs
streams. Regex selectors without a glob/extension proof scan the whole selected
scope. A6 uses the pattern-derived protected-name test for find name/iname
filters and preserves a failed root proof instead of falling back to scanning
only xargs' cwd. Metadata-only children stay available. Public file symlinks are
checked through their resolved target; symlinked directories remain uncertified.
A7 peels npm x just like npm exec, including package/yes options and its separator.
A11 judges Windows alternate streams by their base file before missing-name
handling, including unnamed $DATA streams; non-Windows colon names are unchanged.

B2 peels Python -m modules while retaining venv/test environment-data roles.
B3 accepts attached rg -tTYPE/-TTYPE with the same policy as separate type values.
B4 adds the Markdown type family. B5 accepts rg quiet output on explicit files
without exempting protected pattern-file inputs. B6 checks a literal DIR/** glob
only within DIR, with the ordinary bounded protected-tree scan. B7 carries
bounded cwd alternatives through brace blocks and if clauses, joined with the
outer cwd instead of replacing alternatives with an unknown directory.

These changes have synthetic Go deny and must-allow regressions. Native Windows
stream behavior and macOS/Windows runner evidence remain CI gates; no installed
hook or host-containment claim follows from Linux tests or cross-platform vet.

## Audit 17 Go decisions and parity evidence

D1 checks the roots supplying listing streams to xargs: every find path,
fd/fdfind root and base directory, ls operand, Git -C directory and rg --files
operand. Static shell expansion is shared with command dispatch. Missing,
dynamic, unmodeled or protected scopes cannot fall back to a clean consumer
cwd. Git repository/index overrides, scope-widening parent/top pathspecs and
transformed or compound listing streams remain uncertified. Modeled wrappers check producer roots before retaining the
existing consumer-scope check. Filtered find/fd proofs still walk matching
physical names, including protected names such as .env.ts; directory symlinks
remain uncertified unless
the explicitly resolved root can be scanned safely. Metadata-only children
remain available, as do public TypeScript find-to-wc and fd-to-gofmt commands.

D2 leaves npx/npm exec call options and yarn exec shell strings out of
safePackageChild. The strict shell-slot analyzer checks separate and attached
call values, including pnpm exec calls and effective yarn/pnpm directory flags.
D4 analyzes background commands without exporting their cwd, preserves the
existing subshell/loop/branch denial coverage, and retains the parent cwd after
a statically zero-iteration while-false loop. The historical audit3 `cd-41`
expectation is a classified class (iii) over-denial correction: `cd .secrets &
paste store` reads the ordinary outer `store`, not `.secrets/store`. Its command
is retained with an allow expectation; new background-cd cases deny actual
protected reads in the outer cwd.

D7 shares fd roles with fdfind before raw operand checks and in pipe proofs.
D8 treats keyring get, including Python module dispatch, as a credential printer;
the existing direct-stash transport exception remains unchanged. D9 checks
.ignore/.rgignore ancestors through the filesystem root, not merely through
.git, and refuses certification if the 128-directory bound is exhausted.
D3 dotted HOME store paths, D5 mixed brace selectors, D6 npm aliases/options and
dotenv environment printers, and D10 option-prefixed package printers already
deny in Go and now have permanent tests. D10 also consumes package-option values
when peeling safe runners, preserving ordinary jest/vitest data operands.

The audit 17 Go table runs shell text and argv-host routes against a fake HOME,
with a shell-realistic missing-bare-operand callback. Dedicated physical-root
and ancestor-ignore tests use disposable metadata only. No probed command is
executed and these checks do not establish installed-host containment or native
macOS/Windows runtime behavior.

## Audit 18 Go package execution and keyring options

pnpm `-c` and `--shell-mode` around `exec` analyze the joined child words as
bounded strict shell source, rather than an executable name. Yarn exec uses
that same joined-source check. npm exec/x and pnpm exec retain workspace
selectors before and after the action, including npm options after child
positionals until `--`. pnpm implicit local-binary execution shares shell-mode
handling, and its workspace-root option resolves ancestor project metadata.
Literal existing workspace directories
are analyzed alongside the invocation directory. Unresolved package names and
filter expressions inspect every possible project directory under the existing
32-cwd, 4096-entry and analysis-deadline bounds. Workspace-root discovery checks
only ancestor marker existence, never manifest contents. Git internals and
installed node_modules trees are not implicit workspace candidates; explicit
path selectors still check them. Unreadable scopes, directory symlinks and
exhausted bounds deny rather than certify an incomplete scan. npm prefix checks
both the selected directory and the invocation directory. Child cwd alternatives
do not flow into subsequent sibling statements. Function definitions check their
bodies without exporting their cwd or nested definitions. Known calls replay
the body with bounded directory alternatives and recursion.

npm script arguments retain their data role after the script name, so a literal
`env` option value is not an environment-printing command. The env script itself
still denies. Keyring consumes backend/path options with their documented arity,
including attached and equals forms, before classifying get. Mode/output
selectors also consume their values without obscuring the action. Python module
execution shares those roles; help and direct-to-stash transport remain allowed.

The retained Bash denial corpus and exact guard/Codex inventories include audit
18, with Linux and Darwin guard inventories updated together. No denial case or
expectation was removed, and no new acceptable divergence was added. The new Go
tests use fabricated paths and values and never execute the probed commands.
