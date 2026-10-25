package cli

const usage = `Usage: secret list [--backend age] [--format=json] | show [--format=json] [--env ENV] [--label N=V ...] [FILE ...] | help
       secret run|exec -f FILE [-f FILE ...] [--env ENV] [--label N=V] [--key KEY] [--optional-key KEY] -- CMD [ARG ...]
       secret stash [--env ENV] [--label N=V ...] FILE KEY
       secret get [--env ENV] [--label N=V ...] FILE KEY
       secret clip [--env ENV] [--label N=V ...] FILE KEY [SECONDS]
       secret import --from dotenv:ABS_PATH|op:ID|bw:ID --into REF [--map FIELD=KEY ...] [--label N=V ...] [--dry-run]
       secret export --from REF --to age:NAME|keychain:NAME|libsecret:NAME|pass:NAME|wincred:NAME --on-conflict=fail [--env ENV] [--label N=V ...] [--key KEY ...] [--dry-run]
       secret age-init age:NAME --age-recipients FILE --age-identity FILE
       secret age-rekey age:NAME --age-identity FILE --age-recipients FILE --age-new-identity FILE
       secret rotate|delete REF KEY [--env ENV] [--label N=V ...]
       secret rename REF OLD NEW [--env ENV] [--label N=V ...]
       secret diff [--format=json] [--env LEFT --env RIGHT] [--left-label N=V ...] [--right-label N=V ...] REF [REF]
       secret doctor [--format=json] [--path ABS_PATH ...] [--ripgrep-config ABS_PATH] [REF ...]
       secret completion [--command CMD] [--flag FLAG] [--prefix TEXT] [-f REF ...] [--env ENV] [--label N=V ...]
       secret audit --directory ABS_PATH [--format=json] [--action ACTION] [--target REF] [--key KEY] [--outcome OUTCOME] [--limit N] [--since RFC3339] [--until RFC3339]
       secret mcp --store REF [--store REF ...]
Bare NAME resolves to ~/.secrets/NAME.secret, then ~/.secrets/.NAME.secret.
keychain:NAME uses macOS Keychain; libsecret:NAME uses Linux Secret Service.
pass:NAME uses optional pass 1.7.4 on Linux/macOS; NAME.pass-keys isolates its inventory.
age:NAME explicitly selects SECRETS_DIR/NAME.secret.age; defaults never discover it.
Use --age-identity ABS_FILE on stash/get/clip/run/exec/import/export/lifecycle.
Key files must be private under HOME/.secrets/.age-keys; no identity discovery exists.
Age metadata is unauthenticated and names-only; value use authenticates the whole store.
age-init is create-only; rekey proves the new identity before publishing ciphertext.
Age sources use export, never import; plaintext export targets remain prohibited.
Age plus --template-file is rejected. Windows age filesystem support awaits M5a.
SECRET_KEYCHAIN selects an explicit keychain path (without spaces or quoting).
file:PATH forces a literal file path. Keystore names must be
simple names, not paths. Legacy provider manifests live at ~/.secrets/NAME.keys.
wincred:NAME uses native Windows Credential Manager (2560-byte raw blob limit),
with names-only NAME.wincred-keys manifests outside Bash discovery. Metadata can
be read on other platforms; credential access is unsupported there. Windows
run/exec and operator workflows remain unavailable pending their native gates.
list prints store references; show prints file lengths or keystore <stored>.
run and exec require explicit files and --. Later files win. Selectors export
only selected keys; required keys must be nonempty, missing optional keys vanish.
--env ENV means --label env=ENV; repeated labels are ANDed. Without labels,
only unlabeled records qualify. Unmatched store keys are removed from the child.
Exact [N=V,...] store headers scope following keys; [] resets the scope.
show without selectors lists every labeled record; selected show marks unmatched keys.
stash updates the exact label set; get and clip select like run.
run redacts ALL nonempty loaded values, longest first, on stdout and stderr.
Redaction cannot catch transformed values. Do not print or inspect credentials.
exec is unfiltered: only human interactive or configured MCP launchers use it.
get prints a value only to a human terminal, never through Claude's ! command.
stash reads hidden terminal input or stdin; writes reject empty, NUL, CR, embedded
newline, boundary whitespace, and surrounding quote pairs. One final LF is allowed.
clip copies and conditionally clears the clipboard (default 45 seconds).
Values are not in this tool's argv or filter argv; a child can expose its own
values in argv. Prefer stdin/header files for consumers that support them.
Exit: 0 success/help/empty inventory, 1 usage/store/filter error; run preserves
a failing child status unless a filter fails (filter failure takes precedence).
run stops its supervised Unix process group, including descendants, on completion.
Filter draining stops after 2 s when descendants hold output open; remaining output
is dropped, never printed unfiltered. Unrelated or escaped processes are not contained.
run --template-file TEMPLATE renders exact {{KEY}} placeholders from selected keys
in HOME/.secrets/.rendered/<random>/payload (0700 directories, 0600 file), independent
of SECRETS_DIR. The child receives SECRET_TEMPLATE_FILE, not an argv value. No exec
or output-directory option is supported. Limits: 1 MiB template, 16 MiB rendered.
Normal/error/catchable-signal cleanup is best effort; SIGKILL, crashes or power loss
can leave protected plaintext. Cleanup is not guaranteed erasure.
Operator commands require stdin AND stdout terminals before access, then exact
hidden controlling-terminal confirmation of every target/key/label identity. No yes
flag, piped confirmation or operator JSON exists. Invoke directly in your terminal,
never through agent tools. REF must be file:ABS_PATH, age:NAME or keychain:NAME/libsecret:NAME/pass:NAME/wincred:NAME.
Rotation reads a hidden value, capped at 64 KiB; oversize input rejects, not truncates.
Import/export are insert-only. op/bw require explicit mappings; export without
selectors selects unlabeled keys only. Dry-run is names/conflicts only and still
requires real terminals. Limits: 16 MiB input, 1 MiB importer output, 1024 records;
provider limits can be tighter. Pending recovery requires manual verification;
doctor reports tracked candidates, not proven or all historical orphans.
Audit is off unless an operator receives --audit-dir ABS_PATH; queries use
--directory ABS_PATH. Logs rotate at 1 MiB across four 0600 files. Metadata includes
names, labels, paths and provider account IDs, never values, hashes or lengths.
MCP is off without explicit --store allowlisting; stdio exposes list/show/diff/health
only. Completion reads only explicit -f scopes and emits literal names, not shell code.
Doctor reports unverified host activation and unavailable M4 release trust honestly.
The Bash CLI, installed hooks and M2 policy remain unchanged; hooks conservatively
deny new secret subcommands, including names-only ones. No installed-host protection
or Windows operator support is claimed. exec preserves child status and signals.
`
