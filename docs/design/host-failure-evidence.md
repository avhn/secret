# M4 real-host failure evidence

## Gate status

**Inactive pending sponsorship. Pending: no hosted run yet.** The owner decision
is to build the harness now and defer authenticated execution until sponsors fund
model usage. This document is an evidence checklist, not proof of installed
protection. Host evidence and Claude cutover remain pending for M4.1, not an
active required check for the M4 release.
No real model sessions, host installations, credential stores, Keychains or
keyrings were used to build the harness.

The workflow is `.github/workflows/host-hooks.yml`, with manual dispatch only.
It defines `claude-host-linux`, `claude-host-macos`, `codex-host-linux` and
`codex-host-macos`. Every job is skipped by default and runs only when the
repository variable `SECRET_HOST_TESTS` equals `enabled`. Never configure these
jobs as required checks. There are no push, pull_request or schedule triggers.
Each job uses the `host-hook-tests` environment. Before enabling runs or adding
credentials, the owner must configure required reviewers and trusted allowed
branches for that environment; no credentials may reach fork code. YAML cannot
create or prove those repository settings.
When enabled, a missing applicable `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` makes the job fail
with `credential not configured; gate incomplete`. No credential value belongs
in a prompt, settings file, command argument, artifact, report or chat.

## Pins and execution limits

- Claude Code: `@anthropic-ai/claude-code@2.1.295`.
- Codex: `@openai/codex@0.163.0`. The exact version was verified against
  <https://registry.npmjs.org/@openai%2fcodex/0.163.0> on 2026-10-20. This verifies
  package existence, not hook compatibility or host behavior.
- Models: `claude-haiku-4-5-20251001` and `gpt-5-mini`. Model access, pricing and
  availability must be checked by the owner before dispatch. No model calls
  were made during implementation.
- Go in the workflow: 1.26.10 with `GOTOOLCHAIN=local`. Node: major 22.
- Every session has a 90-second process-tree watchdog and bounded captured
  streams. Claude gets two turns and a $0.10 session budget. There are at most
  60 Claude sessions per job, with an additional $8 aggregate stop condition.
- Codex has at most 30 sessions, the same watchdog, and a 120,000-token
  between-session stop condition. These are not a hard Codex dollar limit or
  an in-flight token cap. Codex exec has no verified equivalent of Claude's
  `--max-budget-usd` in this pin. The owner must provision a separately bounded
  CI API project before an owner-operated Codex run; do not infer a hard spend
  cap from a reporting-only project budget. Without acceptable budget and trust
  controls, defer that run and leave this gate incomplete.
- Package prefixes, npm cache, Go caches, HOME and XDG_CACHE_HOME are disposable
  directories below a fresh runner scratch directory. Sessions get a minimal
  environment and a separate synthetic work directory. Nothing is installed
  into the runner's original HOME or a developer's HOME.

## Harness contract and evidence

`python3 -I tests/test-host-hooks.py` runs offline classification tests only.
To include the compiled fault fixture, explicitly build
`tests/host-hook-fixture.go` with `-tags hosthookfixture` and pass its absolute
path with `--fixture`. The Go build constraint excludes it from normal `./...`
builds. Fixture faults include a real Go runtime deadlock fatal exit and SIGKILL,
not only scripts that return chosen exit codes.

`--hosted` additionally requires `GITHUB_ACTIONS=true` and
`RUNNER_ENVIRONMENT=github-hosted`, pinned executables, all explicit paths and a
fresh empty private root. These checks prevent accidental local invocation;
they are not a sandbox or authentication boundary.

Claude testing requires the staged branch configuration to already reference
`hooks/guard-go`, timeout 5 and `onFailure: "block"` on both synchronous groups.
It does not edit the checkout's plugin manifest, hooks or policy. The harness
copies the two group definitions into a disposable test plugin and changes only
fault commands, adding a SessionStart dispatch probe. The host's `system/init`
message must identify the loaded test plugin. A missing plugin cannot pass.

For post-exec faults and controls, the disposable plugin copies the real
`guard-go` and installer. It installs the test-only native fault binary through
`--from-dir --offline`, a candidate checksum manifest and the required private
`.secret-release-test-fixture` marker. Only the native asset is supplied; the
other manifest lines are unused placeholders. This is intentionally not release
provenance, cross-architecture, published-asset or production installation
verification. No fixture marker or fault executable is shipped. Startup fault
cases replace or remove only this disposable launcher's path. Missing-binary
and exec-format cases use a test launcher that reaches a failing `exec`, distinct
from the real launcher's earlier bootstrap denial.

Each operation first requires a neutral healthy control. Every fault uses the
identical prompt, operation, input, cwd and witness path as that control, with a
fresh host session and reset fixture. Claude preapproves only the exact synthetic
Bash command or absolute witness-file rule, exposes only the operation under
test, and uses dontAsk for anything not preapproved. A permission-rule mismatch
makes the healthy control incomplete, never grounds for broader permissions.
Claude exercises Bash, Read, Edit and Write, covering both synchronous groups.
Codex exercises Bash and apply_patch using the
retained Bash hook definitions; no Codex Go cutover is proposed.

Classification is deliberately conservative:

- PASS for a fault requires a completed authenticated session, plugin/probe
  evidence, the exact structured tool attempt, a linked host-authored hook
  failure result, no successful tool result and no filesystem execution witness.
- Bash and writes require filesystem witnesses for healthy controls. Read
  execution is established by structured tool results, not a model's narrative.
  Even an error result containing the synthetic read sentinel fails a fault.
- A missing attempt, missing control, policy refusal, API error, unknown stream
  shape, timeout, nonzero host exit or missing hook report is INCOMPLETE.
- Any successful result or filesystem execution witness after a fault is FAIL,
  including when authentication or other evidence is also missing. Malformed
  structured output cannot erase an independent filesystem witness. Usage
  accounting runs separately and never downgrades FAIL. Missing or invalid usage
  stops further sessions, records `usage_complete: false`, and makes any otherwise
  passing case INCOMPLETE; reported totals then cover known usage only.
- Empty successful hook output is a separate control, not a failure claimed to
  be blocked by `onFailure`. The safe neutral control contains only the event
  name and never an explicit allow that could override another permission rule.
- Raw stdout/stderr, prompts and session transcripts are never uploaded. The
  only artifact is an allowlisted JSON summary: host/version, OS, architecture,
  runner image/version, commit, run ID, case/status/reason, shell identity and
  names-only cwd/workdir envelope facts. Cleanup removes temporary sessions.

The shell-form hook command records its actual shell via `/proc/$$/exe` on Linux
or `ps -p $$ -o comm=` on macOS without consuming hook stdin. The fault executable
records whether the envelope cwd is absolute and matches its actual cwd, and
whether workdir was present. These facts still require hosted review; do not
infer Codex's omitted-workdir behavior from a synthetic envelope.

## Required case matrix

Every cell below applies to all operations for that host: Claude Bash, Read,
Edit and Write; Codex Bash and apply_patch. A host/operation not attempted is
incomplete, not covered by a neighboring result. Both macOS and Linux are
required independently. Rows name the exact harness case where applicable.

| Case | Claude Linux | Claude macOS | Codex Linux | Codex macOS |
| --- | --- | --- | --- | --- |
| missing-launcher | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| failed-launcher | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| nonexecutable-launcher | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| missing-binary (exec reached) | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| exec-format | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| exit1 | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| fatal (post-exec Go runtime) | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| signal (post-exec SIGKILL) | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| malformed JSON | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| schema-invalid JSON | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| timeout (8 seconds, host limit 5) | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| valid deny | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| neutral healthy control | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| successful empty output control | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| retained safe Go/Bash policy control | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| plugin loaded and tool attempted | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| actual shell and cwd/workdir contract | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |
| authentication/model outage blocks gate | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet | pending: no hosted run yet |

## Codex trust and owner-operated evidence

| Required Codex evidence | Linux | macOS |
| --- | --- | --- |
| Installed plugin dispatch | pending: no hosted run yet | pending: no hosted run yet |
| Initial hook trust review | pending: no hosted run yet | pending: no hosted run yet |
| Re-trust after hook modification | pending: no hosted run yet | pending: no hosted run yet |
| Omitted per-command workdir | pending: no hosted run yet | pending: no hosted run yet |

The automated Codex probe loads a disposable user hooks.json with the unchanged
Bash matcher/timeout policy. It deliberately does not use a hook-trust bypass.
User-hook dispatch alone is not installed-plugin evidence. Even if every
synthetic fault session succeeds, these four extra contract rows remain
INCOMPLETE and the Codex job exits nonzero. No automated plugin trust/re-trust
interface was verified for this pin. Do not turn a refused trust prompt or
missing structured blocked-tool event into a pass.

If automation cannot complete trust review, the owner must run an interactive
session on a fresh disposable GitHub-hosted runner, never a developer machine:

1. Record the run URL, commit, runner image/architecture and exact host versions.
   Use an isolated HOME, synthetic workspace and a bounded CI API project.
2. Install the retained branch Codex plugin in that disposable environment using
   the pinned host's supported plugin manager. Review its requested hooks with
   `/hooks`; record sanitized dispatch evidence before fault testing.
3. Run an identical healthy request and each fault from the matrix for Bash and
   apply_patch, recording tool attempts, linked failure reports and filesystem
   witnesses. A missing call or model refusal is incomplete.
4. Change a disposable hook command and verify that the host requires re-trust.
   Review again, then rerun the identical request and record envelope facts,
   including absence or presence of per-command workdir.
5. Publish only a sanitized names-only case summary with run links, never raw
   sessions or credentials. Keep incomplete and execution-failure rows explicit.

Actual supported plugin-manager commands and trust prompts must be taken from
the pinned executable's help on that runner, not guessed here. Until reviewed
owner-operated evidence covers every row, Codex and the overall gate remain
incomplete. Codex stays on Bash regardless of results.

## Promotion boundary

Offline fixtures test classifier logic and test-only process behavior. They do
not establish host failure blocking. Disposable test-plugin runs also do not
replace the final installed branch plugin and public released-asset runs. Those
runs, native OS evidence, protected-environment settings, authenticated model
availability and actual release provenance can only be proved by the later
hosted gate. Later host version upgrades must rerun it.

Host interface references:
<https://code.claude.com/docs/en/hooks>,
<https://code.claude.com/docs/en/headless>,
<https://learn.chatgpt.com/docs/hooks>,
<https://learn.chatgpt.com/docs/non-interactive-mode>.
