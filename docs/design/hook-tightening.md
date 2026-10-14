# Hook tightening decisions for M2

The Bash guard remains the installed hook. These outcomes are measured with synthetic tool envelopes, not live credentials. Go hook activation requires a verified host failure-blocking contract and the later M2 shell parser.

| Case | Bash decision | Go decision | Reason |
| --- | --- | --- | --- |
| Nonempty malformed JSON (`malformed_json`, `malformed_sensitive`) | No decision | Deny with fixed complexity reason | An undecodable supported call cannot establish safe file or shell roles. |
| Duplicate security-relevant keys | Last value wins | Deny with fixed complexity reason | Prevent ambiguous path and command interpretation. |
| Trailing JSON or input above 32 KiB in the default deferred build | May parse or continue | Deny with fixed complexity reason | Enforce one bounded host envelope. |
| Incorrect path or command field types | May coerce or continue | Deny with fixed complexity reason | Cannot certify a file role from an incorrect type. |
| Unresolved protected-file operands (`unresolved_file_safe`, `unresolved_positional_safe`, `unresolved_listing_safe`, `unresolved_wc_safe`, `unresolved_redirect_safe`, `unresolved_xargs_safe`, `unresolved_literal_safe`, `unresolved_no_eval`) | No decision if Bash cannot prove a protected name | Deny as indeterminate content-producing input | Unknown expansion and substitution output cannot certify a non-protected file operand; do not evaluate shell syntax to decide. |
| Go does not execute find; walk failures deny and are covered by Go tests (`grep_find_exit`, `grep_find_exit_count`, `grep_timeout`, `grep_timeout_count`) | Deny when the external find shim fails or times out | No decision for the empty synthetic tree; deny on Go metadata walk error, permission error, loop, budget overflow or deadline | The Go scanner never executes the alternate find in PATH; synthetic fault injection verifies its own failure handling. |

The default Go build **defers Bash tool decisions**. The isolated `internal/hook/policy` and `internal/hook/roles` prototypes are not installed protection. `python3 -I tests/trial-go-hook.py guard|codex ABSOLUTE_BINARY claude|codex` builds an isolated `hooktrial` binary and classifies synthetic case results by name prefix without rewriting the reviewed divergence inventory. The external-find shim differences are classified as deliberate search differences; only the unresolved-input row is currently reviewed as intentional command tightening. The other false denies are not yet approved tightening.

| Trial group completed | Claude false allows | Claude false denies | Timed decisions, p99 |
| --- | ---: | ---: | --- |
| Initial AST and role tables | 277 | 100 | 1379, 3.192 ms |
| Search scope and xargs listing | 142 | 138 | 1379, 3.182 ms |
| Env, docker, wrappers, grep | 93 | 141 | 1379, 3.171 ms |
| Timeout argument and nested child | 68 | 141 | 1379, 3.081 ms |
| Fail-closed unknown reads, ANSI words, name-list options | 30 | 154 | 1379, 3.141 ms |
| Malformed code, wrappers, nested `find`, argv handling | 4 | 151 | 1379, 3.105 ms |
| Trial-only untrusted-PATH Grep parity check | 0 | 151 | 1379, 3.169 ms |
| Tagged AST, walk fault injection and wrapper review | 4 (external-find shims) | 150 | 1379, 3.093 ms |
| Larger bounded trial envelope, role and wrapper parity, search in progress | 7 (search shims) | 24 | 1379, 3.873 ms |

The zero-false-allow trial temporarily changed the Go Grep decision for an alternate `find` in PATH; that change and the Bash wiring were withdrawn together. **The retained hook still defers Bash and has four Grep false allows under the trial corpus's alternate failing/timed-out `find` shims.** Go's metadata scanner does not execute `find`, so this requires a reviewed search policy decision, not a fixture-specific PATH rule. Codex's trial with direct argv handling reached zero false allows and one false deny (workdir); that integration was also withdrawn. The timing wrapper measures Go process launch and decision, not an installed host callback. Earlier direct guard-suite trial wiring without the wrapper yielded 275 false allows and 98 false denies out of 1389 assertions. That 150/one baseline preceded the larger tagged budgets and role fixes. The current tagged trial has seven search-only false allows (alternate failing/timed-out find shims), 24 Claude false denies and one Codex false deny. The 46 over-budget safe cases and the sudo, stash, Git and operand groups now match; remaining differences beyond the unresolved-input row have not been approved as tightening. Scope, variable provenance, quoting, printer-to-stash options, and wrapper parity still need work. Do not connect the prototype to either host until every false allow is fixed in the retained code, false denies are classified, and the exact divergence table is reviewed. The checked inventory retains `pending-M2-ast` and `pending-M2-search`; the host cannot be claimed fail-closed merely because the hook returns a valid result on ordinary calls.
