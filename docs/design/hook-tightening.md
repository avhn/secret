# Hook tightening decisions for M2

The Bash guard remains the installed hook. These outcomes are measured with synthetic tool envelopes, not live credentials. Go hook activation requires a verified host failure-blocking contract and the later M2 shell parser.

| Case | Bash decision | Go decision | Reason |
| --- | --- | --- | --- |
| Nonempty malformed JSON (`malformed_json`, `malformed_sensitive`) | No decision | Deny with fixed complexity reason | An undecodable supported call cannot establish safe file or shell roles. |
| Duplicate security-relevant keys | Last value wins | Deny with fixed complexity reason | Prevent ambiguous path and command interpretation. |
| Trailing JSON or input above 32 KiB | May parse or continue | Deny with fixed complexity reason | Enforce one bounded host envelope. |
| Incorrect path or command field types | May coerce or continue | Deny with fixed complexity reason | Cannot certify a file role from an incorrect type. |

The Go implementation currently **defers Bash tool decisions**. The isolated `internal/hook/policy` and `internal/hook/roles` prototypes are not protection. `python3 -I tests/trial-go-hook.py guard|codex ABSOLUTE_BINARY claude|codex` classifies synthetic case results by name prefix without rewriting the reviewed divergence inventory. Trial wiring is withdrawn after each measurement; none of these differences is classified as intentional tightening.

| Trial group completed | Claude false allows | Claude false denies | Timed decisions, p99 |
| --- | ---: | ---: | --- |
| Initial AST and role tables | 277 | 100 | 1379, 3.192 ms |
| Search scope and xargs listing | 142 | 138 | 1379, 3.182 ms |
| Env, docker, wrappers, grep | 93 | 141 | 1379, 3.171 ms |
| Timeout argument and nested child | 68 | 141 | 1379, 3.081 ms |

Trial Codex: 5 false allows, 1 false deny; 31 timed decisions, p99 2.946 ms. The timing wrapper measures each Go process launch and decision, not an installed host callback. Earlier direct guard-suite trial wiring without the wrapper yielded 275 false allows and 98 false denies out of 1389 assertions. Remaining Claude false-allow groups include unresolved substitutions (7), name-list file options (6), ANSI quoting (5), braces (5), operands (5), malformed code (5), jq (4) and search edge cases. The measured false denies are not approved tightening; search certification, variable provenance, direct argv, wrappers and bounded expansion still need parity. Do not connect the prototype to either host until every false allow is fixed and the exact divergence table is reviewed. The checked inventory retains `pending-M2-ast` and `pending-M2-search`; the host cannot be claimed fail-closed merely because the hook returns a valid result on ordinary calls.
