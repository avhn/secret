# Hook tightening decisions for M2

The Bash guard remains the installed hook. These outcomes are measured with synthetic tool envelopes, not live credentials. Go hook activation requires a verified host failure-blocking contract and the later M2 shell parser.

| Case | Bash decision | Go decision | Reason |
| --- | --- | --- | --- |
| Nonempty malformed JSON (`malformed_json`, `malformed_sensitive`) | No decision | Deny with fixed complexity reason | An undecodable supported call cannot establish safe file or shell roles. |
| Duplicate security-relevant keys | Last value wins | Deny with fixed complexity reason | Prevent ambiguous path and command interpretation. |
| Trailing JSON or input above 32 KiB | May parse or continue | Deny with fixed complexity reason | Enforce one bounded host envelope. |
| Incorrect path or command field types | May coerce or continue | Deny with fixed complexity reason | Cannot certify a file role from an incorrect type. |

The Go implementation currently **defers Bash tool decisions** because AST analysis is a later M2 item. This is not a protective decision and the Go hook must not replace the active Bash hook in installed manifests. The checked divergence inventory categorizes this temporary gap as `pending-M2-ast` and search differences as `pending-M2-search`. The host cannot be claimed fail-closed merely because the hook returns a valid result on ordinary calls.
