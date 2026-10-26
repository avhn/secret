package hook

import "github.com/avhn/secret/internal/hook/input"

const powershellReason = "PowerShell host contract is not enabled"

// powershellClassifier is a test-only adapter seam, never populated in
// production. Host and shell evidence must precede any production enablement;
// neither environment variables nor envelope fields can select a classifier.
// Tests replacing this value must not run in parallel.
var powershellClassifier func(e input.Envelope, cwd, home string) string
