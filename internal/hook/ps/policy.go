package ps

import (
	"context"
	"strings"
	"time"
)

// FileKind is metadata-only certification. The adapter must reject links,
// reparses, uncertain identity and metadata errors rather than following them
// for a Copy-Item source or a names-only enumeration.
type FileKind string

const (
	RegularFile  FileKind = "regular-file"
	Directory    FileKind = "directory"
	NonDirectory FileKind = "non-directory" // Existing regular file or absent destination.
)

// Context is supplied by a trusted native adapter, never by PowerShell source.
// Callbacks receive absolute, unexpanded Windows operands, preserving dot
// components for lexical and native identity witnesses. ProtectedWrite must
// include configuration-write protection; both callbacks are used for writes.
// CertifyPath is additionally required by Copy-Item and Get-ChildItem. A missing
// callback never supplies a proof. No filesystem or environment is read here.
type Context struct {
	Cwd            string
	Home           string
	Analysis       context.Context
	Deadline       time.Time
	ProtectedRead  func(string) bool
	ProtectedWrite func(string) bool
	CertifyPath    func(string, FileKind) bool
	// Now permits deterministic budget testing; production adapters leave it nil.
	Now func() time.Time
}

type Decision struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
}

// Classify recovers analyzer and callback panics into a fixed value-free deny.
// It never certifies incomplete work, including cancellation after the walk.
func Classify(src []byte, ctx Context) (decision Decision) {
	decision = Decision{Reason: ReasonPanic}
	defer func() {
		if v := recover(); v != nil {
			decision = Decision{Reason: ReasonPanic}
			if reason, ok := v.(rejection); ok {
				decision.Reason = string(reason)
			}
		}
	}()
	b := &budget{ctx: ctx.Analysis, deadline: ctx.Deadline, now: ctx.Now}
	if b.now == nil {
		b.now = time.Now
	}
	b.check()
	if !absolute(ctx.Cwd) || !absolute(ctx.Home) || !validNative(ctx.Cwd) || !validNative(ctx.Home) || ctx.ProtectedRead == nil || ctx.ProtectedWrite == nil {
		deny(ReasonContext)
	}
	tree := parse(src, b)
	a := analyzer{ctx: ctx, b: b}
	a.script(tree.Script)
	b.check()
	return Decision{Allow: true}
}

type analyzer struct {
	ctx Context
	b   *budget
}

func certified(s Source) bool { return s == Literal || s == PublicContent }
func combine(a, b Source) Source {
	if a == Unknown || b == Unknown {
		return Unknown
	}
	if a == PublicContent || b == PublicContent {
		return PublicContent
	}
	if a == Literal || b == Literal {
		return Literal
	}
	return None
}
func (a *analyzer) script(script Script) Source {
	out := None
	for _, pipeline := range script.Pipelines {
		a.b.check()
		input := None
		for i, command := range pipeline.Commands {
			a.b.check()
			input = a.command(command, input, i > 0, i+1 < len(pipeline.Commands))
		}
		out = combine(out, input)
	}
	a.b.check()
	return out
}
func (a *analyzer) command(c Command, input Source, piped, downstream bool) Source {
	a.b.check()
	bound := bind(c, a.b)
	switch bound.role.input {
	case "none":
		if piped {
			deny(ReasonPipeline)
		}
	case "optional":
		if input != None && !certified(input) {
			deny(ReasonPipeline)
		}
	case "required":
		if !certified(input) {
			deny(ReasonPipeline)
		}
	case "value":
		if bound.get("Value") == nil {
			if !certified(input) {
				deny(ReasonPipeline)
			}
		} else if piped {
			deny(ReasonPipeline)
		}
	default:
		deny(ReasonPipeline)
	}
	for _, arg := range bound.arguments {
		a.b.check()
		switch arg.parameter.role {
		case "read", "regular-read", "directory", "write", "non-directory-write":
			if arg.argument.Word == nil {
				deny(ReasonBinding)
			}
			path := a.path(arg.argument.Word.Value, strings.Contains(arg.parameter.role, "write"))
			kind := FileKind("")
			switch arg.parameter.role {
			case "regular-read":
				kind = RegularFile
			case "directory":
				kind = Directory
			case "non-directory-write":
				kind = NonDirectory
			}
			if kind != "" {
				a.b.check()
				if a.ctx.CertifyPath == nil || !a.ctx.CertifyPath(path, kind) {
					deny(ReasonMetadata)
				}
				a.b.check()
			}
		}
	}
	output := bound.role.output
	if bound.role.name == "ForEach-Object" {
		block := bound.get("Process")
		if block == nil || block.Block == nil {
			deny(ReasonBinding)
		}
		output = a.script(*block.Block)
	}
	if output == Unknown {
		deny(ReasonPipeline)
	}
	seenStreams := map[int]bool{}
	merged, successRedirect := false, false
	for _, redirect := range c.Redirects {
		a.b.check()
		if seenStreams[redirect.Stream] || seenStreams[-1] || redirect.Stream == -1 && len(seenStreams) != 0 {
			deny(ReasonUnsupported)
		}
		seenStreams[redirect.Stream] = true
		if redirect.Target != nil {
			a.path(redirect.Target.Value, true)
		}
		if redirect.Merge != 0 {
			merged = true
		} else if redirect.Stream == 1 || redirect.Stream == -1 {
			successRedirect = true
			output = None
		}
	}
	if merged {
		// Roles certify success objects only, not ErrorRecord or other streams.
		// No consumer exception (including Out-Null) or block-level emptiness
		// proof is modeled. Redirect order cannot erase an unproved merge.
		if downstream || successRedirect || bound.role.name == "ForEach-Object" {
			deny(ReasonPipeline)
		}
		// A terminal merge may display objects but cannot certify data escaping
		// a nested block into its enclosing ForEach-Object's success stream.
		output = Unknown
	}
	a.b.check()
	return output
}
func (a *analyzer) path(operand string, write bool) string {
	a.b.check()
	if operand == "" || strings.HasPrefix(operand, "~") || strings.HasPrefix(operand, "$") || strings.Contains(operand, "${") {
		deny(ReasonPath)
	}
	name := strings.ReplaceAll(operand, "/", `\`)
	if !absolute(name) {
		// Root-relative and drive-relative operands depend on ambient drive state.
		if strings.HasPrefix(name, `\`) || strings.Contains(name, ":") {
			deny(ReasonPath)
		}
		name = strings.TrimRight(strings.ReplaceAll(a.ctx.Cwd, "/", `\`), `\`) + `\` + name
	}
	if !validNative(name) {
		deny(ReasonPath)
	}
	a.b.check()
	protected := a.ctx.ProtectedRead(name)
	a.b.check()
	if protected {
		if write {
			deny(ReasonWrite)
		}
		deny(ReasonRead)
	}
	if write {
		a.b.check()
		protected = a.ctx.ProtectedWrite(name)
		a.b.check()
		if protected {
			deny(ReasonWrite)
		}
	}
	return name
}

// absolute and validNative model Windows lexical anchoring on every test OS.
// Native adapters still validate identities and retain all existing witnesses.
// Do not use filepath.Clean/Join here: cleaning away link/.. loses a witness.
func absolute(name string) bool {
	name = strings.ReplaceAll(name, "/", `\`)
	if len(name) >= 3 && asciiLetter(name[0]) && name[1] == ':' && name[2] == '\\' {
		return true
	}
	if strings.HasPrefix(name, `\\`) {
		parts := strings.Split(name[2:], `\`)
		return len(parts) >= 2 && parts[0] != "" && parts[1] != "" && parts[0] != "." && parts[0] != ".." && parts[1] != "." && parts[1] != ".."
	}
	return false
}
func validNative(name string) bool {
	if !absolute(name) {
		return false
	}
	name = strings.ReplaceAll(name, "/", `\`)
	if strings.HasPrefix(name, `\\`) {
		name = name[2:]
	} else {
		name = name[3:]
	}
	parts := strings.Split(name, `\`)
	for i, part := range parts {
		if part == "" {
			if i == len(parts)-1 {
				continue
			}
			return false
		}
		if part == "." || part == ".." {
			continue
		}
		if strings.ContainsAny(part, ":*?[]<>|\"") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
		for _, r := range part {
			if r < 32 || r == 127 {
				return false
			}
		}
		stem := strings.ToUpper(strings.TrimRight(strings.SplitN(part, ".", 2)[0], " "))
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || stem == "CONIN$" || stem == "CONOUT$" {
			return false
		}
		if len([]rune(stem)) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && strings.ContainsRune("123456789¹²³", []rune(stem)[3]) {
			return false
		}
	}
	return true
}
