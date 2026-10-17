package policy

import (
	"strings"
	"time"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

type interpreterInput struct {
	producer *syntax.Stmt
	redirect *syntax.Redirect
	cwd      string
}

// Use the normal bounded command dispatch to resolve stdin recipients, rather
// than a second wrapper/alias parser which can lose the original pipe source.
func (a *analyzer) pipelineRecipient(cmd *syntax.BinaryCmd, depth int, cwd string) string {
	prior := a.interpreterInputs
	if cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll {
		a.interpreterInputs = append(a.interpreterInputs, interpreterInput{producer: cmd.X, cwd: cwd})
	}
	defer func() { a.interpreterInputs = prior }()
	return a.stmts([]*syntax.Stmt{cmd.Y}, depth, cwd)
}

func (a *analyzer) interpreterInputProtected(cwd, name string) bool {
	for _, input := range a.interpreterInputs {
		if time.Now().After(a.deadline) {
			a.reason = roles.Indeterminate
			return true
		}
		if input.producer != nil {
			if a.interpreterProducer(input.producer, input.cwd, cwd, name) {
				return true
			}
			continue
		}
		r := input.redirect
		word := r.Word
		if r.Hdoc != nil {
			word = r.Hdoc
		}
		// Retain raw file/environment witnesses. Literal scan ceilings belong
		// to decoded source, not here-string shell quoting and escape bytes.
		raw := a.raw(word)
		if a.inlineGitDir(raw, cwd) || environmentCode(raw) || a.interpreterProtected(raw, cwd) {
			return true
		}
		body, known := a.expandInterpreterStdin(word, r.Hdoc != nil, input.cwd)
		if !known {
			a.reason = roles.Indeterminate
			return true
		}
		if a.inlineGitDir(body, cwd) || a.executableInterpreterProtected(body, cwd, name) {
			return true
		}
	}
	return false
}

// Expand executable stdin without shell execution, field splitting or globbing.
// The parser preserves quoted heredocs as literal bodies. Only simple, known
// scalar substitutions are admitted; unsupported executable input denies.
func (a *analyzer) expandInterpreterStdin(word *syntax.Word, document bool, cwd string) (string, bool) {
	const maxBody = 1 << 20
	if a.countedWords == nil {
		a.countedWords = make(map[*syntax.Word]bool)
	}
	if !a.countedWords[word] {
		a.words++
		a.countedWords[word] = true
	}
	budget := len(a.raw(word))
	known := a.words <= 256 && budget <= maxBody
	values := []string{"HOME=" + a.home}
	steps := 0
	syntax.Walk(word, func(node syntax.Node) bool {
		if node == nil {
			return false
		}
		steps++
		if !known || steps > maxFlowSteps || time.Now().After(a.deadline) {
			known = false
			return false
		}
		switch n := node.(type) {
		case *syntax.Word, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted:
		case *syntax.ParamExp:
			if n.Param == nil || n.Exp != nil || n.Repl != nil || n.Slice != nil || n.Index != nil || n.Length || n.Excl || n.Width || n.Names != 0 {
				known = false
				return false
			}
			name := n.Param.Value
			value, ok := a.loopVars[name]
			if !ok && name == "PWD" && cwd != "" && !strings.Contains(a.source, "PWD=") {
				value, ok = cwd, true
			}
			if !ok {
				value, ok = a.staticVariable(name)
			}
			budget += len(value)
			if !ok || budget > maxBody {
				known = false
				return false
			}
			values = append(values, name+"="+value)
			return false
		default:
			known = false
			return false
		}
		return true
	})
	if !known {
		return "", false
	}
	// Avoid user database lookup for an unquoted ~user prefix. HOME tilde
	// expansion uses only the explicit synthetic/guard home supplied above.
	if !document && word != nil && len(word.Parts) > 0 {
		if lit, ok := word.Parts[0].(*syntax.Lit); ok && strings.HasPrefix(lit.Value, "~") && lit.Value != "~" && !strings.HasPrefix(lit.Value, "~/") {
			return "", false
		}
	}
	cfg := &expand.Config{Env: expand.ListEnviron(values...), NoUnset: true}
	var body string
	var err error
	if document {
		body, err = expand.Document(cfg, word)
	} else {
		// expand.Literal retains backslashes in unquoted Lit parts, unlike
		// shell quote removal. Decode only those parts before scalar expansion;
		// single-quoting the result prevents a second tilde or expansion pass.
		copy := *word
		copy.Parts = append([]syntax.WordPart(nil), word.Parts...)
		for i, part := range copy.Parts {
			lit, ok := part.(*syntax.Lit)
			if !ok {
				continue
			}
			value := lit.Value
			var decoded strings.Builder
			if i == 0 && (value == "~" || strings.HasPrefix(value, "~/")) {
				decoded.WriteString(a.home)
				value = value[1:]
			}
			for j := 0; j < len(value); j++ {
				if j%128 == 0 && time.Now().After(a.deadline) {
					return "", false
				}
				if value[j] == '\\' && j+1 < len(value) {
					j++
					if value[j] == '\n' {
						continue
					}
				}
				decoded.WriteByte(value[j])
			}
			copy.Parts[i] = &syntax.SglQuoted{Value: decoded.String()}
		}
		body, err = expand.Literal(cfg, &copy)
	}
	return body, err == nil && len(body) <= maxBody && time.Now().Before(a.deadline)
}
