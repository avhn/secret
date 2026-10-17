package policy

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// stdinCall identifies the recipient of the original statement's redirects.
// Only bounded single-field expansions and transparent prefixes are certified;
// the returned call retains the original operand and redirect provenance.
func (a *analyzer) stdinCall(call *syntax.CallExpr, cwd string) (*syntax.CallExpr, string) {
	copy := *call
	for len(copy.Args) > 0 {
		values, ok := a.expandWord(copy.Args[0], cwd)
		if !ok || len(values) != 1 {
			return &copy, ""
		}
		name := values[0]
		if name != "command" && name != "builtin" {
			return &copy, path.Base(name)
		}
		i := 1
		for i < len(copy.Args) {
			options, ok := a.expandWord(copy.Args[i], cwd)
			if !ok || len(options) != 1 {
				return &copy, ""
			}
			option := options[0]
			if option == "--" {
				i++
				break
			}
			if name == "command" && option == "-p" {
				i++
				continue
			}
			if strings.HasPrefix(option, "-") {
				return &copy, name // command -v/-V queries do not execute a child.
			}
			break
		}
		if i >= len(copy.Args) {
			return &copy, name
		}
		copy.Args = copy.Args[i:]
	}
	return &copy, ""
}
