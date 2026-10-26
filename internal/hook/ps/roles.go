package ps

import "strings"

// Source is an object-pipeline proof, not an inferred filename. None represents
// no success-stream objects; Unknown must never satisfy a consumer contract.
type Source string

const (
	None          Source = "none"
	Literal       Source = "literal"
	PublicContent Source = "public-file-content"
	Unknown       Source = "unknown"
)

type parameter struct {
	name     string
	position int
	kind     string
	role     string
}
type commandRole struct {
	name       string
	parameters []parameter
	input      string
	output     Source
}

// This table is intentionally smaller than the native cmdlets' parameter sets.
// Path and LiteralPath are mutually exclusive. There is exactly one operand
// per parameter, no arrays, aliases for parameters, common or dynamic parameters.
// Positions are native positions, not a Bash-style option parser's leftovers.
var roleTable = []commandRole{
	{"Write-Output", []parameter{{"InputObject", 0, "word", "data"}}, "none", Literal},
	{"Out-Null", nil, "optional", None},
	{"Get-Content", []parameter{{"Path", 0, "word", "read"}, {"LiteralPath", -1, "word", "read"}, {"Raw", -1, "switch", ""}}, "none", PublicContent},
	{"Select-String", []parameter{{"Pattern", 0, "word", "data"}, {"Path", 1, "word", "read"}, {"LiteralPath", -1, "word", "read"}, {"SimpleMatch", -1, "switch", ""}, {"CaseSensitive", -1, "switch", ""}}, "none", PublicContent},
	{"Get-ChildItem", []parameter{{"Path", 0, "word", "directory"}, {"LiteralPath", -1, "word", "directory"}, {"Name", -1, "switch", ""}}, "none", Literal},
	{"Copy-Item", []parameter{{"Path", 0, "word", "regular-read"}, {"LiteralPath", -1, "word", "regular-read"}, {"Destination", 1, "word", "non-directory-write"}}, "none", None},
	{"Set-Content", []parameter{{"Path", 0, "word", "write"}, {"LiteralPath", -1, "word", "write"}, {"Value", 1, "word", "data"}}, "value", None},
	{"Add-Content", []parameter{{"Path", 0, "word", "write"}, {"LiteralPath", -1, "word", "write"}, {"Value", 1, "word", "data"}}, "value", None},
	{"Out-File", []parameter{{"FilePath", 0, "word", "write"}, {"Append", -1, "switch", ""}}, "required", None},
	{"ForEach-Object", []parameter{{"Process", 0, "block", "block"}}, "required", Unknown},
}
var aliases = map[string]string{
	"gc": "get-content", "cat": "get-content", "type": "get-content", "sls": "select-string",
	"gci": "get-childitem", "ls": "get-childitem", "dir": "get-childitem",
	"cp": "copy-item", "copy": "copy-item", "cpi": "copy-item", "%": "foreach-object", "foreach": "foreach-object",
}

type boundArgument struct {
	parameter  parameter
	argument   Argument
	positional bool
}
type binding struct {
	role      commandRole
	arguments []boundArgument
}

func (b binding) get(name string) *Argument {
	for i := range b.arguments {
		if strings.EqualFold(b.arguments[i].parameter.name, name) {
			return &b.arguments[i].argument
		}
	}
	return nil
}
func (b binding) path() *Argument {
	if a := b.get("LiteralPath"); a != nil {
		return a
	}
	return b.get("Path")
}

func bind(c Command, budget *budget) binding {
	budget.check()
	if c.Name.Quote != "" {
		deny(ReasonCommand)
	}
	name := strings.ToLower(c.Name.Value)
	if canonical, ok := aliases[name]; ok {
		name = canonical
	}
	var role *commandRole
	for i := range roleTable {
		if strings.ToLower(roleTable[i].name) == name {
			role = &roleTable[i]
			break
		}
	}
	if role == nil {
		deny(ReasonCommand)
	}
	result := binding{role: *role}
	seen := map[string]bool{}
	add := func(p parameter, a Argument, positional bool) {
		budget.check()
		if seen[p.name] {
			deny(ReasonBinding)
		}
		seen[p.name] = true
		if p.kind == "word" && (a.Word == nil || a.Word.Quote == "parameter") || p.kind == "block" && a.Block == nil {
			deny(ReasonBinding)
		}
		result.arguments = append(result.arguments, boundArgument{p, a, positional})
	}
	var positionals []Argument
	for i := 0; i < len(c.Arguments); i++ {
		budget.check()
		a := c.Arguments[i]
		if a.Word != nil && a.Word.Quote == "parameter" {
			var param *parameter
			for j := range role.parameters {
				if strings.EqualFold(a.Word.Value, role.parameters[j].name) {
					param = &role.parameters[j]
					break
				}
			}
			if param == nil {
				deny(ReasonBinding)
			}
			colon := a.Word.Colon
			if param.kind == "switch" {
				if colon {
					deny(ReasonBinding)
				}
				add(*param, a, false)
				continue
			}
			i++
			if i == len(c.Arguments) {
				deny(ReasonBinding)
			}
			value := c.Arguments[i]
			if colon && a.Span.End != value.Span.Start {
				deny(ReasonBinding)
			}
			add(*param, value, false)
			continue
		}
		positionals = append(positionals, a)
	}
	// Named parameters bind first, independently of textual order. Selecting
	// LiteralPath removes Path's positional slot from the active parameter set.
	position := 0
	for _, a := range positionals {
		budget.check()
		var param *parameter
		for param == nil {
			anyLater := false
			for j := range role.parameters {
				p := &role.parameters[j]
				if seen[p.name] || p.name == "Path" && seen["LiteralPath"] {
					continue
				}
				if p.position >= position {
					anyLater = true
				}
				if p.position == position {
					param = p
					break
				}
			}
			position++
			if !anyLater {
				deny(ReasonBinding)
			}
		}
		add(*param, a, true)
	}
	if seen["Path"] && seen["LiteralPath"] {
		deny(ReasonBinding)
	}
	required := func(name string) {
		if !seen[name] {
			deny(ReasonBinding)
		}
	}
	switch role.name {
	case "Write-Output":
		required("InputObject")
	case "Get-Content":
		if result.path() == nil {
			deny(ReasonBinding)
		}
	case "Select-String":
		required("Pattern")
		if result.path() == nil {
			deny(ReasonBinding)
		}
	case "Get-ChildItem":
		required("Name")
		if result.path() == nil {
			deny(ReasonBinding)
		}
	case "Copy-Item":
		required("Destination")
		if result.path() == nil {
			deny(ReasonBinding)
		}
	case "Set-Content", "Add-Content":
		if result.path() == nil {
			deny(ReasonBinding)
		}
	case "Out-File":
		required("FilePath")
	case "ForEach-Object":
		required("Process")
	}
	return result
}
