package transport

import "strings"

// WindowsSearchDirectory accepts only explicitly absolute PATH entries. In
// particular an empty, dot or drive-relative entry never opts a bare name into
// cwd search. This lexical predicate is portable for ordering/selection tests;
// native resolution also applies filepath.IsAbs before opening an image.
func WindowsSearchDirectory(path string) bool {
	separator := func(b byte) bool { return b == '\\' || b == '/' }
	if len(path) >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && separator(path[2]) {
		return true
	}
	if len(path) < 5 || !separator(path[0]) || !separator(path[1]) {
		return false
	}
	parts := strings.FieldsFunc(path[2:], func(r rune) bool { return r == '\\' || r == '/' })
	return len(parts) >= 2 && parts[0] != "." && parts[0] != "?" && parts[0] != ".." && parts[1] != "." && parts[1] != ".."
}
