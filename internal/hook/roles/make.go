package roles

import "strings"

func makeLongValueOption(key string) bool {
	return strings.Contains(" --directory --file --makefile --include-dir --old-file --assume-old --what-if --new-file --assume-new ", " "+key+" ") || strings.HasPrefix(key, "--e") && strings.HasPrefix("--eval", key)
}

// NormalizeMakeArgs separates short-option clusters without interpreting option
// values as flags. Required and optional value options both end their cluster.
// Keep every occurrence so repeated executable values cannot erase witnesses.
func NormalizeMakeArgs(args []string) []string {
	var normalized []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return append(normalized, args[i:]...)
		}
		if strings.HasPrefix(arg, "--") {
			normalized = append(normalized, arg)
			key, _, attached := strings.Cut(arg, "=")
			if !attached && makeLongValueOption(key) && i+1 < len(args) {
				i++
				normalized = append(normalized, args[i])
			}
			continue
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			normalized = append(normalized, arg)
			continue
		}
		for j := 1; j < len(arg); j++ {
			flag := arg[j]
			normalized = append(normalized, "-"+string(flag))
			if strings.ContainsRune("CfIoWEjlO", rune(flag)) {
				if j+1 < len(arg) {
					normalized = append(normalized, arg[j+1:])
				} else if strings.ContainsRune("CfIoWE", rune(flag)) && i+1 < len(args) {
					i++
					normalized = append(normalized, args[i])
				}
				break
			}
		}
	}
	return normalized
}
