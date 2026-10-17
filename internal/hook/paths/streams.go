package paths

import (
	"path/filepath"
	"runtime"
	"strings"
)

// StreamBase retains the base file's role for Windows alternate data streams.
// On other platforms a colon is an ordinary filename character.
func StreamBase(name string) string {
	if runtime.GOOS != "windows" {
		return name
	}
	return windowsStreamBase(name, filepath.VolumeName(name))
}

func windowsStreamBase(name, volume string) string {
	var base strings.Builder
	base.WriteString(volume)
	stream := false
	for _, c := range name[len(volume):] {
		switch c {
		case '/', '\\':
			stream = false
			base.WriteRune(c)
		case ':':
			stream = true
		default:
			if !stream {
				base.WriteRune(c)
			}
		}
	}
	return base.String()
}
