package cli

import (
	"testing"

	"golang.org/x/sys/unix"
)

func operatorTerminalState(fd int) (*unix.Termios, error) {
	state, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return nil, err
	}
	*state = operatorTerminalSettings(*state)
	return state, nil
}

func operatorTerminalSettings(state unix.Termios) unix.Termios {
	// Darwin's TIOCSETA sets PENDIN when ICANON is restored, even if the saved
	// state did not contain it. This is pending-input status, cleared by the
	// kernel on subsequent input, not a terminal setting the caller can restore.
	// Compare every setting, including ECHO, ICANON, control bytes and speeds.
	state.Lflag &^= unix.PENDIN
	return state
}

func TestOperatorTerminalSettings(t *testing.T) {
	before := unix.Termios{Iflag: unix.ICRNL, Oflag: unix.OPOST, Cflag: unix.CS8, Lflag: unix.ECHO | unix.ICANON, Ispeed: 9600, Ospeed: 9600}
	for _, tc := range []struct {
		name  string
		edit  func(*unix.Termios)
		equal bool
	}{
		{"pending input", func(s *unix.Termios) { s.Lflag |= unix.PENDIN }, true},
		{"echo", func(s *unix.Termios) { s.Lflag &^= unix.ECHO }, false},
		{"canonical", func(s *unix.Termios) { s.Lflag &^= unix.ICANON }, false},
		{"input flags", func(s *unix.Termios) { s.Iflag = 0 }, false},
		{"output flags", func(s *unix.Termios) { s.Oflag = 0 }, false},
		{"control flags", func(s *unix.Termios) { s.Cflag = 0 }, false},
		{"control bytes", func(s *unix.Termios) { s.Cc[unix.VMIN] = 1 }, false},
		{"input speed", func(s *unix.Termios) { s.Ispeed++ }, false},
		{"output speed", func(s *unix.Termios) { s.Ospeed++ }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			after := before
			tc.edit(&after)
			if equal := operatorTerminalSettings(before) == operatorTerminalSettings(after); equal != tc.equal {
				t.Fatal("terminal settings comparison ignored a setting or retained pending-input status")
			}
		})
	}
}
