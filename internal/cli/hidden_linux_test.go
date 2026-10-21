package cli

import (
	"bytes"
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// openTestPTY opens a disposable Linux pseudo-terminal pair; no real terminal is touched.
func openTestPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("pseudo-terminals unavailable")
	}
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetUint32(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

// echoProbe records whether the terminal echoed input at the moment the prompt is written.
type echoProbe struct {
	fd       int
	echoed   []bool
	rendered bytes.Buffer
}

func (p *echoProbe) Write(b []byte) (int, error) {
	state, err := unix.IoctlGetTermios(p.fd, getTermios)
	if err != nil {
		return 0, err
	}
	p.echoed = append(p.echoed, state.Lflag&unix.ECHO != 0)
	return p.rendered.Write(b)
}

func TestHiddenInputSilencesEchoBeforePrompt(t *testing.T) {
	master, slave := openTestPTY(t)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), getTermios)
	if err != nil || before.Lflag&unix.ECHO == 0 {
		t.Fatal("disposable terminal does not start with echo")
	}
	if _, err := master.Write([]byte("synthetic-hidden\n")); err != nil {
		t.Fatal(err)
	}
	probe := &echoProbe{fd: int(slave.Fd())}
	value, err := command{in: slave, errOut: probe}.input("KEY")
	if err != nil || string(value) != "synthetic-hidden" {
		t.Fatal("hidden input was not read")
	}
	if len(probe.echoed) == 0 || probe.echoed[0] || !bytes.HasPrefix(probe.rendered.Bytes(), []byte("KEY: ")) {
		t.Fatal("prompt was written while the terminal still echoed input")
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), getTermios)
	if err != nil || *after != *before {
		t.Fatal("terminal settings were not restored")
	}
}
