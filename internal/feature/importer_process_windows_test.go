//go:build windows

package feature

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"golang.org/x/sys/windows"
)

func TestWindowsImporterStopsDescendants(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "stdout overflow", "stderr overflow", "inherited pipe", "closed pipe"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			listener.SetDeadline(time.Now().Add(10 * time.Second))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
			}
			defer cancel()
			type result struct {
				data []byte
				err  error
			}
			finished := make(chan result, 1)
			go func() {
				data, err := runImporter(ctx, os.Args[0], []string{"-test.run=^TestWindowsImporterFixture$", "--", mode, dir, listener.Addr().String()})
				finished <- result{data, err}
			}()
			connection, err := listener.Accept()
			if err != nil {
				t.Fatal("importer descendant did not connect")
			}
			defer connection.Close()
			connection.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(connection)
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal("importer descendant did not signal readiness")
			}
			pid, err := strconv.Atoi(line[:len(line)-1])
			if err != nil || pid <= 0 {
				t.Fatal("invalid synthetic descendant PID")
			}
			process, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				windows.TerminateProcess(process, 1)
				windows.CloseHandle(process)
			})
			// Pin the descendant identity before allowing the importer to exit,
			// overflow or time out. Socket EOF is not a Windows liveness oracle:
			// forced termination can close TCP with WSAECONNRESET instead.
			if err := os.WriteFile(filepath.Join(dir, "release"), []byte("ready"), 0600); err != nil {
				t.Fatal(err)
			}
			if mode == "cancel" {
				cancel()
			}
			select {
			case result := <-finished:
				defer secure.Clear(result.data)
				if mode == "closed pipe" {
					if result.err != nil || !bytes.Equal(result.data, []byte("{}")) {
						t.Fatal("normal importer exit failed")
					}
				} else if result.err != secure.ErrTransaction || len(result.data) != 0 {
					t.Fatal("importer failure was not fixed and private")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Windows importer exceeded cleanup bound")
			}
			if status, err := windows.WaitForSingleObject(process, 2000); err != nil || status != windows.WAIT_OBJECT_0 {
				t.Fatal("Windows importer grandchild survived Job cleanup")
			}
		})
	}
}

func TestWindowsImporterFixture(t *testing.T) {
	index := -1
	for i, arg := range os.Args {
		if arg == "--" {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	mode, dir, address := os.Args[index+1], os.Args[index+2], os.Args[index+3]
	if mode == "descendant" {
		connection, err := net.Dial("tcp", address)
		if err != nil {
			os.Exit(2)
		}
		defer connection.Close()
		if _, err := connection.Write([]byte(strconv.Itoa(os.Getpid()) + "\n")); err != nil {
			os.Exit(2)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
				break
			}
			if time.Now().After(deadline) {
				os.Exit(2)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if os.WriteFile(filepath.Join(dir, "ready"), []byte("ready"), 0600) != nil {
			os.Exit(2)
		}
	} else {
		child := exec.Command(os.Args[0], "-test.run=^TestWindowsImporterFixture$", "--", "descendant", dir, address)
		if mode != "closed pipe" {
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
		}
		if child.Start() != nil {
			os.Exit(2)
		}
		ready := false
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
				ready = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !ready {
			os.Exit(2)
		}
		switch mode {
		case "stdout overflow":
			os.Stdout.Write(make([]byte, MaxImporterOutputBytes+1))
		case "stderr overflow":
			os.Stderr.Write(make([]byte, MaxImporterOutputBytes+1))
		case "inherited pipe":
			os.Exit(0)
		case "closed pipe":
			os.Stdout.Write([]byte("{}"))
			os.Exit(0)
		}
	}
	for {
		time.Sleep(time.Second)
	}
}
