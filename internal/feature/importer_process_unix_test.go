//go:build !windows

package feature

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
)

func TestImporterRunnerStopsDescendants(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRET_IMPORTER_DESCENDANT_HELPER", "1")
	for _, mode := range []string{"cancel", "deadline", "stdout overflow", "stderr overflow", "inherited pipe"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			timeout := 5 * time.Second
			if mode == "deadline" {
				timeout = 2 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			type result struct {
				output []byte
				err    error
			}
			finished := make(chan result, 1)
			go func() {
				output, err := runImporter(ctx, executable, []string{"-test.run=^TestImporterDescendantHelperProcess$", "--", mode, listener.Addr().String()})
				finished <- result{output, err}
			}()
			connection, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(connection)
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal("descendant did not signal readiness")
			}
			pid, err := strconv.Atoi(line[:len(line)-1])
			if err != nil || pid <= 0 {
				t.Fatal("invalid synthetic descendant PID")
			}
			process, err := os.FindProcess(pid)
			if err != nil {
				t.Fatal(err)
			}
			// Clean up the synthetic descendant even when the regression fails.
			defer process.Release()
			defer process.Kill()
			if mode == "cancel" {
				cancel()
			}
			select {
			case result := <-finished:
				defer secure.Clear(result.output)
				if result.err != secure.ErrTransaction || len(result.output) != 0 {
					t.Fatal("descendant failure was not fixed and private")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("importer did not return within the cleanup bound")
			}
			// WaitDelay closes exec's pipes itself. Only descendant termination
			// closes this independent connection, so EOF proves more than return.
			if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
				t.Fatal("importer descendant survived cleanup")
			}
		})
	}
}

func TestImporterDescendantHelperProcess(t *testing.T) {
	if os.Getenv("SECRET_IMPORTER_DESCENDANT_HELPER") != "1" {
		return
	}
	mode, address := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	if mode == "descendant" {
		connection, err := net.Dial("tcp", address)
		if err != nil {
			os.Exit(2)
		}
		defer connection.Close()
		if _, err := connection.Write([]byte(strconv.Itoa(os.Getpid()) + "\n")); err != nil {
			os.Exit(2)
		}
		ready := os.NewFile(3, "synthetic-ready")
		if _, err := ready.Write([]byte{1}); err != nil {
			os.Exit(2)
		}
		_ = ready.Close()
	} else {
		read, write, err := os.Pipe()
		if err != nil {
			os.Exit(2)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestImporterDescendantHelperProcess$", "--", "descendant", address)
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		child.ExtraFiles = []*os.File{write}
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		_ = write.Close()
		if _, err := io.ReadFull(read, make([]byte, 1)); err != nil {
			os.Exit(2)
		}
		_ = read.Close()
		switch mode {
		case "stdout overflow", "stderr overflow":
			output := os.Stdout
			if mode == "stderr overflow" {
				output = os.Stderr
			}
			_, _ = output.Write(make([]byte, MaxImporterOutputBytes+1))
		case "inherited pipe":
			os.Exit(0)
		}
	}
	for {
		time.Sleep(time.Second)
	}
}
