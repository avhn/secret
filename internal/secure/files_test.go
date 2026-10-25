package secure

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func privateTestRoot(t *testing.T) *os.Root {
	t.Helper()
	parent, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := CreatePrivateDirectory(parent, "private"); err != nil {
		t.Fatal(err)
	}
	root, err := parent.OpenRoot("private")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestPrivateFiles(t *testing.T) {
	root := privateTestRoot(t)
	parent, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(parent); err != nil {
		t.Fatal(err)
	}
	parent.Close()
	file, err := CreatePrivateFile(root, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(file); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("synthetic-file-bytes")); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := CreatePrivateFile(root, "synthetic"); !os.IsExist(err) {
		t.Fatalf("exclusive create: %v", err)
	}
	file, err = OpenPrivateFile(root, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	defer Clear(data)
	if err != nil || string(data) != "synthetic-file-bytes" {
		t.Fatal("private read did not preserve synthetic bytes")
	}
	if _, err := OpenPrivateFile(root, "missing"); !os.IsNotExist(err) {
		t.Fatalf("missing read: %v", err)
	}
	if err := CreatePrivateDirectory(root, "directory"); err != nil {
		t.Fatal(err)
	}
	if err := CreatePrivateDirectory(root, "directory"); !os.IsExist(err) {
		t.Fatalf("existing directory accepted or repaired: %v", err)
	}
	if file, err := OpenPrivateFile(root, "directory"); err == nil {
		file.Close()
		t.Fatal("directory accepted as a regular file")
	}
}

func TestPrivateChildrenStayAnchored(t *testing.T) {
	root := privateTestRoot(t)
	for _, name := range []string{"", ".", "..", "../escape", "child/leaf", filepath.Join(root.Name(), "absolute")} {
		t.Run(name, func(t *testing.T) {
			if file, err := CreatePrivateFile(root, name); err == nil {
				file.Close()
				t.Fatal("ambiguous child create accepted")
			}
			if err := CreatePrivateDirectory(root, name); err == nil {
				t.Fatal("ambiguous directory create accepted")
			}
			if file, err := OpenPrivateFile(root, name); err == nil {
				file.Close()
				t.Fatal("ambiguous child read accepted")
			}
		})
	}
	old := root.Name()
	moved := old + "-moved"
	if err := os.Rename(old, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(old, 0700); err != nil {
		t.Fatal(err)
	}
	file, err := CreatePrivateFile(root, "anchored")
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := os.Stat(filepath.Join(moved, "anchored")); err != nil {
		t.Fatal("create did not use the retained directory handle")
	}
	if _, err := os.Stat(filepath.Join(old, "anchored")); !os.IsNotExist(err) {
		t.Fatal("create reopened the directory by its old name")
	}
}

func TestPrivateNilHandles(t *testing.T) {
	if CheckPrivate(nil) != ErrPrivateFile {
		t.Fatal("nil file accepted")
	}
	if _, err := OpenPrivateFile(nil, "synthetic"); err != ErrPrivateFile {
		t.Fatal("nil root accepted")
	}
	if _, err := CreatePrivateFile(nil, "synthetic"); err != ErrPrivateFile {
		t.Fatal("nil root accepted")
	}
	if CreatePrivateDirectory(nil, "synthetic") != ErrPrivateFile {
		t.Fatal("nil root accepted")
	}
}
