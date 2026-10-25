package store

import (
	"os"
	"testing"

	"github.com/avhn/secret/internal/secure"
)

func assertPrivateFixture(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if secure.CheckPrivate(file) != nil {
		t.Fatal("synthetic object does not have private permissions")
	}
}
