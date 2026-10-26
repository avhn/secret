package store

import (
	"testing"
	"time"
)

func TestSetLockWaitForTest(t *testing.T) {
	const productionWait = 3 * time.Second
	if lockWait != productionWait {
		t.Fatalf("default lock wait = %s, want %s", lockWait, productionWait)
	}
	for _, wait := range []time.Duration{30 * time.Second, 45 * time.Second} {
		t.Run(wait.String(), func(t *testing.T) {
			t.Cleanup(SetLockWaitForTest(wait))
			if lockWait != wait {
				t.Fatalf("test lock wait = %s, want %s", lockWait, wait)
			}
		})
		if lockWait != productionWait {
			t.Fatalf("restored lock wait = %s, want %s", lockWait, productionWait)
		}
	}
}
