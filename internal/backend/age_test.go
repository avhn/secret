package backend

import (
	"testing"

	"filippo.io/age"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func FuzzAgeDecrypt(f *testing.F) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatal("generate")
	}
	identities := []age.Identity{identity}
	candidate, err := encryptAge(nil, nil, []string{identity.Recipient().String()}, identities, ageSteps{})
	if err != nil {
		f.Fatal(err)
	}
	// Only mutations, never keys or stable identity-bearing ciphertext, are seeds.
	f.Add([]byte{}, uint8(0))
	f.Add([]byte("unsupported"), uint8(1))
	f.Add([]byte{0}, uint8(2))
	f.Fuzz(func(t *testing.T, mutation []byte, mode uint8) {
		if len(mutation) > 64<<10 {
			return
		}
		data := append([]byte(nil), candidate...)
		switch mode % 3 {
		case 0:
			if len(mutation) > 0 {
				data = mutation
			}
		case 1:
			for i, b := range mutation {
				data[i%len(data)] ^= b
			}
		case 2:
			data = append(data, mutation...)
		}
		snapshot, err := decryptAge(data, identities)
		if err != nil {
			if snapshot != nil || err != store.ErrAge {
				t.Fatal("unsafe error")
			}
			return
		}
		defer snapshot.Close()
		if store.ValidateAgePlaintext(snapshot.Dotenv, snapshot.Envelope.Records) != nil {
			t.Fatal("unverified plaintext")
		}
	})
}
func FuzzAgeKeyFiles(f *testing.F) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatal("generate")
	}
	private := []byte(identity.String() + "\n")
	defer secure.Clear(private)
	public := []byte(identity.Recipient().String() + "\n")
	f.Add([]byte{}, true)
	f.Add([]byte{}, false)
	f.Add([]byte("# comment\n"), true)
	f.Add([]byte("scrypt\n"), false)
	f.Fuzz(func(t *testing.T, input []byte, secret bool) {
		if len(input) > maxAgeKeyFile+1 {
			return
		}
		data := input
		if len(input) == 0 {
			if secret {
				data = private
			} else {
				data = public
			}
		}
		identities, recipients, err := parseAgeKeyLines(data, secret)
		if err != nil {
			if err != store.ErrAge {
				t.Fatal("unsafe key error")
			}
			return
		}
		if len(recipients) < 1 || len(recipients) > 32 || secret && len(identities) != len(recipients) {
			t.Fatal("key count")
		}
		if _, err := store.CanonicalAgeRecipients(recipients); err != nil {
			t.Fatal("accepted recipients")
		}
	})
}
