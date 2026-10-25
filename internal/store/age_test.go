package store

import (
	"bytes"
	"testing"

	"filippo.io/age"
)

// FuzzAgeEnvelope seeds only public metadata. Every test process generates its
// own recipient; no private identity is retained in a fuzz corpus.
func FuzzAgeEnvelope(f *testing.F) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatal("generate")
	}
	prefix, err := EncodeAgePrefix([]string{id.Recipient().String()}, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(append(prefix, []byte("age-encryption.org/v1\nsynthetic")...))
	f.Add([]byte(AgeMagic))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxAgeMetadata+8192 {
			return
		}
		envelope, err := ParseAgeEnvelope(data)
		if err != nil {
			return
		}
		encoded, err := EncodeAgePrefix(envelope.Recipients, envelope.Records)
		if err != nil || !bytes.Equal(encoded, envelope.Prefix) {
			t.Fatal("accepted noncanonical envelope")
		}
		if len(envelope.Records) > MaxAgeRecords || len(envelope.Recipients) > 32 {
			t.Fatal("bounds")
		}
	})
}
