package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestKeygen_MultibaseRoundtrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	mb := "z" + base58Encode(pub)

	got, err := DecodeMultibaseEd25519Pub(mb)
	if err != nil {
		t.Fatalf("DecodeMultibaseEd25519Pub: %v", err)
	}

	if string(got) != string(pub) {
		t.Fatalf("pubkey mismatch after roundtrip")
	}
}
