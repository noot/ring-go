package ring

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestPadTo32Bytes(t *testing.T) {
	in := []byte{1, 2, 3, 4, 5}
	out := padTo32Bytes(in)
	if len(out) != 32 {
		t.Error("did not pad to 32 bytes")
	}
}

func TestHashPoint(t *testing.T) {
	p, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}

	ge := hashToCurve(p.Public().(*ecdsa.PublicKey))
	if ge == nil {
		t.Error("did not hash point to curve")
	}
}
