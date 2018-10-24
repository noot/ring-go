package test

import (
	"testing"

	"crypto/rand"
 	"golang.org/x/crypto/sha3"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/noot/ring-go/ring"
)

func createSig(size int, s int) *ring.RingSign {
	/* generate new private public keypair */
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* sign message */
	msg := "helloworld"
	msgHash := sha3.Sum256([]byte(msg))

	/* generate keyring */
	keyring := ring.GenNewKeyRing(size, privkey, s)

	sig, err := ring.Sign(msgHash, keyring, privkey, s)
	if err != nil {
		return nil
	}
	return sig
}

func TestGenNewKeyRing(t *testing.T) {
	/* generate new private public keypair */
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* generate keyring */
	keyring := ring.GenNewKeyRing(2, privkey, 0)

	if keyring == nil || len(keyring) != 2 {
		t.Error("could not generate keyring of size 2")
	} else {
		t.Log("generation of new keyring of size 2 ok")
	}
}

func TestGenNewKeyRing3(t *testing.T) {
	/* generate new private public keypair */
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* generate keyring */
	keyring := ring.GenNewKeyRing(3, privkey, 1)

	if keyring == nil || len(keyring) != 3 {
		t.Error("could not generate keyring of size 3")
	} else {
		t.Log("generation of new keyring of size 3 ok")
	}
}

func TestSign(t *testing.T) {
	/* generate new private public keypair */
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* sign message */
	msg := "helloworld"
	msgHash := sha3.Sum256([]byte(msg))

	/* generate keyring */
	keyring := ring.GenNewKeyRing(2, privkey, 0)

	sig, err := ring.Sign(msgHash, keyring, privkey, 0)
	if err != nil {
		t.Error("error when signing with ring size of 2")
	} else {
		t.Log("signing ok with ring size of 2")
		t.Log(sig)
	}
}

func TestVerify(t *testing.T) {
	sig := createSig(5, 4)
	if sig == nil {
		t.Error("signing error")
	}
	/* verify signature */
	ver := ring.Verify(sig)
 	if !ver {
		t.Error("verified? false")
	}
}

func TestVerifyFalse(t *testing.T) {
	sig := createSig(5, 2)
	if sig == nil {
		t.Error("signing error")
	}
	curve := sig.Ring[0].Curve
	sig.C, _ = rand.Int(rand.Reader, curve.Params().P)	
	/* verify signature */
	ver := ring.Verify(sig)
	if ver {
		t.Error("verified? true")
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	sig := createSig(5, 1)
	if sig == nil {
		t.Error("signing error")
	}

	msg := "noot"
	msgHash := sha3.Sum256([]byte(msg))
	sig.M = msgHash

	/* verify signature */
	ver := ring.Verify(sig)
	if ver {
		t.Error("verified? true")
	}
}