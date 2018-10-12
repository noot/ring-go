package test

import (
	"testing"

	"math/big"
	"crypto/rand"
 	"golang.org/x/crypto/sha3"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/noot/ring-go/ring"
)

func createSig(size int) *ring.RingSign {
	/* generate new private public keypair */
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* sign message */
	msg := "helloworld"
	msgHashArr := sha3.Sum256([]byte(msg))
	msgHash := msgHashArr[:]

	/* generate keyring */
	keyring := ring.GenNewKeyRing(size, privkey)

	sig, err := ring.Sign(msgHash, keyring, privkey)
	if err != nil {
		return nil
	}
	return sig
}

func TestGenNewKeyRing(t *testing.T) {
	/* generate new private public keypair */
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* generate keyring */
	keyring := ring.GenNewKeyRing(2, privkey)

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
	keyring := ring.GenNewKeyRing(3, privkey)

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
	msgHashArr := sha3.Sum256([]byte(msg))
	msgHash := msgHashArr[:]

	/* generate keyring */
	keyring := ring.GenNewKeyRing(2, privkey)

	sig, err := ring.Sign(msgHash, keyring, privkey)
	if err != nil {
		t.Error("error when signing with ring size of 2")
	} else {
		t.Log("signing ok with ring size of 2")
		t.Log(sig)
	}
}

func TestVerify(t *testing.T) {
	sig := createSig(5)
	/* verify signature */
	ver, err := ring.Verify(sig)
	if err != nil { 
		t.Error("verification error")
	} else if !ver {
		t.Error("verified? false")
	}
}

func TestVerifyFalse(t *testing.T) {
	sig := createSig(5)
	curve := sig.Ring[0].Curve
	sig.C, _ = rand.Int(rand.Reader, curve.Params().P)	
	/* verify signature */
	ver, err := ring.Verify(sig)
	if err != nil { 
		t.Error("verification error")
	} else if ver {
		t.Error("verified? true")
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	sig := createSig(5)
	m, _ := rand.Int(rand.Reader, new(big.Int).SetInt64(2^64))
	sig.M = m.Bytes()
	/* verify signature */
	ver, err := ring.Verify(sig)
	if err != nil { 
		t.Error("verification error")
	} else if ver {
		t.Error("verified? true")
	}
}