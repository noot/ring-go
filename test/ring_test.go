package test

import (
	"testing"
 	"golang.org/x/crypto/sha3"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/noot/ring-go/ring"
)

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