package test

import (
	"testing"
	"crypto/ecdsa"
	//"io/ioutil"
	//"crypto/rand"
 	//"golang.org/x/crypto/sha3"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/noot/linkable-ring/ring"
)

func TestGenKeyImage(t *testing.T) {
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	image := ring.GenKeyImage(privkey)

	if image == nil {
		t.Error("could not generate key image")
	} 
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

func TestHashPoint(t *testing.T) {
	p, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}

	h_x, h_y := ring.HashPoint(p.Public().(*ecdsa.PublicKey))
	if h_x == nil || h_y == nil {
		t.Error("did not hash point")
	}
}