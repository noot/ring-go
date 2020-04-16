package ring

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

func createSig(size int, s int) *RingSign {
	/* generate new private public keypair */
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* sign message */
	msg := "helloworld"
	msgHash := sha3.Sum256([]byte(msg))

	/* generate keyring */
	keyring, err := GenNewKeyRing(size, privkey, s)
	if err != nil {
		return nil
	}

	sig, err := Sign(msgHash, keyring, privkey, s)
	if err != nil {
		return nil
	}
	return sig
}

func TestGenNewKeyRing(t *testing.T) {
	/* generate new private public keypair */
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* generate keyring */
	keyring, err := GenNewKeyRing(2, privkey, 0)
	if err != nil {
		t.Error(err)
	}

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
	keyring, err := GenNewKeyRing(3, privkey, 1)
	if err != nil {
		t.Error(err)
	}

	if keyring == nil || len(keyring) != 3 {
		t.Error("could not generate keyring of size 3")
	} else {
		t.Log("generation of new keyring of size 3 ok")
	}
}

func TestGenKeyRing(t *testing.T) {
	/* generate new private public keypair */
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	s := 0
	size := 3

	/* generate some pubkeys */
	pubkeys := make([]*ecdsa.PublicKey, size)
	for i := 0; i < size; i++ {
		priv, err := crypto.GenerateKey()
		if err != nil {
			t.Error(err)
		}

		pub := priv.Public()
		pubkeys[i] = pub.(*ecdsa.PublicKey)
	}

	/* generate keyring */
	keyring, err := GenKeyRing(pubkeys, privkey, s)
	if err != nil {
		t.Error(err)
	}

	if keyring == nil || len(keyring) != size+1 {
		t.Error("could not generate keyring of size 4")
	} else if keyring[s].X.Cmp(privkey.Public().(*ecdsa.PublicKey).X) != 0 {
		t.Error("secret index in ring is not signer")
	} else {
		t.Log("generation of new keyring of size 4 ok")
	}
}

func TestGenKeyImage(t *testing.T) {
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	image := GenKeyImage(privkey)

	if image == nil {
		t.Error("could not generate key image")
	}
}

func TestHashPoint(t *testing.T) {
	p, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}

	h_x, h_y := HashPoint(p.Public().(*ecdsa.PublicKey))
	if h_x == nil || h_y == nil {
		t.Error("did not hash point")
	}
}

func TestSign(t *testing.T) {
	/* generate new private public keypair */
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* sign message */
	msg := "helloworld"
	msgHash := sha3.Sum256([]byte(msg))

	/* generate keyring */
	keyring, err := GenNewKeyRing(2, privkey, 0)
	if err != nil {
		t.Error(err)
	}

	sig, err := Sign(msgHash, keyring, privkey, 0)
	if err != nil {
		t.Error("error when signing with ring size of 2")
	} else {
		t.Log("signing ok with ring size of 2")
		t.Log(sig)
	}
}

func TestSignAgain(t *testing.T) {
	/* generate new private public keypair */
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* sign message */
	msg := "helloworld"
	msgHash := sha3.Sum256([]byte(msg))

	/* generate keyring */
	keyring, err := GenNewKeyRing(100, privkey, 17)
	if err != nil {
		t.Error(err)
	}

	sig, err := Sign(msgHash, keyring, privkey, 17)
	if err != nil {
		t.Error("error when signing with ring size of 100")
	} else {
		t.Log("signing ok with ring size of 100")
		t.Log(sig)
	}
}

func TestVerify(t *testing.T) {
	sig := createSig(5, 4)
	if sig == nil {
		t.Error("signing error")
	}
	/* verify signature */
	ver := Verify(sig)
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
	ver := Verify(sig)
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
	ver := Verify(sig)
	if ver {
		t.Error("verified? true")
	}
}

func TestLinkabilityTrue(t *testing.T) {
	/* generate new private public keypair */
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* sign message */
	msg1 := "helloworld"
	msgHash1 := sha3.Sum256([]byte(msg1))

	/* generate keyring */
	keyring1, err := GenNewKeyRing(2, privkey, 0)
	if err != nil {
		t.Error(err)
	}

	sig1, err := Sign(msgHash1, keyring1, privkey, 0)
	if err != nil {
		t.Error("error when signing with ring size of 2")
	} else {
		t.Log("signing ok with ring size of 2")
		t.Log(sig1)
		spew.Dump(sig1.I)
	}

	/* sign message */
	msg2 := "hello world"
	msgHash2 := sha3.Sum256([]byte(msg2))

	/* generate keyring */
	keyring2, err := GenNewKeyRing(2, privkey, 0)
	if err != nil {
		t.Error(err)
	}

	sig2, err := Sign(msgHash2, keyring2, privkey, 0)
	if err != nil {
		t.Error("error when signing with ring size of 2")
	} else {
		t.Log("signing ok with ring size of 2")
		t.Log(sig2)
	}

	link := Link(sig1, sig2)
	if link {
		t.Log("the signatures are linkable")
	} else {
		t.Error("linkable? false")
	}
}

func TestLinkabilityFalse(t *testing.T) {
	/* generate new private public keypair */
	privkey1, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* sign message */
	msg1 := "helloworld"
	msgHash1 := sha3.Sum256([]byte(msg1))

	/* generate keyring */
	keyring1, err := GenNewKeyRing(2, privkey1, 0)
	if err != nil {
		t.Error(err)
	}

	sig1, err := Sign(msgHash1, keyring1, privkey1, 0)
	if err != nil {
		t.Error("error when signing with ring size of 2")
	} else {
		t.Log("signing ok with ring size of 2")
		t.Log(sig1)
		spew.Dump(sig1.I)
	}

	privkey2, _ := crypto.HexToECDSA("01ad23ee4fbabbcf31dda1270154a623f5f7c07433193ff07395b33ac5bf2bea")
	/* sign message */
	msg2 := "hello world"
	msgHash2 := sha3.Sum256([]byte(msg2))

	/* generate keyring */
	keyring2, err := GenNewKeyRing(2, privkey2, 0)
	if err != nil {
		t.Error(err)
	}

	sig2, err := Sign(msgHash2, keyring2, privkey2, 0)
	if err != nil {
		t.Error("error when signing with ring size of 2")
	} else {
		t.Log("signing ok with ring size of 2")
		t.Log(sig2)
	}

	link := Link(sig1, sig2)
	if !link {
		t.Log("signatures signed with different private keys are not linkable")
	} else {
		t.Error("linkable? true")
	}
}
