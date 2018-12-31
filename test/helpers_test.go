package test

import (
	"testing"
	"io/ioutil"
	"reflect"

	"github.com/ethereum/go-ethereum/crypto"
 	"golang.org/x/crypto/sha3"
	"github.com/noot/ring-go/ring"
)

func TestPadTo32Bytes(t *testing.T) {
	in := []byte{1, 2, 3, 4, 5}
	out := ring.PadTo32Bytes(in)
	if len(out) != 32 {
		t.Error("did not pad to 32 bytes")
	}
}

func TestSerialize(t *testing.T) {
	/* generate new private public keypair */
	privkey, err := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	if err != nil {
		t.Error(err)
	}

	/* sign message */
	file, err := ioutil.ReadFile("../message.txt")
	if err != nil {
		t.Error(err)
	}
	msgHash := sha3.Sum256(file)

	/* secret index */
	s := 7

	/* generate keyring */
	keyring := ring.GenNewKeyRing(17, privkey, s)

	sig, err := ring.Sign(msgHash, keyring, privkey, s)
	if err != nil {
		t.Error(err)
	}

	byteSig := sig.SerializeSignature()

	if len(byteSig) != 32 * (3 * sig.Size + 4) + 8 {
		t.Error("incorrect signature length")
	}

	marshal_sig := ring.DeserializeSignature(byteSig)

	marshal_ok := reflect.DeepEqual(marshal_sig.S, sig.S) && 
		reflect.DeepEqual(marshal_sig.Size, sig.Size) && 
		reflect.DeepEqual(marshal_sig.C, sig.C) && 
		reflect.DeepEqual(marshal_sig.M, sig.M) && 
		reflect.DeepEqual(marshal_sig.I, sig.I)

	for i := 0; i < sig.Size; i++ {
		marshal_ok = marshal_ok && reflect.DeepEqual(marshal_sig.Ring[i].X, sig.Ring[i].X)
		marshal_ok = marshal_ok && reflect.DeepEqual(marshal_sig.Ring[i].Y, sig.Ring[i].Y)
	}

	if !marshal_ok {
		t.Error("did not marshal to correct sig")
	}
}

func TestSerializeAndDeserialize(t *testing.T) {
	privkey, err := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	if err != nil {
		t.Error(err)
	}

	file, err := ioutil.ReadFile("../message.txt")
	if err != nil {
		t.Error(err)
	}
	msgHash := sha3.Sum256(file)

	s := 9
	keyring := ring.GenNewKeyRing(29, privkey, s)

	sig, err := ring.Sign(msgHash, keyring, privkey, s)
	if err != nil {
		t.Error(err)
	}

	byteSig := sig.SerializeSignature()

	if len(byteSig) != 32 * (3 * sig.Size + 4) + 8 {
		t.Log(len(byteSig))
		t.Error("incorrect signature length")
	}

	marshal_sig := ring.DeserializeSignature(byteSig)

	marshal_ok := reflect.DeepEqual(marshal_sig.S, sig.S) && 
		reflect.DeepEqual(marshal_sig.Size, sig.Size) && 
		reflect.DeepEqual(marshal_sig.C, sig.C) && 
		reflect.DeepEqual(marshal_sig.M, sig.M) && 
		reflect.DeepEqual(marshal_sig.I, sig.I)

	for i := 0; i < sig.Size; i++ {
		marshal_ok = marshal_ok && reflect.DeepEqual(marshal_sig.Ring[i].X, sig.Ring[i].X)
		marshal_ok = marshal_ok && reflect.DeepEqual(marshal_sig.Ring[i].Y, sig.Ring[i].Y)
	}

	if !marshal_ok {
		t.Error("did not marshal to correct sig")
	}
}