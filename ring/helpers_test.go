package ring

import (
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

func TestPadTo32Bytes(t *testing.T) {
	in := []byte{1, 2, 3, 4, 5}
	out := PadTo32Bytes(in)
	if len(out) != 32 {
		t.Error("did not pad to 32 bytes")
	}
}

func TestSerializeAndDeserialize(t *testing.T) {
	/* generate new private public keypair */
	privkey, err := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	if err != nil {
		t.Fatal(err)
	}

	/* sign message */
	file, err := ioutil.ReadFile("../message.txt")
	if err != nil {
		t.Fatal(err)
	}
	msgHash := sha3.Sum256(file)

	/* secret index */
	s := 7

	/* generate keyring */
	keyring, err := GenNewKeyRing(17, privkey, s)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := Sign(msgHash, keyring, privkey, s)
	if err != nil {
		t.Fatal(err)
	}

	byteSig, err := sig.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	if len(byteSig) != 32*(3*sig.Size+4)+8 {
		t.Fatal("incorrect signature length")
	}

	marshal_sig, err := Deserialize(byteSig)
	if err != nil {
		t.Fatal(err)
	}

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
		t.Fatal("did not marshal to correct sig")
	}
}

func TestSerializeAndDeserializeAgain(t *testing.T) {
	privkey, err := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.ReadFile("../message.txt")
	if err != nil {
		t.Fatal(err)
	}
	msgHash := sha3.Sum256(file)

	s := 9
	keyring, err := GenNewKeyRing(100, privkey, s)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := Sign(msgHash, keyring, privkey, s)
	if err != nil {
		t.Fatal(err)
	}

	byteSig, err := sig.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	if len(byteSig) != 32*(3*sig.Size+4)+8 {
		t.Fatal("incorrect signature length")
	}

	marshal_sig, err := Deserialize(byteSig)
	if err != nil {
		t.Fatal(err)
	}

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
		t.Fatal("did not marshal to correct sig")
	}
}
