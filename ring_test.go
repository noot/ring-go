package ring

import (
	"crypto/ecdsa"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func createSig(t *testing.T, size int, idx int) *RingSig {
	// instantiate private key
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	// generate keyring
	keyring, err := NewKeyRing(size, privkey, idx)
	require.NoError(t, err)

	// hash message
	msg := "helloworld"
	msgHash := sha3.Sum256([]byte(msg))

	// sign message
	sig, err := Sign(msgHash, keyring, privkey, idx)
	require.NoError(t, err)
	return sig
}

func TestNewKeyRing(t *testing.T) {
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	keyring, err := NewKeyRing(2, privkey, 0)
	require.NoError(t, err)
	require.NotNil(t, keyring)
	require.Equal(t, 2, len(keyring))
}

func TestNewKeyRing3(t *testing.T) {
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	keyring, err := NewKeyRing(3, privkey, 1)
	require.NoError(t, err)
	require.NotNil(t, keyring)
	require.Equal(t, 3, len(keyring))
}

func TestNewKeyRing_IdxOutOfBounds(t *testing.T) {
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	_, err := NewKeyRing(2, privkey, 3)
	require.Error(t, err)
}

func TestGenKeyRing(t *testing.T) {
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	s := 0
	size := 3

	// generate some pubkeys for the keyring
	pubkeys := make([]*ecdsa.PublicKey, size)
	for i := 0; i < size; i++ {
		priv, err := crypto.GenerateKey()
		if err != nil {
			t.Error(err)
		}

		pub := priv.Public()
		pubkeys[i] = pub.(*ecdsa.PublicKey)
	}

	keyring, err := GenKeyRing(pubkeys, privkey, s)
	require.NoError(t, err)
	require.NotNil(t, keyring)
	require.Equal(t, size+1, len(keyring))
	require.Equal(t, keyring[s].X, privkey.Public().(*ecdsa.PublicKey).X)
}

func TestGenKeyImage(t *testing.T) {
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	image := genKeyImage(privkey)
	require.NotNil(t, image)
}

func TestSign(t *testing.T) {
	createSig(t, 9, 0)
}

func TestSignAgain(t *testing.T) {
	createSig(t, 100, 17)
}

func TestVerify(t *testing.T) {
	sig := createSig(t, 5, 4)
	require.True(t, Verify(sig))
}

func TestVerifyFalse(t *testing.T) {
	sig := createSig(t, 5, 2)

	// alter signature
	curve := sig.Ring[0].Curve
	sig.C, _ = rand.Int(rand.Reader, curve.Params().P)
	require.False(t, Verify(sig))
}

func TestVerifyWrongMessage(t *testing.T) {
	sig := createSig(t, 5, 1)
	msgHash := sha3.Sum256([]byte("noot"))
	sig.M = msgHash
	require.False(t, Verify(sig))
}

func TestLinkabilityTrue(t *testing.T) {
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	msg1 := "helloworld"
	msgHash1 := sha3.Sum256([]byte(msg1))

	keyring1, err := NewKeyRing(2, privkey, 0)
	require.NoError(t, err)

	sig1, err := Sign(msgHash1, keyring1, privkey, 0)
	require.NoError(t, err)

	msg2 := "hello world"
	msgHash2 := sha3.Sum256([]byte(msg2))

	keyring2, err := NewKeyRing(2, privkey, 0)
	require.NoError(t, err)

	sig2, err := Sign(msgHash2, keyring2, privkey, 0)
	require.NoError(t, err)
	require.True(t, Link(sig1, sig2))
}

func TestLinkabilityFalse(t *testing.T) {
	privkey1, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	msg1 := "helloworld"
	msgHash1 := sha3.Sum256([]byte(msg1))

	keyring1, err := NewKeyRing(2, privkey1, 0)
	require.NoError(t, err)

	sig1, err := Sign(msgHash1, keyring1, privkey1, 0)
	require.NoError(t, err)

	privkey2, _ := crypto.HexToECDSA("01ad23ee4fbabbcf31dda1270154a623f5f7c07433193ff07395b33ac5bf2bea")
	msg2 := "hello world"
	msgHash2 := sha3.Sum256([]byte(msg2))

	keyring2, err := NewKeyRing(2, privkey2, 0)
	require.NoError(t, err)

	sig2, err := Sign(msgHash2, keyring2, privkey2, 0)
	require.NoError(t, err)
	require.False(t, Link(sig1, sig2))
}

func testSerializeAndDeserialize(t *testing.T, size, idx int) {
	privkey, err := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	require.NoError(t, err)

	msgHash := sha3.Sum256([]byte("helloworld"))

	keyring, err := NewKeyRing(size, privkey, idx)
	require.NoError(t, err)

	sig, err := Sign(msgHash, keyring, privkey, idx)
	require.NoError(t, err)

	byteSig, err := sig.Serialize()
	require.NoError(t, err)

	expectedLength := 32*(3*sig.Size+4) + 8
	require.Equal(t, expectedLength, len(byteSig))

	res, err := Deserialize(byteSig)
	require.NoError(t, err)

	ok := reflect.DeepEqual(res.S, sig.S) &&
		reflect.DeepEqual(res.Size, sig.Size) &&
		reflect.DeepEqual(res.C, sig.C) &&
		reflect.DeepEqual(res.M, sig.M) &&
		reflect.DeepEqual(res.I, sig.I)

	for i := 0; i < sig.Size; i++ {
		ok = ok && reflect.DeepEqual(res.Ring[i].X, sig.Ring[i].X)
		ok = ok && reflect.DeepEqual(res.Ring[i].Y, sig.Ring[i].Y)
	}

	require.True(t, ok)
}

func TestSerializeAndDeserialize(t *testing.T) {
	testSerializeAndDeserialize(t, 17, 7)
}

func TestSerializeAndDeserializeAgain(t *testing.T) {
	testSerializeAndDeserialize(t, 100, 9)
}
