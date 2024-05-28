package ring

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func testSerializeAndDeserialize(t *testing.T, curve Curve, size, idx int) {
	privKey := curve.NewRandomScalar()
	msgHash := sha3.Sum256([]byte("helloworld"))

	keyring, err := NewKeyRing(curve, size, privKey, idx)
	require.NoError(t, err)

	sig, err := Sign(msgHash, keyring, privKey, idx)
	require.NoError(t, err)

	byteSig, err := sig.Serialize()
	require.NoError(t, err)

	res := new(RingSig)
	err = res.Deserialize(curve, byteSig)
	require.NoError(t, err)
	require.Equal(t, sig.ring.Size(), res.ring.Size())
	require.Equal(t, sig.c, res.c)
	require.True(t, sig.image.Equals(res.image))
	require.Equal(t, sig.s, res.s)

	for i := 0; i < sig.ring.Size(); i++ {
		require.True(t, res.ring.pubkeys[i].Equals(sig.ring.pubkeys[i]))
	}
}

func TestSerializeAndDeserialize_Secp256k1(t *testing.T) {
	maxSize := 16
	curve := Secp256k1()
	for i := 2; i < maxSize; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(i)))
		require.NoError(t, err)
		testSerializeAndDeserialize(t, curve, i, int(idx.Int64()))
	}
}

func TestSerializeAndDeserialize_Ed25519(t *testing.T) {
	maxSize := 16
	curve := Ed25519()
	for i := 2; i < maxSize; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(i)))
		require.NoError(t, err)
		testSerializeAndDeserialize(t, curve, i, int(idx.Int64()))
	}
}
