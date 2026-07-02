package ring

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/pokt-network/go-dleq/types"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

var (
	testMsg = sha3.Sum256([]byte("helloworld"))
)

func createSigWithCurve(t *testing.T, curve types.Curve, size, idx int) *RingSig {
	// instantiate private key
	privKey := curve.NewRandomScalar()

	// generate keyring
	keyring, err := NewKeyRing(curve, size, privKey, idx)
	require.NoError(t, err)

	// sign message
	sig, err := keyring.Sign(testMsg, privKey)
	require.NoError(t, err)
	return sig
}

func createSig(t *testing.T, size, idx int) *RingSig {
	return createSigWithCurve(t, Secp256k1(), size, idx)
}

func TestSign_Loop_Ed25519(t *testing.T) {
	maxSize := 100
	curve := Ed25519()
	for i := 2; i < maxSize; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(i)))
		require.NoError(t, err)
		sig := createSigWithCurve(t, curve, i, int(idx.Int64()))
		require.True(t, sig.Verify(testMsg))
	}
}

func TestSign_Loop_Secp256k1(t *testing.T) {
	maxSize := 100
	for i := 2; i < maxSize; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(i)))
		require.NoError(t, err)
		sig := createSig(t, i, int(idx.Int64()))
		require.True(t, sig.Verify(testMsg))
	}
}

func TestNewKeyRing(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	keyring, err := NewKeyRing(curve, 2, privKey, 0)
	require.NoError(t, err)
	require.NotNil(t, keyring)
	require.Equal(t, 2, len(keyring.pubkeys))
}

func TestNewKeyRing3(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	keyring, err := NewKeyRing(curve, 3, privKey, 1)
	require.NoError(t, err)
	require.NotNil(t, keyring)
	require.Equal(t, 3, len(keyring.pubkeys))
}

func TestNewKeyRing_IdxOutOfBounds(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	_, err := NewKeyRing(curve, 2, privKey, 3)
	require.Error(t, err)
}

func TestGenKeyRing(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	s := 0
	size := 3

	// generate some pubkeys for the keyring
	pubkeys := make([]types.Point, size)
	for i := 0; i < size; i++ {
		priv := curve.NewRandomScalar()
		pubkeys[i] = curve.ScalarBaseMul(priv)
	}

	keyring, err := NewKeyRingFromPublicKeys(curve, pubkeys, privKey, s)
	require.NoError(t, err)
	require.NotNil(t, keyring)
	require.Equal(t, size+1, keyring.Size())
	require.True(t, keyring.pubkeys[s].Equals(curve.ScalarBaseMul(privKey)))

	fixedKeys := make([]types.Point, size+1)
	fixedKeys[0] = curve.ScalarBaseMul(privKey)
	copy(fixedKeys[1:], pubkeys)
	keyring, err = NewFixedKeyRingFromPublicKeys(curve, fixedKeys)
	require.NoError(t, err)
	require.NotNil(t, keyring)
	for i := 0; i < size; i++ {
		require.True(t, keyring.pubkeys[i].Equals(fixedKeys[i]))
	}
}

func TestRing_Equals(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	keyring, err := NewKeyRing(curve, 10, privKey, 0)
	require.NoError(t, err)
	keyring2, err := NewKeyRing(curve, 10, privKey, 0)
	require.NoError(t, err)
	require.False(t, keyring.Equals(keyring2)) // NewKeyRing generates random pubkeys
	keyring3, err := NewFixedKeyRingFromPublicKeys(curve, keyring.pubkeys)
	require.NoError(t, err)
	require.True(t, keyring.Equals(keyring3))
}

func TestSig_RingEquals(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	keyring, err := NewKeyRing(curve, 10, privKey, 0)
	require.NoError(t, err)
	keyring2, err := NewKeyRing(curve, 10, privKey, 0)
	require.NoError(t, err)
	sig, err := keyring.Sign(testMsg, privKey)
	require.NoError(t, err)
	sig2, err := keyring2.Sign(testMsg, privKey)
	require.NoError(t, err)
	require.False(t, sig.Ring().Equals(keyring2))
	require.True(t, sig.Ring().Equals(keyring))
	require.False(t, sig2.Ring().Equals(keyring))
	require.True(t, sig2.Ring().Equals(keyring2))
}

func TestSign(t *testing.T) {
	createSig(t, 9, 0)
}

func TestSignAgain(t *testing.T) {
	createSig(t, 100, 17)
}

func TestVerify(t *testing.T) {
	sig := createSig(t, 5, 4)
	require.True(t, sig.Verify(testMsg))
}

func TestVerifyFalse(t *testing.T) {
	curve := Secp256k1()
	sig := createSig(t, 5, 2)

	// alter signature
	sig.c = curve.NewRandomScalar()
	require.False(t, sig.Verify(testMsg))
}

func TestVerifyWrongMessage(t *testing.T) {
	sig := createSig(t, 5, 1)
	fakeMsg := sha3.Sum256([]byte("noot"))
	require.False(t, sig.Verify(fakeMsg))
}

func TestLinkabilityTrue(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	msg1 := "helloworld"
	msgHash1 := sha3.Sum256([]byte(msg1))

	keyring1, err := NewKeyRing(curve, 2, privKey, 0)
	require.NoError(t, err)

	sig1, err := keyring1.Sign(msgHash1, privKey)
	require.NoError(t, err)

	msg2 := "hello world"
	msgHash2 := sha3.Sum256([]byte(msg2))

	keyring2, err := NewKeyRing(curve, 2, privKey, 0)
	require.NoError(t, err)

	sig2, err := keyring2.Sign(msgHash2, privKey)
	require.NoError(t, err)
	require.True(t, Link(sig1, sig2))
}

func TestLinkabilityTrue_imageSmallSubgroup(t *testing.T) {
	// test for the audit case where one image has a small subgroup
	// point added to it in an attempt to break the linkability property.
	// ensure that the two images can still be linked.

	// point from https://monero.stackexchange.com/questions/8671/what-are-the-hex-representations-of-the-small-subgroup-curve-points-on-ed25519
	subgroupPointBytes, err := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err)
	subgroupPoint, err := Ed25519().DecodeToPoint(subgroupPointBytes)
	require.NoError(t, err)

	curve := Ed25519()
	privkey := curve.NewRandomScalar()
	msg1 := "helloworld"
	msgHash1 := sha3.Sum256([]byte(msg1))

	keyring1, err := NewKeyRing(curve, 2, privkey, 0)
	require.NoError(t, err)

	sig1, err := keyring1.Sign(msgHash1, privkey)
	require.NoError(t, err)

	msg2 := "hello world"
	msgHash2 := sha3.Sum256([]byte(msg2))

	keyring2, err := NewKeyRing(curve, 2, privkey, 0)
	require.NoError(t, err)

	sig2, err := keyring2.Sign(msgHash2, privkey)
	require.NoError(t, err)
	sig2.image = sig2.image.Add(subgroupPoint)
	require.True(t, Link(sig1, sig2))
}

func TestLinkabilityFalse(t *testing.T) {
	curve := Secp256k1()
	privKey1 := curve.NewRandomScalar()
	msg1 := "helloworld"
	msgHash1 := sha3.Sum256([]byte(msg1))

	keyring1, err := NewKeyRing(curve, 2, privKey1, 0)
	require.NoError(t, err)

	sig1, err := keyring1.Sign(msgHash1, privKey1)
	require.NoError(t, err)

	privKey2 := curve.NewRandomScalar()
	msg2 := "hello world"
	msgHash2 := sha3.Sum256([]byte(msg2))

	keyring2, err := NewKeyRing(curve, 2, privKey2, 0)
	require.NoError(t, err)

	sig2, err := keyring2.Sign(msgHash2, privKey2)
	require.NoError(t, err)
	require.False(t, Link(sig1, sig2))
}

func TestSign_OneKey_Fails(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	keyring, err := NewKeyRing(curve, 1, privKey, 0)
	require.NoError(t, err)
	require.NotNil(t, keyring)
	require.Equal(t, 1, len(keyring.pubkeys))
	_, err = keyring.Sign(testMsg, privKey)
	require.Error(t, err)
	require.Equal(t, "size of ring less than two", err.Error())
}

// TestSignWithContext tests that SignWithContext produces valid signatures
func TestSignWithContext_Secp256k1(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	keyring, err := NewKeyRing(curve, 10, privKey, 3)
	require.NoError(t, err)

	ctx, err := keyring.NewSignerContext(privKey)
	require.NoError(t, err)
	require.NotNil(t, ctx)

	// Sign multiple messages with the same context
	for i := 0; i < 5; i++ {
		msg := sha3.Sum256([]byte("message" + string(rune(i))))
		sig, err := keyring.SignWithContext(msg, privKey, ctx)
		require.NoError(t, err)
		require.True(t, sig.Verify(msg))
	}
}

func TestSignWithContext_Ed25519(t *testing.T) {
	curve := Ed25519()
	privKey := curve.NewRandomScalar()
	keyring, err := NewKeyRing(curve, 10, privKey, 3)
	require.NoError(t, err)

	ctx, err := keyring.NewSignerContext(privKey)
	require.NoError(t, err)
	require.NotNil(t, ctx)

	for i := 0; i < 5; i++ {
		msg := sha3.Sum256([]byte("message" + string(rune(i))))
		sig, err := keyring.SignWithContext(msg, privKey, ctx)
		require.NoError(t, err)
		require.True(t, sig.Verify(msg))
	}
}

func TestSignWithContext_InvalidPrivKey(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	wrongPrivKey := curve.NewRandomScalar()
	keyring, err := NewKeyRing(curve, 10, privKey, 3)
	require.NoError(t, err)

	_, err = keyring.NewSignerContext(wrongPrivKey)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not correspond to any public key")
}

func TestSignWithContext_ZeroPrivKey(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	keyring, err := NewKeyRing(curve, 10, privKey, 3)
	require.NoError(t, err)

	zeroKey := curve.ScalarFromBytes([32]byte{})
	_, err = keyring.NewSignerContext(zeroKey)
	require.Error(t, err)
	require.Contains(t, err.Error(), "private key is zero")
}

func TestSignWithContext_Linkability(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()

	keyring1, err := NewKeyRing(curve, 5, privKey, 2)
	require.NoError(t, err)
	keyring2, err := NewKeyRing(curve, 5, privKey, 2)
	require.NoError(t, err)

	ctx1, err := keyring1.NewSignerContext(privKey)
	require.NoError(t, err)
	ctx2, err := keyring2.NewSignerContext(privKey)
	require.NoError(t, err)

	msg1 := sha3.Sum256([]byte("message1"))
	msg2 := sha3.Sum256([]byte("message2"))

	sig1, err := keyring1.SignWithContext(msg1, privKey, ctx1)
	require.NoError(t, err)
	sig2, err := keyring2.SignWithContext(msg2, privKey, ctx2)
	require.NoError(t, err)

	// Same private key should produce linkable signatures
	require.True(t, Link(sig1, sig2))
}

func TestSignWithContext_MatchesSign(t *testing.T) {
	// SignWithContext and Sign use different randomness, so signatures differ,
	// but both must verify and share the same key image (linkable).
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	keyring, err := NewKeyRing(curve, 10, privKey, 5)
	require.NoError(t, err)

	ctx, err := keyring.NewSignerContext(privKey)
	require.NoError(t, err)

	sig1, err := keyring.Sign(testMsg, privKey)
	require.NoError(t, err)

	sig2, err := keyring.SignWithContext(testMsg, privKey, ctx)
	require.NoError(t, err)

	require.True(t, sig1.Verify(testMsg))
	require.True(t, sig2.Verify(testMsg))
	require.True(t, Link(sig1, sig2))
}

// TestSignWithContext_KeyMismatchRejected checks that a context is not a way to
// sign with the wrong key: because the context holds no secret and the key is
// passed per call, a mismatched key is caught by the closing self-check.
func TestSignWithContext_KeyMismatchRejected(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	keyring, err := NewKeyRing(curve, 5, privKey, 2)
	require.NoError(t, err)

	ctx, err := keyring.NewSignerContext(privKey)
	require.NoError(t, err)

	// Sign with a key that does not match the context; self-check must reject it.
	wrongKey := curve.NewRandomScalar()
	_, err = keyring.SignWithContext(testMsg, wrongKey, ctx)
	require.Error(t, err)
}
