package ring

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestPadTo32Bytes(t *testing.T) {
	in := []byte{1, 2, 3, 4, 5}
	out := padTo32Bytes(in)
	require.Equal(t, 32, len(out))
}

func TestHashPoint(t *testing.T) {
	p, err := crypto.GenerateKey()
	require.NoError(t, err)

	ge := hashToCurve(p.Public().(*ecdsa.PublicKey))
	require.NotNil(t, ge)
}
