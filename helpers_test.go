package ring

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashToCurveSecp256k1(t *testing.T) {
	curve := Secp256k1()
	privKey := curve.NewRandomScalar()
	p := hashToCurve(curve.ScalarBaseMul(privKey))
	require.NotNil(t, p)
}

func TestHashToCurveEd25519(t *testing.T) {
	curve := Ed25519()
	privKey := curve.NewRandomScalar()
	p := hashToCurve(curve.ScalarBaseMul(privKey))
	require.NotNil(t, p)
}
