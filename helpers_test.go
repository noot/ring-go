package ring

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashToCurveSecp256k1(t *testing.T) {
	curve := Secp256k1()
	privkey := curve.NewRandomScalar()
	p := hashToCurve(curve.ScalarBaseMul(privkey))
	require.NotNil(t, p)
}

func TestHashToCurveEd25519(t *testing.T) {
	curve := Ed25519()
	privkey := curve.NewRandomScalar()
	p := hashToCurve(curve.ScalarBaseMul(privkey))
	require.NotNil(t, p)
}
