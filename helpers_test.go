package ring

import (
	"testing"

	"github.com/athanorlabs/go-dleq/secp256k1"
	"github.com/stretchr/testify/require"
)

func TestPadTo32Bytes(t *testing.T) {
	in := []byte{1, 2, 3, 4, 5}
	out := padTo32Bytes(in)
	require.Equal(t, 32, len(out))
}

func TestHashToCurveSecp256k1(t *testing.T) {
	curve := secp256k1.NewCurve()
	privkey := curve.NewRandomScalar()
	ge := hashToCurveSecp256k1(curve.ScalarBaseMul(privkey).(*secp256k1.PointImpl))
	require.NotNil(t, ge)
}
