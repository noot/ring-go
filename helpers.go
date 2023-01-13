package ring

import (
	"filippo.io/edwards25519"
	dsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"

	"github.com/athanorlabs/go-dleq/ed25519"
	"github.com/athanorlabs/go-dleq/secp256k1"
	"github.com/athanorlabs/go-dleq/types"
)

func padTo32Bytes(in []byte) (out []byte) {
	out = append(out, in...)
	for {
		if len(out) == 32 {
			return
		}
		out = append([]byte{0}, out...)
	}
}

func hashToCurve(pk types.Point) types.Point {
	switch k := pk.(type) {
	case *ed25519.PointImpl:
		return hashToCurveEd25519(k)
	case *secp256k1.PointImpl:
		return hashToCurveSecp256k1(k)
	default:
		panic("unsupported point type")
	}
}

func hashToCurveEd25519(pk *ed25519.PointImpl) *ed25519.PointImpl {
	const safety = 128
	compressedKey := pk.Encode()
	hash := sha3.Sum256(compressedKey)

	for i := 0; i < safety; i++ {
		hash[31] |= byte(1 << 7)
		p, err := new(edwards25519.Point).SetBytes(hash[:])
		if err == nil && p.Equal(edwards25519.NewIdentityPoint()) == 0 {
			return ed25519.NewPoint(p)
		}

		hash = sha3.Sum256(hash[:])
	}

	panic("failed to hash ed25519 point to curve")
}

// based off https://github.com/particl/particl-core/blob/master/src/secp256k1/src/modules/mlsag/main_impl.h#L139
func hashToCurveSecp256k1(pk *secp256k1.PointImpl) *secp256k1.PointImpl {
	const safety = 128
	compressedKey := pk.Encode()
	hash := sha3.Sum256(compressedKey)
	fe := &dsecp256k1.FieldVal{}
	fe.SetBytes(&hash)
	maybeY := &dsecp256k1.FieldVal{}

	for i := 0; i < safety; i++ {
		ok := dsecp256k1.DecompressY(fe, false, maybeY)
		if ok {
			return secp256k1.NewPointFromCoordinates(*fe, *maybeY)
		}

		hash = sha3.Sum256(hash[:])
		fe.SetBytes(&hash)
	}

	return nil
}
