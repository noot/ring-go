package ring

import (
	"fmt"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"github.com/athanorlabs/go-dleq/ed25519"
	"github.com/athanorlabs/go-dleq/secp256k1"
	"github.com/athanorlabs/go-dleq/types"
	dsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

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

// hashToCurveEd25519 hashes a point and attempts to set the hash to a point.
// It's effectively hashing to a y-coordinate, as an encoded ed25519 point
// is the y-coordinate with the highest bit set for whether x is positive/negative.
// It repeatedly hashes the hash until it finds a valid point.
func hashToCurveEd25519(pk *ed25519.PointImpl) *ed25519.PointImpl {
	const safety = 128
	compressedKey := pk.Encode()
	hash := sha3.Sum256(compressedKey)

	for i := 0; i < safety; i++ {
		point, err := new(edwards25519.Point).SetBytes(hash[:])
		if err == nil {
			return ed25519.NewPoint(
				new(edwards25519.Point).MultByCofactor(point),
			)
		}

		hash = sha3.Sum256(hash[:])
	}

	panic("failed to hash ed25519 point to curve")
}

// hashToCurveEd25519Alt hashes a point to a x-coordinate and attempts to find a
// corresponding y-coordinate. It repeatedly hashes the hash until it finds a valid point.
//
// this is slightly slower than hashToCurveEd25519.
// I *think* they're effectively the same security-wise, as this impl hashes to an x-coordinate,
// and the above hashes to a y-coordinate.
func hashToCurveEd25519Alt(pk *ed25519.PointImpl) *ed25519.PointImpl { //nolint:deadcode,unused
	const safety = 128
	compressedKey := pk.Encode()
	hash := sha3.Sum512(compressedKey)

	for i := 0; i < safety; i++ {
		x, err := new(field.Element).SetWideBytes(hash[:])
		if err != nil {
			panic(err) // this shouldn't happen
		}

		point, err := decompressYEd25519(x)
		if err == nil {
			return point
		}

		hash = sha3.Sum512(hash[:])
	}

	panic("failed to hash ed25519 point to curve")
}

// see https://crypto.stackexchange.com/questions/101961/find-ed25519-y-coordinate-from-x-coordinate
func decompressYEd25519(x *field.Element) (*ed25519.PointImpl, error) { //nolint:unused
	// y^2 = (1 + x^2) / (1 + d*(x^2)) where d = 121665/121666
	one := new(field.Element).One()
	xSq := new(field.Element).Square(x)

	// d*x^2
	dd := new(field.Element).Mult32(one, 121666)
	dd = new(field.Element).Invert(dd)
	dxSq := new(field.Element).Mult32(xSq, 121665)
	dxSq = new(field.Element).Multiply(dxSq, dd)

	// (1 + d*x^2)^-1
	denom := new(field.Element).Add(one, dxSq)
	denom = new(field.Element).Invert(denom)

	// 1 + x^2
	num := new(field.Element).Add(one, xSq)

	// find y
	y, wasSquare := new(field.Element).SqrtRatio(num, denom)
	if wasSquare != 1 {
		return nil, fmt.Errorf("failed to decompress Y")
	}

	var out [32]byte
	copy(out[:], y.Bytes())
	out[31] |= byte(x.IsNegative() << 7)

	point, err := new(edwards25519.Point).SetBytes(out[:])
	if err != nil {
		return nil, err
	}

	return ed25519.NewPoint(
		new(edwards25519.Point).MultByCofactor(point),
	), nil
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
