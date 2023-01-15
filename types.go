package ring

import (
	"github.com/athanorlabs/go-dleq/ed25519"
	"github.com/athanorlabs/go-dleq/secp256k1"
	"github.com/athanorlabs/go-dleq/types"
)

type (
	// Curve represents an elliptic curve that can be used for signing.
	Curve = types.Curve
)

// Ed25519 returns a new ed25519 curve instance.
func Ed25519() types.Curve {
	return ed25519.NewCurve()
}

// Secp256k1 returns a new secp256k1 curve instance
func Secp256k1() types.Curve {
	return secp256k1.NewCurve()
}
