package main

import (
	"fmt"

	"golang.org/x/crypto/sha3"

	ring "github.com/pokt-network/ring-go"
)

// signAndVerify uses the default Sign/Verify path.
//
// This path is CONSENSUS-SAFE: the amount of work it does is fixed and
// independent of any cache or call history, so it is deterministic across
// nodes. Use it on-chain / in gas-metered code.
func signAndVerify(curve ring.Curve) {
	privKey := curve.NewRandomScalar()
	msgHash := sha3.Sum256([]byte("helloworld"))

	// size of the public key ring (anonymity set)
	const size = 16

	// our key's secret index within the set
	const idx = 7

	keyring, err := ring.NewKeyRing(curve, size, privKey, idx)
	if err != nil {
		panic(err)
	}

	sig, err := keyring.Sign(msgHash, privKey)
	if err != nil {
		panic(err)
	}

	ok := sig.Verify(msgHash)
	if !ok {
		fmt.Println("failed to verify :(")
		return
	}

	fmt.Println("verified signature!")
}

// signManyWithContext uses the SignerContext / SignWithContext fast path.
//
// A SignerContext pre-computes, once, the values that are constant across
// messages for a given (private key, ring): the signer's public key, key image,
// and the hash-to-curve of every ring member. Signing many messages then reuses
// that work instead of recomputing it each time. The context holds NO secret —
// the private key is passed per call, just like Sign.
//
// WARNING: this is an OFF-CHAIN optimization. Because it does less work than the
// plain path, its cost is not identical across calls/nodes. Do NOT use it on
// consensus-critical or gas-metered paths — use Sign there. Verification of the
// resulting signatures is unchanged (sig.Verify).
func signManyWithContext(curve ring.Curve) {
	privKey := curve.NewRandomScalar()

	const size = 16
	const idx = 7

	keyring, err := ring.NewKeyRing(curve, size, privKey, idx)
	if err != nil {
		panic(err)
	}

	// build the context once...
	ctx, err := keyring.NewSignerContext(privKey)
	if err != nil {
		panic(err)
	}
	// optional: skip the closing self-checks for extra speed (off-chain only).
	ctx.SkipSelfCheck = true

	// ...then reuse it to sign many messages.
	for i := 0; i < 3; i++ {
		msgHash := sha3.Sum256([]byte(fmt.Sprintf("message-%d", i)))
		sig, err := keyring.SignWithContext(msgHash, privKey, ctx)
		if err != nil {
			panic(err)
		}
		if !sig.Verify(msgHash) {
			fmt.Println("failed to verify :(")
			return
		}
	}

	fmt.Println("verified all context-signed signatures!")
}

func main() {
	// Default path — consensus-safe, use on-chain.
	fmt.Println("Sign/Verify (consensus-safe):")
	fmt.Println("  using secp256k1...")
	signAndVerify(ring.Secp256k1())
	fmt.Println("  using ed25519...")
	signAndVerify(ring.Ed25519())

	// Fast path — off-chain only, reuses a SignerContext across messages.
	fmt.Println("SignWithContext (off-chain fast path):")
	fmt.Println("  using secp256k1...")
	signManyWithContext(ring.Secp256k1())
	fmt.Println("  using ed25519...")
	signManyWithContext(ring.Ed25519())
}
