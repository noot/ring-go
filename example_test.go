package ring_test

import (
	"fmt"

	ring "github.com/pokt-network/ring-go"
	"golang.org/x/crypto/sha3"
)

// Example_signAndVerify shows the default signing path.
//
// Sign/Verify are CONSENSUS-SAFE: they perform a fixed amount of work
// independent of any cache or call history, so their cost is deterministic
// across nodes. Use this path on-chain / in gas-metered code.
func Example_signAndVerify() {
	curve := ring.Secp256k1()
	privKey := curve.NewRandomScalar()

	// ring of 16 keys; ours sits at secret index 7.
	keyring, err := ring.NewKeyRing(curve, 16, privKey, 7)
	if err != nil {
		panic(err)
	}

	msg := sha3.Sum256([]byte("hello"))
	sig, err := keyring.Sign(msg, privKey)
	if err != nil {
		panic(err)
	}

	fmt.Println(sig.Verify(msg))
	// Output: true
}

// ExampleRing_SignWithContext shows the off-chain fast path: build a
// SignerContext once (which pre-computes the signer's key image and the
// hash-to-curve of every ring member), then reuse it to sign many messages
// without redoing that work.
//
// WARNING: this path does less work than Sign, so its cost is not identical
// across calls/nodes. Do NOT use it on consensus-critical or gas-metered
// paths — use Sign there. Verification is unchanged.
func ExampleRing_SignWithContext() {
	curve := ring.Secp256k1()
	privKey := curve.NewRandomScalar()

	keyring, err := ring.NewKeyRing(curve, 16, privKey, 7)
	if err != nil {
		panic(err)
	}

	// Pre-compute once.
	ctx, err := keyring.NewSignerContext(privKey)
	if err != nil {
		panic(err)
	}
	ctx.SkipSelfCheck = true // optional extra speed, off-chain only

	// Reuse across many messages.
	allVerified := true
	for i := 0; i < 3; i++ {
		msg := sha3.Sum256([]byte(fmt.Sprintf("message-%d", i)))
		sig, err := keyring.SignWithContext(msg, privKey, ctx)
		if err != nil {
			panic(err)
		}
		allVerified = allVerified && sig.Verify(msg)
	}

	fmt.Println(allVerified)
	// Output: true
}
