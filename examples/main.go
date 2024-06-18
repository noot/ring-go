package main

import (
	"fmt"

	"golang.org/x/crypto/sha3"

	ring "github.com/pokt-network/ring-go"
)

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

func main() {
	fmt.Println("using secp256k1...")
	signAndVerify(ring.Secp256k1())
	fmt.Println("using ed25519...")
	signAndVerify(ring.Ed25519())
}
