package main

import (
	"fmt"

	"github.com/athanorlabs/go-dleq/secp256k1"
	ring "github.com/noot/ring-go"
	"golang.org/x/crypto/sha3"
)

func main() {
	curve := secp256k1.NewCurve()
	privkey := curve.NewRandomScalar()
	msgHash := sha3.Sum256([]byte("helloworld"))
	const size = 10
	const idx = 7

	keyring, err := ring.NewKeyRing(curve, size, privkey, idx)
	if err != nil {
		panic(err)
	}

	sig, err := keyring.Sign(msgHash, privkey)
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
