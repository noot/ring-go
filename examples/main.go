package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	ring "github.com/noot/ring-go"
	"golang.org/x/crypto/sha3"
)

func main() {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}

	msg := "helloworld"
	msgHash := sha3.Sum256([]byte(msg))
	const size = 16
	const idx = 7

	keyring, err := ring.GenNewKeyRing(size, privkey, idx)
	if err != nil {
		panic(err)
	}

	sig, err := ring.Sign(msgHash, keyring, privkey, idx)
	if err != nil {
		panic(err)
	}

	ok := ring.Verify(sig)
	if !ok {
		fmt.Println("failed to verify :(")
	}

	fmt.Println("verified signature!")
}
