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

	msgHash := sha3.Sum256([]byte("helloworld"))
	const size = 16
	const idx = 7

	keyring, err := ring.NewKeyRing(size, privkey, idx)
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
