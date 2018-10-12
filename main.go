package main

import (
	"fmt"
	"log"
	"github.com/noot/ring-go/ring"

 	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	fmt.Println("starting ring-go...")
	fmt.Println("starting generation of keys...")

	/* generate new private public keypair */
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* sign message */
	msg := "helloworld"
	msgHashArr := sha3.Sum256([]byte(msg))
	msgHash := msgHashArr[:]

	/* generate keyring */
	keyring := ring.GenNewKeyRing(17, privkey)

	/* sign */
	sig, err := ring.Sign(msgHash, keyring, privkey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("signature: ")
	fmt.Println(sig.S)
	fmt.Println(sig.C)

	/* verify signature */
	ver, err := ring.Verify(sig)
	if err != nil { log.Fatal(err) }
	fmt.Println("verified? ", ver)
}