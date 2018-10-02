package main

import (
	"fmt"
	"log"
	"crypto/sha256"
	"github.com/noot/ring-go/ring"
	//"encoding/hex"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	fmt.Println("starting ring-go...")
	fmt.Println("starting generation of keys...")

	/* generate new private public keypair */
	//privkey, err := ring.GenPrivkey()
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* generate public key image */
	//image := ring.GenKeyImage(privkey)
	//fmt.Println(image)

	/* sign message */
	msg := "helloworld"
	msgHashArr := sha256.Sum256([]byte(msg))
	msgHash := msgHashArr[:]

	/* generate keyring */
	keyring := ring.GenNewKeyRing(2, privkey)
	fmt.Println(keyring)
	
	sig, err := ring.Sign(msgHash, keyring, privkey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("signature: ")
	fmt.Println(sig.S)
	fmt.Println(sig.C)

	// /* verify signature */
	// ver, err := ring.Verify(msgHash, sig)
	// if err != nil { log.Fatal(err) }
	// fmt.Println("verified? ", ver)

	//verified := sig.Verify(msgHash, pubkey)
	//fmt.Printf("verified? %v\n", verified)
}
