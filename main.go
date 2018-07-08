package main

import (
	"fmt"
	"log"
	"crypto/sha256"
	//"github.com/btcsuite/btcec"
	"github.com/noot/ring-go/ring"
	//"encoding/hex"
)

func main() {
	fmt.Println("starting ring-go...")
	fmt.Println("starting generation of keys...")

	/* generate new private public keypair */
	//privkey, err := ring.GenPrivkey()
	privkey, pubkey := ring.GenKeysFromStr("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	/*if err != nil {
		log.Fatal(err)
	}*/
	//pubkey := privkey.PubKey()

	/* generate public key image */
	image := ring.GenKeyImage(privkey)
	fmt.Println(image)

	/* sign message */
	msg := "helloworld"
	msgHashArr := sha256.Sum256([]byte(msg))
	msgHash := msgHashArr[:]
	sig, err := privkey.Sign(msgHash)
	if err != nil {
		log.Fatal(err)
	}

	verified := sig.Verify(msgHash, pubkey)
	fmt.Printf("verified? %v\n", verified)
}
