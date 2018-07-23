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
	privkey, _ := ring.GenKeysFromStr("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")

	/* generate public key image */
	//image := ring.GenKeyImage(privkey)
	//fmt.Println(image)

	/* sign message */
	msg := "helloworld"
	msgHashArr := sha256.Sum256([]byte(msg))
	msgHash := msgHashArr[:]

	keyring := ring.GenNewKeyRing(5, privkey)
	//key1, _ := ring.GenPrivkey()
	//pubkey1 := key1.PubKey()
	//key2, _ := ring.GenPrivkey()
	//pubkey2 := ring.GenPubkey(key2)

	//keyring.Ring = append(keyring.Ring, pubkey1)

	//sig, err := privkey.Sign(msgHash, keyring, privkey)
	sig, err := ring.Sign(msgHash, keyring, privkey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("signature: ")
	fmt.Println(sig.C)
	fmt.Println(sig.T)
	fmt.Println(sig.I)

	//verified := sig.Verify(msgHash, pubkey)
	//fmt.Printf("verified? %v\n", verified)
}
