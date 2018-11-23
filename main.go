package main

import (
	"fmt"
	"log"
	"io/ioutil"
	"github.com/noot/linkable-ring/ring"

 	//"golang.org/x/crypto/sha3"
 	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	fmt.Println("starting ring-go...")

	/* generate new private public keypair */
	privkey, err := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	if err != nil {
		log.Fatal(err)
	}

	/* sign message */
	file, err := ioutil.ReadFile("./message.txt")
	if err != nil {
		log.Fatal("could not read message from message.txt", err)
	}
	msgHash := sha3.Sum256(file)

	/* secret index */
	s := 7

	/* generate keyring */
	keyring := ring.GenNewKeyRing(17, privkey, s)

	/* sign */
	sig, err := ring.Sign(msgHash, keyring, privkey, s)
	if err != nil {
		log.Fatal(err)
	}

	byteSig := sig.ByteifySignature()

	fmt.Println("signature: ")
	fmt.Println(fmt.Sprintf("0x%x", byteSig))

	/* verify signature */
	ver := ring.Verify(sig)
	fmt.Println("verified? ", ver)
}