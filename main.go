package main

import (
	"fmt"
	"log"
	//"encoding/hex"
	"io/ioutil"
	"github.com/noot/ring-go/ring"

 	"golang.org/x/crypto/sha3"

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
	msgHashArr := sha3.Sum256(file)
	msgHash := msgHashArr[:]

	/* secret index */
	s := 17

	/* generate keyring */
	keyring := ring.GenNewKeyRing(33, privkey, s)

	/* sign */
	sig, err := ring.Sign(msgHash, keyring, privkey, s)
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