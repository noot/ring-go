package main

import (
	"flag"
	"fmt"
	"log"
	"io/ioutil"
	"os"

	"github.com/noot/ring-go/ring"

 	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	fmt.Println("welcome to ring-go...")

	// cli options
	genPtr := flag.Bool("gen", false, "generate a new public-private keypair")
	importPtr := flag.Bool("import", false, "import a public key")
	signPtr := flag.Bool("sign", false, "sign a message with a ring signature")
	verifyPtr := flag.Bool("verify", false, "verify a ring signature")

	// if no flags passed, display help
	if len(os.Args) < 2 {
		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.Parse()
	if *genPtr {
		os.Exit(0)
	}

	if *importPtr {
		os.Exit(0)
	}

	if *signPtr {
		os.Exit(0)
	}

	if *verifyPtr {
		os.Exit(0)
	}

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
	keyring := ring.GenNewKeyRing(12, privkey, s)

	/* sign */
	sig, err := ring.Sign(msgHash, keyring, privkey, s)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(sig.S)

	byteSig := sig.SerializeSignature()

	fmt.Println("signature: ")
	fmt.Println(fmt.Sprintf("0x%x", byteSig))

	/* verify signature */
	ver := ring.Verify(sig)
	fmt.Println("verified? ", ver)
}