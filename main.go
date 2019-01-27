package main

import (
	"flag"
	"fmt"
	"log"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/noot/ring-go/ring"

 	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/accounts/keystore"
)

// prompt to generate a new public-private keypair, encrypt with a password, and save in ./keystore directory
func gen() {
	var password string
	fmt.Print("enter password to encrypt key: ")
	fmt.Scanln(&password)

	ks := keystore.NewKeyStore("./keystore", keystore.StandardScryptN, keystore.StandardScryptP)
	account, err := ks.NewAccount(password)

	if err != nil {
		log.Fatal(err)
	}

	_, err = ks.Export(account, password, password)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("output saved to ./keystore")
	os.Exit(0)
}

func main() {
	fmt.Println("welcome to ring-go...")

	// cli options
	genPtr := flag.Bool("gen", false, "generate a new public-private keypair")
	signPtr := flag.Bool("sign", false, "sign a message with a ring signature")
	verifyPtr := flag.Bool("verify", false, "verify a ring signature")

	// if no flags passed, display help
	if len(os.Args) < 2 {
		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.Parse()
	if *genPtr {
		gen()
	}

	if *signPtr {
		if len(os.Args) < 3 {
			fmt.Println("need to supply path to keys: ring-go --sign /path/to/keystore /path/to/pubkey1 /path/to/pubkey2 ...")
			os.Exit(0)
		}

		for i, arg := range os.Args {

		}
		
		fp, err := filepath.Abs(os.Args[2])
		if err != nil {
			log.Fatal("could not read key from ", os.Args[2], "\n", err)
		}

		file, err := ioutil.ReadFile(fp)
		if err != nil {
			log.Fatal("could not read key from ", fp, "\n", err)
		}

		keyStr := string(file)

		if strings.Compare(keyStr[0:2], "0x") == 0 {
			keyStr = keyStr[2:]
		}

		fmt.Println(keyStr)

		os.Exit(0)	}

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