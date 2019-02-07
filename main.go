package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/noot/ring-go/ring"

	//"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	//"github.com/ethereum/go-ethereum/accounts"
	//"github.com/ethereum/go-ethereum/accounts/keystore"
)

// prompt to generate a new public-private keypair and save in ./keystore directory
func gen() {
	priv, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	pub := priv.Public().(*ecdsa.PublicKey)

	fp, err := filepath.Abs("./keystore")
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		os.Mkdir("./keystore", os.ModePerm)
	}

	fp, err = filepath.Abs(fmt.Sprintf("./keystore/%d.priv", time.Now().Unix()))
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(fp, []byte(fmt.Sprintf("%x", priv.D.Bytes())), 0644)
	if err != nil {
		log.Fatal(err)
	}

	fp, err = filepath.Abs(fmt.Sprintf("./keystore/%d.pub", time.Now().Unix()))
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(fp, []byte(fmt.Sprintf("%x", (append(pub.X.Bytes(), pub.Y.Bytes()...)))), 0644)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("output saved to ./keystore")
	os.Exit(0)
}

func sign() {
	// read public keys and put them in a ring
	fp, err := filepath.Abs(os.Args[2])
	if err != nil {
		log.Fatal("could not read key from ", os.Args[2], "\n", err)
	}
	files, err := ioutil.ReadDir(fp)
	if err != nil {
		log.Fatal(err)
	}

	pubkeys := make([]*ecdsa.PublicKey, len(files))

	for i, file := range files {
		fmt.Print(file.Name(), ":")

		fp, err = filepath.Abs(fmt.Sprintf("%s/%s", os.Args[2], file.Name()))
		key, err := ioutil.ReadFile(fp)
		if err != nil {
			log.Fatal("could not read key from ", fp, "\n", err)
		}

		keyStr := string(key)

		if strings.Compare(keyStr[0:2], "0x") == 0 {
			keyStr = keyStr[2:66]
		}

		fmt.Println(keyStr)

		keyBytes, err := hex.DecodeString(keyStr[0:64])
		if err != nil {
			log.Fatal("could not decode key string: ", err)
		}

		pub, err := crypto.UnmarshalPubkey(keyBytes)
		pubkeys[i] = pub
	}

	// handle secret key and generate ring of pubkeys
	fp, err = filepath.Abs(os.Args[3])
	privBytes, err := ioutil.ReadFile(fp)
	if err != nil {
		log.Fatal("could not read key from ", fp, "\n", err)
	}

	privHex := fmt.Sprintf("%s\n", privBytes)
	fmt.Printf(privHex)

	priv, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	_, success := priv.D.SetString(privHex, 16)
	if !success {
		log.Fatal("could not parse private key")
	}
	//priv.PublicKey.Curve = crypto.S256()

	fmt.Printf("secret.pub:%x\n", priv.D)

	s, err := rand.Int(rand.Reader, new(big.Int).SetInt64(int64(len(pubkeys))))
	if err != nil {
		log.Fatal(err)
	}

	r, err := ring.GenKeyRing(pubkeys, priv, int(s.Int64()))
	if err != nil {
		log.Fatal(err)
	}

	// read message and hash
	fp, err = filepath.Abs(os.Args[4])
	msgBytes, err := ioutil.ReadFile(fp)
	if err != nil {
		log.Fatal("could not read key from ", fp, "\n", err)
	}

	msgHash := sha3.Sum256(msgBytes)

	// all good, let's sign
	sig, err := ring.Sign(msgHash, r, priv, int(s.Int64()))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sig)
	os.Exit(0)
}

func main() {
	fmt.Println("welcome to ring-go...")

	// cli options
	genPtr := flag.Bool("gen", false, "generate a new public-private keypair")
	signPtr := flag.Bool("sign", false, "sign a message with a ring signature")
	//messagePtr := flag.String("m", "", "path to message file")
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
		if len(os.Args) < 2 {
			fmt.Println("need to supply path to public key directory: ring-go --sign /path/to/pubkey/dir /path/to/privkey.priv message.txt")
			os.Exit(0)
		}

		if len(os.Args) < 3 {
			fmt.Println("need to supply path to private key file: ring-go --sign /path/to/pubkey/dir /path/to/privkey.priv message.txt")
			os.Exit(0)
		}

		if len(os.Args) < 4 {
			fmt.Println("need to supply path to message file: ring-go --sign /path/to/pubkey/dir /path/to/privkey.priv message.txt")
			os.Exit(0)
		}

		sign()
	}

	if *verifyPtr {
		os.Exit(0)
	}

	/* generate new private public keypair */
	// privkey, err := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// /* sign message */
	// file, err := ioutil.ReadFile("./message.txt")
	// if err != nil {
	// 	log.Fatal("could not read message from message.txt", err)
	// }
	// msgHash := sha3.Sum256(file)

	// /* secret index */
	// s := 7

	//  generate keyring 
	// keyring := ring.GenNewKeyRing(12, privkey, s)

	// /* sign */
	// sig, err := ring.Sign(msgHash, keyring, privkey, s)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Println(sig.S)

	// byteSig := sig.SerializeSignature()

	// fmt.Println("signature: ")
	// fmt.Println(fmt.Sprintf("0x%x", byteSig))

	// /* verify signature */
	// ver := ring.Verify(sig)
	// fmt.Println("verified? ", ver)
}
