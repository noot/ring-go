package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/noot/ring-go/ring"

	//"github.com/ethereum/go-ethereum/common"
 	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/crypto"
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

	fp, err := filepath.Abs(fmt.Sprintf("./keystore", time.Now().Unix()))
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
		if len(os.Args) < 2 {
			fmt.Println("need to supply path to public key directory: ring-go --sign /path/to/pubkey/dir")
			fmt.Println("optionally specify what keystore account to sign with: ring-go --sign /path/to/pubkey/dir [/path/to/privkey.priv]")
			os.Exit(0)
		}

		// read public keys and put them in a ring
		fp, err := filepath.Abs(os.Args[2])
		if err != nil {
			log.Fatal("could not read key from ", os.Args[2], "\n", err)
		}	    
		files, err := ioutil.ReadDir(fp)
	    if err != nil {
	        log.Fatal(err)
	    }

	 	ring := make([]*ecdsa.PublicKey, len(files))

	    for i, file := range files {
	    	fmt.Println(file.Name())

	    	fp, err = filepath.Abs(fmt.Sprintf("%s/%s", os.Args[2], file.Name()))
	    	key, err := ioutil.ReadFile(fp)
			if err != nil {
				log.Fatal("could not read key from ", fp, "\n", err)
			}

			keyStr := string(key)
			fmt.Println(keyStr)

			if strings.Compare(keyStr[0:2], "0x") == 0 {
				keyStr = keyStr[2:66]
			}

			keyBytes, err := hex.DecodeString(keyStr[0:64])
			if err != nil {
				log.Fatal("could not decode key string: ", err)
			}
			
			pub, err := crypto.UnmarshalPubkey(keyBytes)
	    	ring[i] = pub
	    }
		
		// // read encrypted secret key
		// ks := keystore.NewKeyStore("./keystore", keystore.StandardScryptN, keystore.StandardScryptP)

		// var account accounts.Account
		// if len(os.Args) == 5 {
		// 	address := common.HexToAddress(os.Args[3])
		// 	acc := new(accounts.Account)
		// 	acc.Address = address
		// 	if !ks.HasAddress(address) {
		// 		log.Fatal("could not find account %s in keystore", os.Args[3])
		// 	} else {
		// 		account, err = ks.Find(*acc)
		// 	}
		// } else {
		// 	if len(ks.Accounts()) == 0 {
		// 		log.Fatal("no accounts in keystore")
		// 	}
		// 	// if account unspecified, use first keystore account
		// 	account = ks.Accounts()[0]		
		// }

		// var password string
		// fmt.Print(fmt.Sprintf("enter password to decrypt account %s: ", account.Address.Hex()))
		// fmt.Scanln(&password)
		
		// for err = nil; err != nil; err = ks.Unlock(account, password) {
		// 	fmt.Print("wrong password!\nenter password to encrypt key: ")
		// 	fmt.Scanln(&password)			
		// }


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