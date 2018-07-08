package ring

import (
	"fmt"
	"github.com/btcsuite/btcec"
	"encoding/hex"
	"crypto/sha256"
	"math/big"
//	"strings"
)

func GenKeysFromStr(str string) (*btcec.PrivateKey, *btcec.PublicKey) {
	pkBytes, err := hex.DecodeString(str)
	if err != nil  { return nil, nil }
	privkey, pubkey := btcec.PrivKeyFromBytes(btcec.S256(), pkBytes)
	return privkey, pubkey
}

func GenPrivkey() (*btcec.PrivateKey, error) {
        privkey, err := btcec.NewPrivateKey(btcec.S256());
        if err != nil {
                fmt.Println(err)
                return nil, err
        }
	return privkey, err
}

func GenPubkey(privkey *btcec.PrivateKey) (*btcec.PublicKey) {
	pubkey := privkey.PubKey()
	return pubkey
}

func GenKeyImage(privkey *btcec.PrivateKey) (*btcec.PublicKey) {
	// get pubkey of privkey
	pubkey := privkey.PubKey()

	// create new pubkey object image
	image := privkey.PubKey()

	// hash pubkey.X
        hashX := sha256.Sum256(pubkey.X.Bytes())
        image.X = new(big.Int).SetBytes( hashX[:] )
	// set image.X to hash of pubkey.X * privkey.D
	image.X.Mul(image.X, privkey.D)

	// hash pubkey.Y
	hashY := sha256.Sum256(pubkey.Y.Bytes())
	image.Y = new(big.Int).SetBytes( hashY[:] )
	// set image.Y to hash of pubkey.Y * privkey.D
	image.Y.Mul(image.Y, privkey.D)

	return image
}

func Sign() { }

func Ver() { }

func Link() { }
