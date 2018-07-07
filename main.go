package main

import (
	"fmt"
	"github.com/btcsuite/btcec"
	"github.com/btcsuite/chaincfg/chainhash"
	"github.com/noot/ring-go/ring"
//	"encoding/hex"
)

func main() {
	fmt.Println("starting ring-go...")
	fmt.Println("starting generation of keys...")

	ring.Gen();

	privkey, err := btcec.NewPrivateKey(btcec.S256());
//	pkBytes, err := hex.DecodeString("22a47fa09a223f2aa079edf85a7c2d4f8720ee63e502ee2869afab7de234b80c")
//	pkBytes, err := hex.DecodeString("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	if err != nil {
		fmt.Println(err)
		return
	}
//	privkey, pubkey := btcec.PrivKeyFromBytes(btcec.S256(), pkBytes)
	pubkey := privkey.PubKey()
	msg := "helloworld"
	msgHash := chainhash.DoubleHashB([]byte(msg))
	sig, err := privkey.Sign(msgHash)
	if err != nil {
		fmt.Println(err)
		return
	}

	verified := sig.Verify(msgHash, pubkey)
	fmt.Printf("verified? %v\n", verified)
}
