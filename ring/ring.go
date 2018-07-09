package ring

import (
	"fmt"
	"io"
	"github.com/btcsuite/btcec"
	"encoding/hex"
	"crypto/sha256"
	"math/big"
	"crypto/rand"
//	"log"
)

type PublicKeyRing struct {
	Ring []btcec.PublicKey
}

type RingSign struct {
	X, Y *big.Int
	C, T *big.Int
}

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

// create ring signature from list of public keys given
// inputs
// msg: byte array, message to be signed
// ring: array of PublicKeys to be included in the ring
// privkey: PrivateKey of signer
func Sign(msg []byte, ring *PublicKeyRing, privkey *btcec.PrivateKey) (*RingSign, error) {
	signature := sha256.Sum256(msg)
	Gx := btcec.S256().Gx
	Gy := btcec.S256().Gy
	var tmp *big.Int

	// wish to create challenge c = hash(m,L_1,..,L_n,R_1,..,R_n)
	// with L_i =  i = s ? q_i*G : q_i*G + w_i*P_i
	// and R_i = i = s ? q_i*hash(P_i) : q_i*hash(P_i) + w_i*I
	// where s is the signer's secret index in the ring and
	// q_i and w_i are random numbers
	image := GenKeyImage(privkey)
	pubkey := privkey.PubKey()
	var sig RingSign
	sig.X = image.X
	sig.Y = image.Y

	var Lx, Ly, Rx, Ry []*big.Int
	for i := 0; i < len(ring.Ring); i ++ {
		pub_x := ring.Ring[i].X
		pub_y := ring.Ring[i].Y
		q_i, _ := rand.Int(*new(io.Reader), privkey.D)
		w_i, _ := rand.Int(*new(io.Reader), privkey.D)

		// calculate Lx[i]
		Lx[i].Mul(q_i, Gx)
		tmp.Mul(w_i,pub_x)
		Lx[i].Add(Lx[i], tmp)

		// calculate Ly[i]
		// calculate Rx[i]
		// calculate Ry[i]
	}

	return &sig, nil
}

func Ver() { }

func Link() { }
