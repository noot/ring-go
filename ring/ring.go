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
	Ring []*btcec.PublicKey
}

type RingSign struct {
	//X, Y *big.Int // parameters from key image.
	C, T []*big.Int
	I *btcec.PublicKey
}

func GenNewKeyRing() (*PublicKeyRing) {
	var keyring *PublicKeyRing
	return keyring
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
	//signature := sha256.Sum256(msg)
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
	//sig.X = image.X
	//sig.Y = image.Y
	sig.I = image

	// l is a large randomly generated prime.
	var l *big.Int

	var Lx, Ly, Rx, Ry []*big.Int
	var hash [32]byte

	fmt.Printf("privkey.D: ")
	fmt.Println(privkey.D)

	// insert signer's info at randomly generated index s
    _s, _ := rand.Int(*new(io.Reader), privkey.D) 
    s := _s.Int64() % int64(len(ring.Ring)) // some sketchy stuff with big.Ints
    
	for i := 0; i < len(ring.Ring) + 1; i ++ {
		if i == int(s) {
			//s := len(ring.Ring) + 1 // randomize this later
		    q_i, _ := rand.Int(*new(io.Reader), privkey.D)
			Lx[s].Mul(q_i, Gx)
			Ly[s].Mul(q_i, Gx)

			var bytesHash *big.Int 
		    hash = sha256.Sum256(pubkey.X.Bytes())
		    bytesHash.SetBytes(hash[:])
			Rx[s].Mul(q_i, bytesHash)
		    hash = sha256.Sum256(pubkey.Y.Bytes())
		    bytesHash.SetBytes(hash[:])
		    Ry[s].Mul(q_i, bytesHash)

		    sig.T[i] = q_i
		} else {
			pub_x := ring.Ring[i].X
			pub_y := ring.Ring[i].Y
			q_i, _ := rand.Int(*new(io.Reader), privkey.D)
			w_i, _ := rand.Int(*new(io.Reader), privkey.D)

			// c_i = w_i and t_i = q_i
			sig.C[i] = w_i
			sig.T[i] = q_i

			// calculate Lx[i]
			Lx[i].Mul(q_i, Gx)
			tmp.Mul(w_i,pub_x)
			Lx[i].Add(Lx[i], tmp)

			// calculate Ly[i]
	        Ly[i].Mul(q_i, Gy)
	        tmp.Mul(w_i,pub_y)
	        Ly[i].Add(Ly[i], tmp)

			// calculate Rx[i]
			hash = sha256.Sum256(pub_x.Bytes())
			var bytesHash *big.Int
			bytesHash.SetBytes(hash[:])
			Rx[i].Mul(q_i, bytesHash)
			tmp.Mul(w_i, image.X)
			Rx[i].Add(Rx[i], tmp)

			// calculate Ry[i]
	        hash = sha256.Sum256(pub_y.Bytes())
	        bytesHash.SetBytes(hash[:])
	        Ry[i].Mul(q_i, bytesHash)
	        tmp.Mul(w_i, image.Y)
	        Ry[i].Add(Ry[i], tmp)
    	}
	}

	cHash := msg

	for i := 0; i < len(ring.Ring) + 1; i ++ {
		// create hash
		cHash = append(cHash,Lx[i].Bytes()...)
		cHash = append(cHash,Ly[i].Bytes()...)
	}
	for i := 0; i < len(ring.Ring) + 1; i ++ {
		// create hash
		cHash = append(cHash,Rx[i].Bytes()...)
		cHash = append(cHash,Ry[i].Bytes()...)
	}

	// calculate c_s, t_s values
	// c_s = c - (c_1 + ... + c _n) % l
	// t_s = q_s - c_s * privkey.D % l

	// sum all c[i]
	var c_sum *big.Int
	for i := 0; i < len(ring.Ring) + 1; i ++ {
		if i != int(s) {
			c_sum.Add(c_sum,sig.C[i])
		}
	}

	// fix the modulo stuff here?
	var challenge *big.Int
	challenge.SetBytes(cHash)
	sig.C[s] = challenge.Sub(challenge, c_sum.Mod(c_sum, l))
	tmp.Mul(sig.C[s], privkey.D)
	tmp.Mod(tmp, l)
	sig.T[s].Sub(sig.T[s], tmp)

	return &sig, nil
}

func Ver() { 
	//Gx := btcec.S256().Gx
	//Gy := btcec.S256().Gy
}

func Link() { }
