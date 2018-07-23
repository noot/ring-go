package ring

import (
	"fmt"
	//"io"
	"github.com/btcsuite/btcec"
	"encoding/hex"
	"crypto/sha256"
	"math/big"
	"crypto/rand"
	//"crypto/elliptic"
	//"log"
)

type PrivateKey struct {
	k []byte
}

type PublicKey struct {
	X, Y *big.Int
}

type PublicKeyRing struct {
	Ring []*btcec.PublicKey
}

type RingSign struct {
	//X, Y *big.Int // parameters from key image.
	C, T []*big.Int
	I *btcec.PublicKey
}

func GenNewKeyRing(size int, privkey *btcec.PrivateKey) (PublicKeyRing) {
	var ring []*btcec.PublicKey

	pubkey := privkey.PubKey()

	l, _ := rand.Prime(rand.Reader, 1024)
	s := new(big.Int)
	len := new(big.Int)
	len.SetInt64(int64(size))
	s.Mod(l, len)
	fmt.Println(s)

	for i := 0; i < size; i++ {
		if i == int(s.Int64()) {
			ring = append(ring, pubkey)
		} else {
		tmpPriv, _ := GenPrivkey()
		tmpPub := GenPubkey(tmpPriv)
		ring = append(ring, tmpPub)
		}
	}

	var keyring PublicKeyRing
	keyring.Ring = ring
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

	curve := pubkey.Curve

	// hash pubkey.X
    hashX := sha256.Sum256(pubkey.X.Bytes())
    image.X = new(big.Int).SetBytes( hashX[:] )

	// hash pubkey.Y
	hashY := sha256.Sum256(pubkey.Y.Bytes())
	image.Y = new(big.Int).SetBytes( hashY[:] )

	image.X, image.Y = curve.ScalarMult(image.X, image.Y, privkey.D.Bytes())

	return image
}

func typeof(v interface{}) string {
   return fmt.Sprintf("%T", v)
}

// create ring signature from list of public keys given
// inputs
// msg: byte array, message to be signed
// ring: array of PublicKeys to be included in the ring
// privkey: PrivateKey of signer
func Sign(msg []byte, ring PublicKeyRing, privkey *btcec.PrivateKey) (*RingSign, error) {
	tmp := new(big.Int)

    ringSize := len(ring.Ring)

	// wish to create challenge c = hash(m,L_1,..,L_n,R_1,..,R_n)
	// with L_i =  i = s ? q_i*G : q_i*G + w_i*P_i
	// and R_i = i = s ? q_i*sha256(P_i) : q_i*sha256(P_i) + w_i*I
	// where s is the signer's secret index in the ring and
	// q_i and w_i are random numbers
	image := GenKeyImage(privkey)
	pubkey := privkey.PubKey()
	//curve := new(elliptic.Curve)
	curve := pubkey.Curve
	sig := new(RingSign)
	sig.I = image

	// l is a large randomly generated prime.
	l, _ := rand.Prime(rand.Reader, 1024)

	//var Lx, Ly, Rx, Ry []*big.Int
	Lx := make([]*big.Int, ringSize)
	Ly := make([]*big.Int, ringSize)
	Rx := make([]*big.Int, ringSize)
	Ry := make([]*big.Int, ringSize)

	// insert signer's info at randomly generated index s
	//n, err := rand.Prime(rand.Reader, 1024)
    //if err != nil { log.Fatal(err) }
    //fmt.Println(n)

   	// sig return values
    C := make([]*big.Int, ringSize)
 	T := make([]*big.Int, ringSize)

 	tmpX := new(big.Int)
 	tmpY := new(big.Int)

 	var s int // secret index

	for i := 0; i < ringSize; i ++ {
	 	C[i] = new(big.Int)
	 	T[i] = new(big.Int)

		Lx[i] = new(big.Int)
 		Ly[i] = new(big.Int)
 		Rx[i] = new(big.Int)
 		Ry[i] = new(big.Int)

		pub_x := ring.Ring[i].X
		pub_y := ring.Ring[i].Y

		bytes_hash_x := sha256.Sum256(pub_x.Bytes())
		hash_x := new(big.Int)
		hash_x.SetBytes(bytes_hash_x[:])

		bytes_hash_y := sha256.Sum256(pub_y.Bytes())
		hash_y := new(big.Int)
		hash_y.SetBytes(bytes_hash_y[:])

 		if(ring.Ring[i] == pubkey) {
 			s = i
			q_i, _ := rand.Prime(rand.Reader, 1024)

			Lx[i], Ly[i] = curve.ScalarBaseMult(q_i.Bytes()) // q_i*G
			Rx[i], Ry[i] = curve.ScalarMult(hash_x, hash_y, q_i.Bytes())
 		} else {
			q_i, _ := rand.Prime(rand.Reader, 1024)
			w_i, _ := rand.Prime(rand.Reader, 1024)

			C[i] = w_i
			T[i] = q_i

			tmpX, tmpY = curve.ScalarBaseMult(q_i.Bytes()) // q_i*G
			Lx[i], Ly[i] = curve.ScalarMult(pub_x, pub_y, w_i.Bytes()) // w_i*P_i
			Lx[i], Ly[i] = curve.Add(Lx[i], Ly[i], tmpX, tmpY) 

			tmpX, tmpY = curve.ScalarMult(hash_x, hash_y, q_i.Bytes()) // q_i*sha256(P_i)
			Rx[i], Ry[i] = curve.ScalarMult(image.X, image.Y, w_i.Bytes()) // w_i*I
			Rx[i], Ry[i] = curve.Add(Rx[i], Ry[i], tmpX, tmpY) 			
    	}
	}

	cHash := msg

	for i := 0; i < ringSize; i ++ {
		// create hash
		cHash = append(cHash,Lx[i].Bytes()...)
		cHash = append(cHash,Ly[i].Bytes()...)
	}
	for i := 0; i < ringSize; i ++ {
		// create hash
		cHash = append(cHash,Rx[i].Bytes()...)
		cHash = append(cHash,Ry[i].Bytes()...)
	}

	// calculate c_s, t_s values
	// c_s = c - (c_1 + ... + c _n) % l
	// t_s = q_s - c_s * privkey.D % l
	// sum all c[i]
	c_sum := new(big.Int)
	for i := 0; i < ringSize; i ++ {
		if i != s {
			c_sum.Add(c_sum,C[i])
		}
	}

    // randomizing s
    // s_big := new(big.Int)
    // len_big := new(big.Int)
    // len_big.SetInt64(int64(len(ring.Ring)))
    // s_big.Mod(n,len_big)
    // s := int(s_big.Int64())

 	C[s] = new(big.Int)
 	T[s] = new(big.Int)
	challenge := new(big.Int)
	challenge.SetBytes(cHash)
	c_mod := new(big.Int)
 	c_mod.Mod(c_sum, l)
	C[s].Sub(challenge, c_mod)
	tmp.Mul(C[s], privkey.D)
	tmp.Mod(tmp, l)
	T[s].Sub(T[s], tmp)

	sig.C = C
	sig.T = T

	return sig, nil
}

func Ver() { 
	//Gx := btcec.S256().Gx
	//Gy := btcec.S256().Gy

	// apply transformations:
	// L_i' = t_i*G + c_i*P_i
	// R_i' = t_i*sha1(P_i) + c_i*I

	// check if sum(c_i) = 
}

func Link() { }
