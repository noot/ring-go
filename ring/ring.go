package ring

import (
	"fmt"
	"errors"
	//"io"
	//"encoding/hex"
	"math/big"
	"crypto/rand"
	"crypto/elliptic"
	"crypto/ecdsa"
	//"log"

 	"golang.org/x/crypto/sha3"
	//"github.com/ethereum/go-ethereum/crypto"
)

type Ring []*ecdsa.PublicKey

type RingSign struct {
	M []byte
	S []*big.Int
	C *big.Int
	Ring Ring // todo: fix this?
	Curve elliptic.Curve
}

/* helpers */
func typeof(v interface{}) string {
   return fmt.Sprintf("%T", v)
}

// Bytes returns the public key ring as a byte slice.
func (r Ring) Bytes() (b []byte) {
	for _, pub := range r {
		b = append(b, pub.X.Bytes()...)
		b = append(b, pub.Y.Bytes()...)
	}
	return
}

func GenNewKeyRing(size int, privkey *ecdsa.PrivateKey) ([]*ecdsa.PublicKey) {
	//ring := new(Ring)
	ring := make([]*ecdsa.PublicKey, size)
	pubkey := privkey.Public().(*ecdsa.PublicKey)
	ring[0] = pubkey

	for i := 1; i < size; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil
		}

		pub := priv.Public()
		ring[i] = pub.(*ecdsa.PublicKey)
	}

	return ring
}

// create ring signature from list of public keys given
// inputs
// msg: byte array, message to be signed
// ring: array of PublicKeys to be included in the ring
// privkey: PrivateKey of signer
func Sign(m []byte, ring []*ecdsa.PublicKey, privkey *ecdsa.PrivateKey) (*RingSign, error) {
	// check ringsize > 1
	ringsize := len(ring)
	if ringsize < 2 {
		return nil, errors.New("length of ring less than two")
	}

	// setup
	pubkey := privkey.Public().(*ecdsa.PublicKey)
	curve := pubkey.Curve
	sig := new(RingSign)
	sig.M = m
	sig.Ring = ring
	sig.Curve = curve

	if ring[0] != pubkey {
		return nil, errors.New("first index in ring is not signer")
	}

	// start at c[1]
	// pick random scalar u (glue value), calculate c[1] = H(m + u*G) where H is a hash function and G is the base point of the curve
	C := make([]*big.Int, ringsize)
	S := make([]*big.Int, ringsize)

	// pick random scalar u
	u, err := rand.Int(rand.Reader, new(big.Int).SetInt64(2 ^ 256) )
	if err != nil {
		return nil, err
	}

	// compute u*G
	gx, gy := curve.ScalarBaseMult(u.Bytes())
	// concatenate m and u*G and calculate sha3 hash
	C_i := sha3.Sum256(append(m, append(gx.Bytes(), gy.Bytes()...)...))
	C[1] = new(big.Int).SetBytes(C_i[:])

	// pick random scalar s
	s, err := rand.Int(rand.Reader, curve.Params().N)
	S[1] = s
	if err != nil {
		return nil, err
	}

	// calculate c[0] = H(m + s[n-1]*G + c[n-1]*P[n-1]) where n = ringsize
	px, py := curve.ScalarMult(ring[1].X, ring[1].Y, s.Bytes())
	gx, gy = curve.ScalarBaseMult(S[1].Bytes())
	cP := append(px.Bytes(), py.Bytes()...)
	sG := append(gx.Bytes(), gy.Bytes()...)
	C_i = sha3.Sum256(append(m, append(sG, cP...)...))
	C[0] = new(big.Int).SetBytes(C_i[:])

	// close ring by finding s[0] = u - c[0]*k[0] where P[0] = k[0]*G
	S[0] = new(big.Int).Sub(u, new(big.Int).Mul(C[0], privkey.D))

	sig.S = S
	sig.C = C[0]

	return sig, nil
}

func Verify(sig *RingSign) (bool, error) { 
	// setup
	ring := sig.Ring
	ringsize := len(ring)
	S := sig.S
	C := make([]*big.Int, ringsize)
	curve := ring[0].Curve

	// calculate c[1]
	px, py := curve.ScalarMult(ring[0].X, ring[0].Y, sig.C.Bytes())
	gx, gy := curve.ScalarBaseMult(S[0].Bytes())
	cP := append(px.Bytes(), py.Bytes()...)
	sG := append(gx.Bytes(), gy.Bytes()...)
	C_i := sha3.Sum256(append(sig.M, append(sG, cP...)...))
	C[1] = new(big.Int).SetBytes(C_i[:])

	// calculate c[0]
	px, py = curve.ScalarMult(ring[1].X, ring[1].Y, C[1].Bytes())
	gx, gy = curve.ScalarBaseMult(S[1].Bytes())
	cP = append(px.Bytes(), py.Bytes()...)
	sG = append(gx.Bytes(), gy.Bytes()...)
	C_i = sha3.Sum256(append(sig.M, append(sG, cP...)...))
	C[0] = new(big.Int).SetBytes(C_i[:])	

	return C[0] == sig.C, nil
}