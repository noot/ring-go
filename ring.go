package ring

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

// Ring represents a group of public keys such that one of the group created a signature.
type Ring []*ecdsa.PublicKey

// Bytes returns the public key ring as a byte slice.
func (r Ring) Bytes() (b []byte) {
	for _, pub := range r {
		b = append(b, pub.X.Bytes()...)
		b = append(b, pub.Y.Bytes()...)
	}
	return
}

// RingSig represents a ring signature.
type RingSig struct {
	ring  Ring             // array of public keys
	c     *big.Int         // ring signature challenge
	s     []*big.Int       // ring signature values
	image *ecdsa.PublicKey // key image
	curve elliptic.Curve
}

// PublicKeys returns a copy of the ring signature's public keys.
func (r *RingSig) PublicKeys() Ring {
	ret := make([]*ecdsa.PublicKey, len(r.ring))
	for i, pk := range r.ring {
		ret[i] = &ecdsa.PublicKey{
			Curve: pk.Curve,
			X:     new(big.Int).Set(pk.X),
			Y:     new(big.Int).Set(pk.Y),
		}
	}
	return ret
}

// Serialize converts the signature to a byte array.
func (r *RingSig) Serialize() ([]byte, error) {
	sig := []byte{}
	size := len(r.ring)

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(size))
	sig = append(sig, b[:]...)                      // 8 bytes
	sig = append(sig, padTo32Bytes(r.c.Bytes())...) // 32 bytes

	// 96 bytes each iteration
	for i := 0; i < size; i++ {
		sig = append(sig, padTo32Bytes(r.s[i].Bytes())...)
		sig = append(sig, padTo32Bytes(r.ring[i].X.Bytes())...)
		sig = append(sig, padTo32Bytes(r.ring[i].Y.Bytes())...)
	}

	// 64 bytes
	sig = append(sig, padTo32Bytes(r.image.X.Bytes())...)
	sig = append(sig, padTo32Bytes(r.image.Y.Bytes())...)

	if len(sig) != 32*(3*size+3)+8 {
		return nil, errors.New("failed to serialize ring signature")
	}

	return sig, nil
}

// Deserialize the byteified signature into a *RingSig.
func (sig *RingSig) Deserialize(r []byte) error {
	// TODO: rewrite this func to use a bytes.Buffer internally
	if len(r) < 72 {
		return errors.New("incorrect ring size")
	}

	sizeBytes := r[0:8]
	size := binary.BigEndian.Uint64(sizeBytes)
	sig.c = new(big.Int).SetBytes(r[8:40])

	bytelen := size * 96
	if uint64(len(r)) < bytelen+104 {
		return errors.New("input is too short")
	}

	j := 0
	sig.s = make([]*big.Int, size)
	sig.ring = make([]*ecdsa.PublicKey, size)

	for i := uint64(40); i < bytelen; i += 96 {
		s_i := r[i : i+32]
		x_i := r[i+32 : i+64]
		y_i := r[i+64 : i+96]

		sig.s[j] = new(big.Int).SetBytes(s_i)
		sig.ring[j] = &ecdsa.PublicKey{
			Curve: secp256k1.S256(),
		}
		sig.ring[j].X = new(big.Int).SetBytes(x_i)
		sig.ring[j].Y = new(big.Int).SetBytes(y_i)
		sig.ring[j].Curve = crypto.S256()
		j++
	}

	sig.image = &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     new(big.Int).SetBytes(r[bytelen+40 : bytelen+72]),
		Y:     new(big.Int).SetBytes(r[bytelen+72 : bytelen+104]),
	}

	sig.curve = crypto.S256()
	return nil
}

// GenKeyRing takes public key ring and places the public key corresponding to `privkey`
// in index s of the ring.
// It returns a ring of public keys of length `len(ring)+1`.
func GenKeyRing(ring []*ecdsa.PublicKey, privkey *ecdsa.PrivateKey, s int) (Ring, error) {
	size := len(ring) + 1
	newRing := make([]*ecdsa.PublicKey, size)
	pubkey := privkey.Public().(*ecdsa.PublicKey)

	if s > len(ring) {
		return nil, errors.New("index s out of bounds")
	}

	newRing[s] = pubkey
	for i := 1; i < size; i++ {
		idx := (i + s) % size
		newRing[idx] = ring[i-1]
	}

	return newRing, nil
}

// NewKeyRing creates a ring with size specified by `size` and places the public key corresponding
// to `privkey` in index s of the ring.
// It returns a ring of public keys of length `size`.
func NewKeyRing(size int, privkey *ecdsa.PrivateKey, s int) (Ring, error) {
	ring := make([]*ecdsa.PublicKey, size)
	pubkey := privkey.Public().(*ecdsa.PublicKey)

	if s > len(ring) {
		return nil, errors.New("index s out of bounds")
	}

	ring[s] = pubkey

	for i := 1; i < size; i++ {
		idx := (i + s) % size
		priv, err := crypto.GenerateKey()
		if err != nil {
			return nil, err
		}

		pub := priv.Public()
		ring[idx] = pub.(*ecdsa.PublicKey)
	}

	return ring, nil
}

// calculate key image I = x * H_p(P) where H_p is a hash function that returns a point
// H_p(P) = sha3(P) * G
func genKeyImage(privkey *ecdsa.PrivateKey) *ecdsa.PublicKey {
	pubkey := privkey.Public().(*ecdsa.PublicKey)
	image := &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
	}

	// calculate sha3(P)
	ge1 := hashToCurve(pubkey)

	// calculate H_p(P) = x * sha3(P) * G
	i_x, i_y := privkey.Curve.ScalarMult(ge1.X, ge1.Y, privkey.D.Bytes())

	image.X = i_x
	image.Y = i_y
	return image
}

// Sign creates a ring signature on the given message using the public key ring
// and a private key of one of the members of the ring.
func (r Ring) Sign(m [32]byte, privkey *ecdsa.PrivateKey) (*RingSig, error) {
	ourIdx := -1
	pubkey := &privkey.PublicKey
	for i, pk := range r {
		if pk.Equal(pubkey) {
			ourIdx = i
			break
		}
	}

	if ourIdx == -1 {
		return nil, errors.New("failed to find given key in public key set")
	}

	return Sign(m, r, privkey, ourIdx)
}

// Sign creates a ring signature from list of public keys given inputs:
// msg: byte array, message to be signed
// ring: array of *ecdsa.PublicKeys to be included in the ring
// privkey: *ecdsa.PrivateKey of signer
// ourIdx: index of signer in ring
func Sign(m [32]byte, ring Ring, privkey *ecdsa.PrivateKey, ourIdx int) (*RingSig, error) {
	// TODO: don't pass index, just get it from the ring?
	size := len(ring)
	if size < 2 {
		return nil, errors.New("size of ring less than two")
	}

	if ourIdx >= size {
		return nil, errors.New("secret index out of range of ring size")
	}

	// check that key at index s is indeed the signer
	pubkey := &privkey.PublicKey
	if ring[ourIdx] != pubkey {
		return nil, errors.New("secret index in ring is not signer")
	}

	// setup
	curve := pubkey.Curve
	sig := &RingSig{
		ring:  ring,
		curve: curve,
		image: genKeyImage(privkey),
	}

	// start at c[1]
	// pick random scalar u (glue value), calculate c[1] = H(m, u*G)
	// where H is a hash function and G is the base point of the curve
	c := make([]*big.Int, size)
	s := make([]*big.Int, size)

	// pick random scalar u
	u, err := rand.Int(rand.Reader, curve.Params().P)
	if err != nil {
		return nil, err
	}

	// start at secret index s
	// compute L_s = u*G
	l_x, l_y := curve.ScalarBaseMult(u.Bytes())

	// compute R_s = u*H_p(P[s])
	ge := hashToCurve(pubkey)
	r_x, r_y := curve.ScalarMult(ge.X, ge.Y, u.Bytes())

	l := append(l_x.Bytes(), l_y.Bytes()...)
	r := append(r_x.Bytes(), r_y.Bytes()...)

	// concatenate m and u*G and calculate c[s+1] = H(m, L_s, R_s)
	c_i := sha3.Sum256(append(m[:], append(l, r...)...))
	idx := (ourIdx + 1) % size
	c[idx] = new(big.Int).SetBytes(c_i[:])

	// start loop at s+1
	for i := 1; i < size; i++ {
		idx := (ourIdx + i) % size
		if ring[idx] == nil {
			return nil, fmt.Errorf("no public key at index %d", idx)
		}

		// pick random scalar s_i
		s_i, err := rand.Int(rand.Reader, curve.Params().P)
		if err != nil {
			return nil, err
		}

		s[idx] = s_i

		// calculate L_i = s_i*G + c_i*P_i
		px, py := curve.ScalarMult(ring[idx].X, ring[idx].Y, c[idx].Bytes()) // px, py = c_i*P_i
		sx, sy := curve.ScalarBaseMult(s_i.Bytes())                          // sx, sy = s[n-1]*G
		l_x, l_y := curve.Add(sx, sy, px, py)

		// calculate R_i = s_i*H_p(P_i) + c_i*I
		px, py = curve.ScalarMult(sig.image.X, sig.image.Y, c[idx].Bytes()) // px, py = c_i*I
		ge := hashToCurve(ring[idx])
		sx, sy = curve.ScalarMult(ge.X, ge.Y, s_i.Bytes()) // sx, sy = s[n-1]*H_p(P_i)
		r_x, r_y := curve.Add(sx, sy, px, py)

		// calculate c[i+1] = H(m, L_i, R_i)
		l := append(l_x.Bytes(), l_y.Bytes()...)
		r := append(r_x.Bytes(), r_y.Bytes()...)
		c_i = sha3.Sum256(append(m[:], append(l, r...)...))

		if i == size-1 {
			c[ourIdx] = new(big.Int).SetBytes(c_i[:])
		} else {
			c[(idx+1)%size] = new(big.Int).SetBytes(c_i[:])
		}
	}

	// close ring by finding S[s] = ( u - c[s]*k[s] ) mod P
	// where k[s] is the private key and P is the curve order
	s[ourIdx] = new(big.Int).Mod(new(big.Int).Sub(u, new(big.Int).Mul(c[ourIdx], privkey.D)), curve.Params().N)

	// check that u*G = S[s]*G + c[s]*P[s]
	ux, uy := curve.ScalarBaseMult(u.Bytes()) // u*G
	px, py := curve.ScalarMult(ring[ourIdx].X, ring[ourIdx].Y, c[ourIdx].Bytes())
	sx, sy := curve.ScalarBaseMult(s[ourIdx].Bytes())
	l_x, l_y = curve.Add(sx, sy, px, py)

	// check that u*H_p(P[s]) = S[s]*H_p(P[s]) + C[s]*I
	px, py = curve.ScalarMult(sig.image.X, sig.image.Y, c[ourIdx].Bytes()) // px, py = C[s]*I
	ge = hashToCurve(pubkey)
	tx, ty := curve.ScalarMult(ge.X, ge.Y, u.Bytes())
	sx, sy = curve.ScalarMult(ge.X, ge.Y, s[ourIdx].Bytes()) // sx, sy = S[s]*H_p(P[s])
	r_x, r_y = curve.Add(sx, sy, px, py)

	l = append(l_x.Bytes(), l_y.Bytes()...)
	r = append(r_x.Bytes(), r_y.Bytes()...)

	// check that H(m, L[s], R[s]) == C[s+1]
	c_i = sha3.Sum256(append(m[:], append(l, r...)...))

	// sanity check
	if !bytes.Equal(ux.Bytes(), l_x.Bytes()) ||
		!bytes.Equal(uy.Bytes(), l_y.Bytes()) ||
		!bytes.Equal(tx.Bytes(), r_x.Bytes()) ||
		!bytes.Equal(ty.Bytes(), r_y.Bytes()) {
		// this should not happen
		return nil, errors.New("failed to close ring")
	}

	// everything ok, add values to signature
	sig.s = s
	sig.c = c[0]
	return sig, nil
}

// Verify verifies the ring signature for the given message.
// It returns true if a valid signature, false otherwise.
func (sig *RingSig) Verify(m [32]byte) bool {
	// setup
	ring := sig.ring
	size := len(ring)
	c := make([]*big.Int, size)
	c[0] = sig.c
	curve := sig.curve

	// calculate c[i+1] = H(m, s[i]*G + c[i]*P[i])
	// and c[0] = H)(m, s[n-1]*G + c[n-1]*P[n-1]) where n is the ring size
	for i := 0; i < size; i++ {
		// calculate L_i = s_i*G + c_i*P_i
		px, py := curve.ScalarMult(ring[i].X, ring[i].Y, c[i].Bytes()) // px, py = c_i*P_i
		sx, sy := curve.ScalarBaseMult(sig.s[i].Bytes())               // sx, sy = s[i]*G
		l_x, l_y := curve.Add(sx, sy, px, py)

		// calculate R_i = s_i*H_p(P_i) + c_i*I
		px, py = curve.ScalarMult(sig.image.X, sig.image.Y, c[i].Bytes()) // px, py = c[i]*I
		ge := hashToCurve(ring[i])
		sx, sy = curve.ScalarMult(ge.X, ge.Y, sig.s[i].Bytes()) // sx, sy = s[i]*H_p(P[i])
		r_x, r_y := curve.Add(sx, sy, px, py)

		// calculate c[i+1] = H(m, L_i, R_i)
		l := append(l_x.Bytes(), l_y.Bytes()...)
		r := append(r_x.Bytes(), r_y.Bytes()...)
		c_i := sha3.Sum256(append(m[:], append(l, r...)...))

		if i == size-1 {
			c[0] = new(big.Int).SetBytes(c_i[:])
		} else {
			c[i+1] = new(big.Int).SetBytes(c_i[:])
		}
	}

	return bytes.Equal(sig.c.Bytes(), c[0].Bytes())
}

// Link returns true if the two signatures were created by the same signer,
// false otherwise.
func Link(sigA, sigB *RingSig) bool {
	return sigA.image.Equal(sigB.image)
}
