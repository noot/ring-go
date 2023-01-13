package ring

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/athanorlabs/go-dleq/types"
	"golang.org/x/crypto/sha3"
)

// Ring represents a group of public keys such that one of the group created a signature.
type Ring struct {
	pubkeys []types.Point
	curve   types.Curve
}

// Bytes returns the public key ring as a byte slice.
func (r Ring) Bytes() (b []byte) {
	for _, pub := range r.pubkeys {
		b = append(b, pub.Encode()...)
	}
	return
}

// RingSig represents a ring signature.
type RingSig struct {
	ring  Ring           // array of public keys
	c     types.Scalar   // ring signature challenge
	s     []types.Scalar // ring signature values
	image types.Point    // key image
}

// PublicKeys returns a copy of the ring signature's public keys.
func (r *RingSig) PublicKeys() []types.Point {
	ret := make([]types.Point, len(r.ring.pubkeys))
	for i, pk := range r.ring.pubkeys {
		ret[i] = pk.Copy()
	}
	return ret
}

// Serialize converts the signature to a byte array.
func (r *RingSig) Serialize() ([]byte, error) {
	sig := []byte{}
	size := len(r.ring.pubkeys)

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(size))
	sig = append(sig, b[:]...)                       // 8 bytes
	sig = append(sig, padTo32Bytes(r.c.Encode())...) // 32 bytes

	// 96 bytes each iteration
	// TODO: now 97 bytes?
	for i := 0; i < size; i++ {
		sig = append(sig, padTo32Bytes(r.s[i].Encode())...)
		sig = append(sig, padTo32Bytes(r.ring.pubkeys[i].Encode())...)
	}

	// 64 bytes
	sig = append(sig, padTo32Bytes(r.image.Encode())...)

	if len(sig) != 32*(3*size+3)+8 {
		return nil, errors.New("failed to serialize ring signature")
	}

	return sig, nil
}

// Deserialize the byteified signature into a *RingSig.
func (sig *RingSig) Deserialize(r []byte) error {
	// TODO: rewrite this func to use a bytes.Buffer internally
	// if len(r) < 72 {
	// 	return errors.New("incorrect ring size")
	// }

	// sizeBytes := r[0:8]
	// size := binary.BigEndian.Uint64(sizeBytes)
	// sig.c = new(big.Int).SetBytes(r[8:40])

	// bytelen := size * 96
	// if uint64(len(r)) < bytelen+104 {
	// 	return errors.New("input is too short")
	// }

	// j := 0
	// sig.s = make([]*big.Int, size)
	// sig.ring = make([]*ecdsa.PublicKey, size)

	// for i := uint64(40); i < bytelen; i += 96 {
	// 	s_i := r[i : i+32]
	// 	x_i := r[i+32 : i+64]
	// 	y_i := r[i+64 : i+96]

	// 	sig.s[j] = new(big.Int).SetBytes(s_i)
	// 	sig.ring[j] = &ecdsa.PublicKey{
	// 		Curve: secp256k1.S256(),
	// 	}
	// 	sig.ring[j].X = new(big.Int).SetBytes(x_i)
	// 	sig.ring[j].Y = new(big.Int).SetBytes(y_i)
	// 	sig.ring[j].Curve = crypto.S256()
	// 	j++
	// }

	// sig.image = &ecdsa.PublicKey{
	// 	Curve: secp256k1.S256(),
	// 	X:     new(big.Int).SetBytes(r[bytelen+40 : bytelen+72]),
	// 	Y:     new(big.Int).SetBytes(r[bytelen+72 : bytelen+104]),
	// }

	// sig.curve = crypto.S256()
	return nil
}

// NewKeyRingFromPublicKeys takes public key ring and places the public key corresponding to `privkey`
// in index idx of the ring.
// It returns a ring of public keys of length `len(ring)+1`.
func NewKeyRingFromPublicKeys(curve types.Curve, pubkeys []types.Point, privkey types.Scalar, idx int) (*Ring, error) {
	size := len(pubkeys) + 1
	newRing := make([]types.Point, size)
	pubkey := curve.ScalarBaseMul(privkey)

	if idx > len(pubkeys) {
		return nil, errors.New("index out of bounds")
	}

	newRing[idx] = pubkey
	for i := 1; i < size; i++ {
		idx := (i + idx) % size
		newRing[idx] = pubkeys[i-1]
	}

	return &Ring{
		pubkeys: newRing,
		curve:   curve,
	}, nil
}

// NewKeyRing creates a ring with size specified by `size` and places the public key corresponding
// to `privkey` in index idx of the ring.
// It returns a ring of public keys of length `size`.
func NewKeyRing(curve types.Curve, size int, privkey types.Scalar, idx int) (*Ring, error) {
	if idx >= size {
		return nil, errors.New("index out of bounds")
	}

	ring := make([]types.Point, size)
	pubkey := curve.ScalarBaseMul(privkey)
	ring[idx] = pubkey

	for i := 1; i < size; i++ {
		idx := (i + idx) % size
		priv := curve.NewRandomScalar()
		ring[idx] = curve.ScalarBaseMul(priv)
	}

	return &Ring{
		pubkeys: ring,
		curve:   curve,
	}, nil
}

// calculate key image I = x * H_p(P) where H_p is a hash-to-curve function
func genKeyImage(curve types.Curve, privkey types.Scalar) types.Point {
	pubkey := curve.ScalarBaseMul(privkey)
	h := hashToCurve(pubkey)
	return curve.ScalarMul(privkey, h)
}

// Sign creates a ring signature on the given message using the public key ring
// and a private key of one of the members of the ring.
func (r Ring) Sign(m [32]byte, privkey types.Scalar) (*RingSig, error) {
	ourIdx := -1
	pubkey := r.curve.ScalarBaseMul(privkey)
	for i, pk := range r.pubkeys {
		if pk.Equals(pubkey) {
			ourIdx = i
			break
		}
	}

	if ourIdx == -1 {
		return nil, errors.New("failed to find given key in public key set")
	}

	return Sign(m, r, privkey, ourIdx)
}

func challenge(curve types.Curve, m [32]byte, l, r types.Point) types.Scalar {
	c := sha3.Sum256(append(m[:], append(l.Encode(), r.Encode()...)...))
	return curve.ScalarFromBytes(c)
}

// Sign creates a ring signature on the given message using the provided private key
// and ring of public keys.
func Sign(m [32]byte, ring Ring, privkey types.Scalar, ourIdx int) (*RingSig, error) {
	size := len(ring.pubkeys)
	if size < 2 {
		return nil, errors.New("size of ring less than two")
	}

	if ourIdx >= size {
		return nil, errors.New("secret index out of range of ring size")
	}

	// check that key at index s is indeed the signer
	pubkey := ring.curve.ScalarBaseMul(privkey) //privkey.Public().(*ecdsa.PublicKey)
	if !ring.pubkeys[ourIdx].Equals(pubkey) {
		return nil, errors.New("secret index in ring is not signer")
	}

	// setup
	sig := &RingSig{
		ring:  ring,
		image: genKeyImage(ring.curve, privkey),
	}
	curve := ring.curve

	// start at c[j]
	c := make([]types.Scalar, size)
	s := make([]types.Scalar, size)

	// pick random scalar u, calculate L[j] = u*G
	u := curve.NewRandomScalar()
	l := curve.ScalarBaseMul(u)

	// compute R[j] = u*H_p(P[j])
	h := hashToCurve(pubkey)
	r := curve.ScalarMul(u, h)

	// calculate challenge c[j+1] = H(m, L_j, R_j)
	idx := (ourIdx + 1) % size
	c[idx] = challenge(ring.curve, m, l, r)

	// start loop at j+1
	for i := 1; i < size; i++ {
		idx := (ourIdx + i) % size
		if ring.pubkeys[idx] == nil {
			return nil, fmt.Errorf("no public key at index %d", idx)
		}

		// pick random scalar s_i
		s[idx] = curve.NewRandomScalar()

		// calculate L_i = s_i*G + c_i*P_i
		cP := curve.ScalarMul(c[idx], ring.pubkeys[idx])
		sG := curve.ScalarBaseMul(s[idx])
		l := cP.Add(sG)

		// calculate R_i = s_i*H_p(P_i) + c_i*I
		cI := curve.ScalarMul(c[idx], sig.image)
		h := hashToCurve(ring.pubkeys[idx])
		sH := curve.ScalarMul(s[idx], h)
		r := cI.Add(sH)

		// calculate c[i+1] = H(m, L_i, R_i)
		c[(idx+1)%size] = challenge(curve, m, l, r)
	}

	// close ring by finding s[j] = ( u - c[j]*x ) mod P
	cx := c[ourIdx].Mul(privkey)
	s[ourIdx] = u.Sub(cx)

	// check that u*G = s[j]*G + c[j]*P[j]
	cP := curve.ScalarMul(c[ourIdx], pubkey)
	sG := curve.ScalarBaseMul(s[ourIdx])
	l = cP.Add(sG)
	uG := curve.ScalarBaseMul(u)
	if !uG.Equals(l) {
		// this should not happen
		return nil, errors.New("failed to close ring: uG != sG + cP")
	}

	// check that u*H_p(P[j]) = S[j]*H_p(P[j]) + C[j]*I
	cI := curve.ScalarMul(c[ourIdx], sig.image)
	sH := curve.ScalarMul(s[ourIdx], h)
	r = cI.Add(sH)
	uH := curve.ScalarMul(u, h)
	if !uH.Equals(r) {
		// this should not happen
		return nil, errors.New("WARN: failed to close ring: uH(P) != sH(P) + cI")
	}

	// check that H(m, L[j], R[j]) == c[j+1]
	cCheck := challenge(ring.curve, m, l, r)
	if !cCheck.Eq(c[(ourIdx+1)%size]) {
		return nil, errors.New("challenge check failed")
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
	size := len(ring.pubkeys)
	c := make([]types.Scalar, size)
	c[0] = sig.c
	curve := ring.curve

	// calculate c[i+1] = H(m, s[i]*G + c[i]*P[i])
	// and c[0] = H)(m, s[n-1]*G + c[n-1]*P[n-1]) where n is the ring size
	for i := 0; i < size; i++ {
		// calculate L_i = s_i*G + c_i*P_i
		cP := curve.ScalarMul(c[i], ring.pubkeys[i])
		sG := curve.ScalarBaseMul(sig.s[i])
		l := cP.Add(sG)

		// calculate R_i = s_i*H_p(P_i) + c_i*I
		cI := curve.ScalarMul(c[i], sig.image)
		h := hashToCurve(ring.pubkeys[i])
		sH := curve.ScalarMul(sig.s[i], h)
		r := cI.Add(sH)

		// calculate c[i+1] = H(m, L_i, R_i)
		if i == size-1 {
			c[0] = challenge(curve, m, l, r)
		} else {
			c[i+1] = challenge(curve, m, l, r)
		}
	}

	return sig.c.Eq(c[0])
}

// Link returns true if the two signatures were created by the same signer,
// false otherwise.
func Link(sigA, sigB *RingSig) bool {
	return sigA.image.Equals(sigB.image)
}
