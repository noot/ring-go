package ring

import (
	"errors"
	"fmt"

	"github.com/athanorlabs/go-dleq/ed25519"
	"github.com/athanorlabs/go-dleq/types"
)

// Ring represents a group of public keys such that one of the group created a signature.
type Ring struct {
	pubkeys []types.Point
	curve   types.Curve
}

// Size returns the size of the ring, ie. the number of public keys in it.
func (r *Ring) Size() int {
	return len(r.pubkeys)
}

// Equals checks whether the supplied ring is equal to the current ring.
// The ring's public keys must be in the same order for the rings to be equal
func (r *Ring) Equals(other *Ring) bool {
	for i, p := range r.pubkeys {
		if !p.Equals(other.pubkeys[i]) {
			return false
		}
	}
	bp, abp := r.curve.BasePoint(), r.curve.AltBasePoint()
	obp, oabp := other.curve.BasePoint(), other.curve.AltBasePoint()
	return bp.Equals(obp) && abp.Equals(oabp)
}

// RingSig represents a ring signature.
type RingSig struct {
	ring  *Ring          // array of public keys
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

// Ring returns the ring from the RingSig struct
func (r *RingSig) Ring() *Ring {
	return r.ring
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
	pubkeysMap := make(map[types.Point]struct{})
	pubkeysMap[pubkey] = struct{}{}

	for i := 1; i < size; i++ {
		idx := (i + idx) % size
		newRing[idx] = pubkeys[i-1]
		pubkeysMap[pubkeys[i-1]] = struct{}{}
	}

	if len(pubkeysMap) != len(newRing) {
		return nil, errors.New("duplicate public keys in ring")
	}

	return &Ring{
		pubkeys: newRing,
		curve:   curve,
	}, nil
}

// NewFixedKeyRingFromPublicKeys takes public keys and a curve to create a ring
func NewFixedKeyRingFromPublicKeys(curve types.Curve, pubkeys []types.Point) (*Ring, error) {
	pubkeysMap := make(map[types.Point]struct{})

	size := len(pubkeys)
	newRing := make([]types.Point, size)
	for i := 0; i < size; i++ {
		pubkeysMap[pubkeys[i]] = struct{}{}
		newRing[i] = pubkeys[i].Copy()
	}

	if len(pubkeysMap) != len(newRing) {
		return nil, errors.New("duplicate public keys in ring")
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

// Sign creates a ring signature on the given message using the public key ring
// and a private key of one of the members of the ring.
func (r *Ring) Sign(m [32]byte, privkey types.Scalar) (*RingSig, error) {
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

// Sign creates a ring signature on the given message using the provided private key
// and ring of public keys.
func Sign(m [32]byte, ring *Ring, privkey types.Scalar, ourIdx int) (*RingSig, error) {
	size := len(ring.pubkeys)
	if size < 2 {
		return nil, errors.New("size of ring less than two")
	}

	if ourIdx >= size {
		return nil, errors.New("secret index out of range of ring size")
	}

	// check that key at index s is indeed the signer
	pubkey := ring.curve.ScalarBaseMul(privkey)
	if !ring.pubkeys[ourIdx].Equals(pubkey) {
		return nil, errors.New("secret index in ring is not signer")
	}

	// setup
	curve := ring.curve
	h := hashToCurve(pubkey)
	sig := &RingSig{
		ring: ring,
		// calculate key image I = x * H_p(P) where H_p is a hash-to-curve function
		image: curve.ScalarMul(privkey, h),
	}

	// start at c[j]
	c := make([]types.Scalar, size)
	s := make([]types.Scalar, size)

	// pick random scalar u, calculate L[j] = u*G
	u := curve.NewRandomScalar()
	l := curve.ScalarBaseMul(u)

	// compute R[j] = u*H_p(P[j])
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
		hp := hashToCurve(ring.pubkeys[idx])
		sH := curve.ScalarMul(s[idx], hp)
		r := cI.Add(sH)

		// calculate c[i+1] = H(m, L_i, R_i)
		c[(idx+1)%size] = challenge(curve, m, l, r)
	}

	// close ring by finding s[j] = u - c[j]*x
	cx := c[ourIdx].Mul(privkey)
	s[ourIdx] = u.Sub(cx)

	// check that u*G = s[j]*G + c[j]*P[j]
	cP := curve.ScalarMul(c[ourIdx], pubkey)
	sG := curve.ScalarBaseMul(s[ourIdx])
	lNew := cP.Add(sG)
	if !lNew.Equals(l) {
		// this should not happen
		return nil, errors.New("failed to close ring: uG != sG + cP")
	}

	// check that u*H_p(P[j]) = s[j]*H_p(P[j]) + c[j]*I
	cI := curve.ScalarMul(c[ourIdx], sig.image)
	sH := curve.ScalarMul(s[ourIdx], h)
	rNew := cI.Add(sH)
	if !rNew.Equals(r) {
		// this should not happen
		return nil, errors.New("failed to close ring: uH(P) != sH(P) + cI")
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
	switch sigA.Ring().curve.(type) {
	case *ed25519.CurveImpl:
		cofactor := Ed25519().ScalarFromInt(8)
		imageA := sigA.image.ScalarMul(cofactor)
		imageB := sigB.image.ScalarMul(cofactor)
		return imageA.Equals(imageB)
	default:
		return sigA.image.Equals(sigB.image)
	}
}

func challenge(curve types.Curve, m [32]byte, l, r types.Point) types.Scalar {
	t := append(m[:], append(l.Encode(), r.Encode()...)...)
	c, err := curve.HashToScalar(t)
	if err != nil {
		// this should not happen
		panic(err)
	}
	return c
}
