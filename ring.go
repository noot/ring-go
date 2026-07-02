package ring

import (
	"errors"
	"fmt"

	"github.com/pokt-network/go-dleq/ed25519"
	"github.com/pokt-network/go-dleq/types"
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
	if r.Size() != other.Size() {
		return false
	}

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

// NewKeyRingFromPublicKeys takes public key ring and places the public key corresponding to `privKey`
// in index idx of the ring.
// It returns a ring of public keys of length `len(ring)+1`.
func NewKeyRingFromPublicKeys(curve types.Curve, pubkeys []types.Point, privKey types.Scalar, idx int) (*Ring, error) {
	size := len(pubkeys) + 1
	newRing := make([]types.Point, size)
	pubkey := curve.ScalarBaseMul(privKey)

	if idx > len(pubkeys) {
		return nil, errors.New("index out of bounds: idx > len(pubkeys)")
	}

	if idx < 0 {
		return nil, errors.New("index out of bounds: idx < 0")
	}

	// ensure that privkey is nonzero
	if privKey.IsZero() {
		return nil, errors.New("private key is zero")
	}

	newRing[idx] = pubkey
	pubkeysMap := make(map[types.Point]struct{})
	pubkeysMap[pubkey] = struct{}{}

	for i := 0; i < size; i++ {
		if i == idx {
			continue
		}

		if i < idx {
			newRing[i] = pubkeys[i]
		} else {
			newRing[i] = pubkeys[i-1]
		}
		pubkeysMap[newRing[i]] = struct{}{}
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
// to `privKey` in index idx of the ring.
// It returns a ring of public keys of length `size`.
func NewKeyRing(curve types.Curve, size int, privKey types.Scalar, idx int) (*Ring, error) {
	if idx >= size {
		return nil, errors.New("index out of bounds")
	}

	// ensure that privkey is nonzero
	if privKey.IsZero() {
		return nil, errors.New("private key is zero")
	}

	ring := make([]types.Point, size)
	pubkey := curve.ScalarBaseMul(privKey)
	ring[idx] = pubkey

	for i := 0; i < size; i++ {
		if i == idx {
			continue
		}
		priv := curve.NewRandomScalar()
		ring[i] = curve.ScalarBaseMul(priv)
	}

	return &Ring{
		pubkeys: ring,
		curve:   curve,
	}, nil
}

// Sign creates a ring signature on the given message using the public key ring
// and a private key of one of the members of the ring.
func (r *Ring) Sign(m [32]byte, privKey types.Scalar) (*RingSig, error) {
	ourIdx := -1
	pubkey := r.curve.ScalarBaseMul(privKey)
	for i, pk := range r.pubkeys {
		if pk.Equals(pubkey) {
			ourIdx = i
			break
		}
	}

	if ourIdx == -1 {
		return nil, errors.New("failed to find given key in public key set")
	}

	return Sign(m, r, privKey, ourIdx)
}

// Sign creates a ring signature on the given message using the provided private key
// and ring of public keys.
func Sign(m [32]byte, ring *Ring, privKey types.Scalar, ourIdx int) (*RingSig, error) {
	size := len(ring.pubkeys)
	if size < 2 {
		return nil, errors.New("size of ring less than two")
	}

	if ourIdx >= size {
		return nil, errors.New("secret index out of range of ring size")
	}

	// ensure that privkey is nonzero
	if privKey.IsZero() {
		return nil, errors.New("private key is zero")
	}

	// check that key at index s is indeed the signer
	pubkey := ring.curve.ScalarBaseMul(privKey)
	if !ring.pubkeys[ourIdx].Equals(pubkey) {
		return nil, errors.New("secret index in ring is not signer")
	}

	// compute the remaining per-signer values and delegate to the shared core.
	// Plain Sign uses no precomputed member hashes and keeps the self-checks on,
	// so its work profile is identical to the un-optimized implementation. This
	// is the consensus-safe path; off-chain callers wanting the precompute/cache
	// use SignerContext + SignWithContext instead.
	h := hashToCurve(pubkey)
	image := ring.curve.ScalarMul(privKey, h)
	return signInternal(m, ring, privKey, ourIdx, pubkey, h, image, nil, false)
}

// signInternal is the core ring-signing routine. It accepts the signer's
// pre-computed public key P[j], hash-to-curve point h = H_p(P[j]), and key
// image I = x*h so a SignerContext can skip re-deriving them each signature.
//
// memberHashes, if non-nil, supplies H_p(P[i]) for every ring member so they
// need not be recomputed; when nil each member's hash-to-curve is computed
// inline (the consensus-safe default, no shared cache / no state). skipCheck
// omits the closing self-checks (off-chain opt-in only).
//
// The caller is responsible for validating that pubkey corresponds to privKey
// at ourIdx; the size and index guards below are kept as cheap safety nets.
func signInternal(m [32]byte, ring *Ring, privKey types.Scalar, ourIdx int, pubkey, h, image types.Point, memberHashes []types.Point, skipCheck bool) (*RingSig, error) {
	size := len(ring.pubkeys)
	if size < 2 {
		return nil, errors.New("size of ring less than two")
	}
	if ourIdx >= size {
		return nil, errors.New("secret index out of range of ring size")
	}

	// setup
	curve := ring.curve
	sig := &RingSig{
		ring: ring,
		// key image I = x * H_p(P) where H_p is a hash-to-curve function
		image: image,
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
		var hp types.Point
		if memberHashes != nil {
			hp = memberHashes[idx] // precomputed by SignerContext (off-chain)
		} else {
			hp = hashToCurve(ring.pubkeys[idx]) // consensus-safe default: inline
		}
		sH := curve.ScalarMul(s[idx], hp)
		r := cI.Add(sH)

		// calculate c[i+1] = H(m, L_i, R_i)
		c[(idx+1)%size] = challenge(curve, m, l, r)
	}

	// close ring by finding s[j] = u - c[j]*x
	cx := c[ourIdx].Mul(privKey)
	s[ourIdx] = u.Sub(cx)

	// Self-check that the ring closes correctly. These re-derivations are an
	// algebraic identity given correct arithmetic, so they only guard against a
	// buggy curve backend, at a cost of ~4 scalar multiplications per signature.
	// Always run on the plain Sign path; skippable only via SignerContext for
	// off-chain callers that accept the trade-off.
	if !skipCheck {
		if err := verifyRingCloses(curve, m, l, r, pubkey, sig.image, h,
			c[ourIdx], c[(ourIdx+1)%size], s[ourIdx]); err != nil {
			return nil, err
		}
	}

	// everything ok, add values to signature
	sig.s = s
	sig.c = c[0]
	return sig, nil
}

// SignerContext holds values that are constant across messages for a given
// (private key, ring): the signer's public key, hash-to-curve point, key image,
// index, and the hash-to-curve of every ring member. Pre-computing them once
// lets repeated signing skip all per-signer and per-member setup.
//
//	ctx, err := ring.NewSignerContext(privKey)
//	sig1, _ := ring.SignWithContext(msg1, privKey, ctx)
//	sig2, _ := ring.SignWithContext(msg2, privKey, ctx) // reuses ctx precompute
//
// A SignerContext holds NO secret material: every field is derived from public
// data (the key image and public key are already published in signatures). The
// private key is not retained — it is supplied per call to SignWithContext,
// exactly as with Sign — so a context is safe to hold, reuse, and pass around.
// It is tied to the ring it was created from; do not use it with a different
// ring or a different private key than the one it was built for.
//
// IMPORTANT: this is an OFF-CHAIN optimization. The precomputed member hashes
// mean SignWithContext performs less work than Sign for the same signature, so
// its cost is not identical to the plain path. Do NOT use SignerContext on
// consensus-critical / gas-metered paths where the amount of work performed
// must be deterministic across nodes — use Sign there.
type SignerContext struct {
	pubkey       types.Point   // P = x*G (public)
	h            types.Point   // H_p(P) == memberHashes[idx] (public)
	image        types.Point   // key image I = x*H_p(P) (public; published in signatures)
	idx          int           // signer's index in the ring
	memberHashes []types.Point // H_p(P[i]) for every ring member (public)

	// SkipSelfCheck, when true, omits the ~4-scalar-mul closing self-checks in
	// SignWithContext. Off-chain speed opt-in only; the signature is still fully
	// verifiable via RingSig.Verify. Leave false unless you trust the backend
	// and have measured the win. NOTE: the self-checks are also what catch a
	// privKey that does not match this context; with them skipped, a mismatched
	// key silently produces an invalid (not forged) signature.
	SkipSelfCheck bool
}

// NewSignerContext pre-computes, for privKey (which must correspond to one of
// the ring's public keys), the signer's public key, key image, index, and the
// hash-to-curve of every ring member. The private key is used only to derive
// these public values and is NOT stored on the returned context. All state
// lives on the context; the shared Ring is not mutated.
func (r *Ring) NewSignerContext(privKey types.Scalar) (*SignerContext, error) {
	if privKey.IsZero() {
		return nil, errors.New("private key is zero")
	}

	pubkey := r.curve.ScalarBaseMul(privKey)

	idx := -1
	for i, pk := range r.pubkeys {
		if pk.Equals(pubkey) {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, errors.New("private key does not correspond to any public key in the ring")
	}

	// Pre-compute H_p(P[i]) for every member; the signer's own h is memberHashes[idx].
	memberHashes := make([]types.Point, len(r.pubkeys))
	for i, pk := range r.pubkeys {
		memberHashes[i] = hashToCurve(pk)
	}
	h := memberHashes[idx]
	image := r.curve.ScalarMul(privKey, h)

	return &SignerContext{
		pubkey:       pubkey,
		h:            h,
		image:        image,
		idx:          idx,
		memberHashes: memberHashes,
	}, nil
}

// SignWithContext creates a ring signature using the values pre-computed in ctx,
// avoiding the per-signer and per-member setup that Sign repeats each call. The
// private key is supplied here (not stored on the context) and must be the same
// key the context was built for; otherwise the resulting signature is invalid
// (and rejected by the closing self-check unless ctx.SkipSelfCheck is set). It
// is an off-chain optimization; see SignerContext for the determinism caveat.
func (r *Ring) SignWithContext(m [32]byte, privKey types.Scalar, ctx *SignerContext) (*RingSig, error) {
	return signInternal(m, r, privKey, ctx.idx, ctx.pubkey, ctx.h, ctx.image, ctx.memberHashes, ctx.SkipSelfCheck)
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
	le, re := l.Encode(), r.Encode()
	t := make([]byte, 0, len(m)+len(le)+len(re))
	t = append(t, m[:]...)
	t = append(t, le...)
	t = append(t, re...)
	c, err := curve.HashToScalar(t)
	if err != nil {
		// this should not happen
		panic(err)
	}
	return c
}

// verifyRingCloses re-derives the signer's L[j] and R[j] from the closing
// scalar s[j] and checks they match the values (l = u*G, r = u*H_p(P[j]))
// chosen at the start of signing, then checks the challenge chain wraps around.
//
// Given correct curve arithmetic these equalities hold by construction
// (s[j] = u - c[j]*x), so they are a defense-in-depth guard against a buggy
// curve backend producing a malformed signature, not a security requirement.
// They cost ~4 scalar multiplications per Sign and run on every plain Sign;
// SignWithContext can skip them via SignerContext.SkipSelfCheck.
//
//	l, r:   u*G and u*H_p(P[j]) from the start of signing
//	pubkey: signer's public key P[j]
//	image:  key image I
//	h:      H_p(P[j])
//	cJ:     c[j]
//	cNext:  c[j+1]
//	sJ:     closing scalar s[j]
func verifyRingCloses(
	curve types.Curve,
	m [32]byte,
	l, r, pubkey, image, h types.Point,
	cJ, cNext, sJ types.Scalar,
) error {
	// check that u*G = s[j]*G + c[j]*P[j]
	cP := curve.ScalarMul(cJ, pubkey)
	sG := curve.ScalarBaseMul(sJ)
	if !cP.Add(sG).Equals(l) {
		return errors.New("failed to close ring: uG != sG + cP")
	}

	// check that u*H_p(P[j]) = s[j]*H_p(P[j]) + c[j]*I
	cI := curve.ScalarMul(cJ, image)
	sH := curve.ScalarMul(sJ, h)
	if !cI.Add(sH).Equals(r) {
		return errors.New("failed to close ring: uH(P) != sH(P) + cI")
	}

	// check that H(m, L[j], R[j]) == c[j+1]
	if !challenge(curve, m, l, r).Eq(cNext) {
		return errors.New("challenge check failed")
	}

	return nil
}
