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

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

type Ring []*ecdsa.PublicKey

type RingSign struct {
	Size  int              // size of ring
	M     [32]byte         // message
	C     *big.Int         // ring signature value
	S     []*big.Int       // ring signature values
	Ring  Ring             // array of public keys
	I     *ecdsa.PublicKey // key image
	Curve elliptic.Curve
}

// helper function, returns type of v
func typeof(v interface{}) string {
	return fmt.Sprintf("%T", v)
}

// bytes returns the public key ring as a byte slice.
func (r Ring) Bytes() (b []byte) {
	for _, pub := range r {
		b = append(b, pub.X.Bytes()...)
		b = append(b, pub.Y.Bytes()...)
	}
	return
}

func PadTo32Bytes(in []byte) (out []byte) {
	out = append(out, in...)
	for {
		if len(out) == 32 {
			return
		}
		out = append([]byte{0}, out...)
	}
}

// converts the signature to a byte array
// this is the format that will be used when passing EVM bytecode
func (r *RingSign) Serialize() ([]byte, error) {
	sig := []byte{}
	// add size and message
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(r.Size))
	sig = append(sig, b[:]...)                      // 8 bytes
	sig = append(sig, PadTo32Bytes(r.M[:])...)      // 32 bytes
	sig = append(sig, PadTo32Bytes(r.C.Bytes())...) // 32 bytes

	// 96 bytes each iteration
	for i := 0; i < r.Size; i++ {
		sig = append(sig, PadTo32Bytes(r.S[i].Bytes())...)
		sig = append(sig, PadTo32Bytes(r.Ring[i].X.Bytes())...)
		sig = append(sig, PadTo32Bytes(r.Ring[i].Y.Bytes())...)
	}

	// 64 bytes
	sig = append(sig, PadTo32Bytes(r.I.X.Bytes())...)
	sig = append(sig, PadTo32Bytes(r.I.Y.Bytes())...)

	if len(sig) != 32*(3*r.Size+4)+8 {
		return []byte{}, errors.New("Could not serialize ring signature")
	}

	return sig, nil
}

// deserializes the byteified signature into a RingSign struct
func Deserialize(r []byte) (*RingSign, error) {
	sig := new(RingSign)
	size := r[0:8]

	if len(r) < 72 {
		return nil, errors.New("incorrect ring size")
	}

	m := r[8:40]

	var m_byte [32]byte
	copy(m_byte[:], m)

	size_uint := binary.BigEndian.Uint64(size)
	size_int := int(size_uint)

	sig.Size = size_int
	sig.M = m_byte
	sig.C = new(big.Int).SetBytes(r[40:72])

	bytelen := size_int * 96

	if len(r) < bytelen+136 {
		return nil, errors.New("incorrect ring size")
	}

	j := 0
	sig.S = make([]*big.Int, size_int)
	sig.Ring = make([]*ecdsa.PublicKey, size_int)

	for i := 72; i < bytelen; i += 96 {
		s_i := r[i : i+32]
		x_i := r[i+32 : i+64]
		y_i := r[i+64 : i+96]

		sig.S[j] = new(big.Int).SetBytes(s_i)
		sig.Ring[j] = new(ecdsa.PublicKey)
		sig.Ring[j].X = new(big.Int).SetBytes(x_i)
		sig.Ring[j].Y = new(big.Int).SetBytes(y_i)
		sig.Ring[j].Curve = crypto.S256()
		j++
	}

	sig.I = new(ecdsa.PublicKey)
	sig.I.X = new(big.Int).SetBytes(r[bytelen+72 : bytelen+104])
	sig.I.Y = new(big.Int).SetBytes(r[bytelen+104 : bytelen+136])
	sig.Curve = crypto.S256()

	return sig, nil
}

// takes public key ring and places the public key corresponding to `privkey` in index s of the ring
// returns a key ring of type []*ecdsa.PublicKey
func GenKeyRing(ring []*ecdsa.PublicKey, privkey *ecdsa.PrivateKey, s int) ([]*ecdsa.PublicKey, error) {
	size := len(ring) + 1
	new_ring := make([]*ecdsa.PublicKey, size)
	pubkey := privkey.Public().(*ecdsa.PublicKey)

	if s > len(ring) {
		return nil, errors.New("index s out of bounds")
	}

	new_ring[s] = pubkey
	for i := 1; i < size; i++ {
		idx := (i + s) % size
		new_ring[idx] = ring[i-1]
	}

	return new_ring, nil
}

// creates a ring with size specified by `size` and places the public key corresponding to `privkey` in index s of the ring
// returns a new key ring of type []*ecdsa.PublicKey
func GenNewKeyRing(size int, privkey *ecdsa.PrivateKey, s int) ([]*ecdsa.PublicKey, error) {
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
func GenKeyImage(privkey *ecdsa.PrivateKey) *ecdsa.PublicKey {
	pubkey := privkey.Public().(*ecdsa.PublicKey)
	image := new(ecdsa.PublicKey)

	// calculate sha3(P)
	h_x, h_y := HashPoint(pubkey)

	// calculate H_p(P) = x * sha3(P) * G
	i_x, i_y := privkey.Curve.ScalarMult(h_x, h_y, privkey.D.Bytes())

	image.X = i_x
	image.Y = i_y
	return image
}

func HashPoint(p *ecdsa.PublicKey) (*big.Int, *big.Int) {
	hash := sha3.Sum256(append(p.X.Bytes(), p.Y.Bytes()...))
	return p.Curve.ScalarBaseMult(hash[:])
}

// create ring signature from list of public keys given inputs:
// msg: byte array, message to be signed
// ring: array of *ecdsa.PublicKeys to be included in the ring
// privkey: *ecdsa.PrivateKey of signer
// s: index of signer in ring
func Sign(m [32]byte, ring []*ecdsa.PublicKey, privkey *ecdsa.PrivateKey, s int) (*RingSign, error) {
	// check ringsize > 1
	ringsize := len(ring)
	if ringsize < 2 {
		return nil, errors.New("size of ring less than two")
	} else if s >= ringsize || s < 0 {
		return nil, errors.New("secret index out of range of ring size")
	}

	// setup
	//pubkey := privkey.Public().(*ecdsa.PublicKey)
	pubkey := &privkey.PublicKey
	curve := pubkey.Curve
	sig := new(RingSign)
	sig.Size = ringsize
	sig.M = m
	sig.Ring = ring
	sig.Curve = curve

	// check that key at index s is indeed the signer
	if ring[s] != pubkey {
		return nil, errors.New("secret index in ring is not signer")
	}

	// generate key image
	image := GenKeyImage(privkey)
	sig.I = image

	// start at c[1]
	// pick random scalar u (glue value), calculate c[1] = H(m, u*G) where H is a hash function and G is the base point of the curve
	C := make([]*big.Int, ringsize)
	S := make([]*big.Int, ringsize)

	// pick random scalar u
	u, err := rand.Int(rand.Reader, curve.Params().P)
	if err != nil {
		return nil, err
	}

	// start at secret index s
	// compute L_s = u*G
	l_x, l_y := curve.ScalarBaseMult(u.Bytes())
	// compute R_s = u*H_p(P[s])
	h_x, h_y := HashPoint(pubkey)
	r_x, r_y := curve.ScalarMult(h_x, h_y, u.Bytes())

	l := append(l_x.Bytes(), l_y.Bytes()...)
	r := append(r_x.Bytes(), r_y.Bytes()...)

	// concatenate m and u*G and calculate c[s+1] = H(m, L_s, R_s)
	C_i := sha3.Sum256(append(m[:], append(l, r...)...))
	idx := (s + 1) % ringsize
	C[idx] = new(big.Int).SetBytes(C_i[:])

	// start loop at s+1
	for i := 1; i < ringsize; i++ {
		idx := (s + i) % ringsize

		// pick random scalar s_i
		s_i, err := rand.Int(rand.Reader, curve.Params().P)
		S[idx] = s_i
		if err != nil {
			return nil, err
		}

		if curve == nil {
			return nil, errors.New(fmt.Sprintf("No curve at index %d", idx))
		}
		if ring[idx] == nil {
			return nil, errors.New(fmt.Sprintf("No public key at index %d", idx))
		}

		// calculate L_i = s_i*G + c_i*P_i
		px, py := curve.ScalarMult(ring[idx].X, ring[idx].Y, C[idx].Bytes()) // px, py = c_i*P_i
		sx, sy := curve.ScalarBaseMult(s_i.Bytes())                          // sx, sy = s[n-1]*G
		l_x, l_y := curve.Add(sx, sy, px, py)

		// calculate R_i = s_i*H_p(P_i) + c_i*I
		px, py = curve.ScalarMult(image.X, image.Y, C[idx].Bytes()) // px, py = c_i*I
		hx, hy := HashPoint(ring[idx])
		sx, sy = curve.ScalarMult(hx, hy, s_i.Bytes()) // sx, sy = s[n-1]*H_p(P_i)
		r_x, r_y := curve.Add(sx, sy, px, py)

		// calculate c[i+1] = H(m, L_i, R_i)
		l := append(l_x.Bytes(), l_y.Bytes()...)
		r := append(r_x.Bytes(), r_y.Bytes()...)
		C_i = sha3.Sum256(append(m[:], append(l, r...)...))

		if i == ringsize-1 {
			C[s] = new(big.Int).SetBytes(C_i[:])
		} else {
			C[(idx+1)%ringsize] = new(big.Int).SetBytes(C_i[:])
		}
	}

	// close ring by finding S[s] = ( u - c[s]*k[s] ) mod P where k[s] is the private key and P is the order of the curve
	S[s] = new(big.Int).Mod(new(big.Int).Sub(u, new(big.Int).Mul(C[s], privkey.D)), curve.Params().N)

	// check that u*G = S[s]*G + c[s]*P[s]
	ux, uy := curve.ScalarBaseMult(u.Bytes()) // u*G
	px, py := curve.ScalarMult(ring[s].X, ring[s].Y, C[s].Bytes())
	sx, sy := curve.ScalarBaseMult(S[s].Bytes())
	l_x, l_y = curve.Add(sx, sy, px, py)

	// check that u*H_p(P[s]) = S[s]*H_p(P[s]) + C[s]*I
	px, py = curve.ScalarMult(image.X, image.Y, C[s].Bytes()) // px, py = C[s]*I
	hx, hy := HashPoint(ring[s])
	tx, ty := curve.ScalarMult(hx, hy, u.Bytes())
	sx, sy = curve.ScalarMult(hx, hy, S[s].Bytes()) // sx, sy = S[s]*H_p(P[s])
	r_x, r_y = curve.Add(sx, sy, px, py)

	l = append(l_x.Bytes(), l_y.Bytes()...)
	r = append(r_x.Bytes(), r_y.Bytes()...)

	// check that H(m, L[s], R[s]) == C[s+1]
	C_i = sha3.Sum256(append(m[:], append(l, r...)...))

	if !bytes.Equal(ux.Bytes(), l_x.Bytes()) || !bytes.Equal(uy.Bytes(), l_y.Bytes()) || !bytes.Equal(tx.Bytes(), r_x.Bytes()) || !bytes.Equal(ty.Bytes(), r_y.Bytes()) { //|| !bytes.Equal(C[(s+1)%ringsize].Bytes(), C_i[:]) {
		return nil, errors.New("error closing ring")
	}

	// everything ok, add values to signature
	sig.S = S
	sig.C = C[0]

	return sig, nil
}

// verify ring signature contained in RingSign struct
// returns true if a valid signature, false otherwise
func Verify(sig *RingSign) bool {
	// setup
	ring := sig.Ring
	ringsize := sig.Size
	S := sig.S
	C := make([]*big.Int, ringsize)
	C[0] = sig.C
	curve := sig.Curve
	image := sig.I

	// calculate c[i+1] = H(m, s[i]*G + c[i]*P[i])
	// and c[0] = H)(m, s[n-1]*G + c[n-1]*P[n-1]) where n is the ring size
	for i := 0; i < ringsize; i++ {
		// calculate L_i = s_i*G + c_i*P_i
		px, py := curve.ScalarMult(ring[i].X, ring[i].Y, C[i].Bytes()) // px, py = c_i*P_i
		sx, sy := curve.ScalarBaseMult(S[i].Bytes())                   // sx, sy = s[i]*G
		l_x, l_y := curve.Add(sx, sy, px, py)

		// calculate R_i = s_i*H_p(P_i) + c_i*I
		px, py = curve.ScalarMult(image.X, image.Y, C[i].Bytes()) // px, py = c[i]*I
		hx, hy := HashPoint(ring[i])
		sx, sy = curve.ScalarMult(hx, hy, S[i].Bytes()) // sx, sy = s[i]*H_p(P[i])
		r_x, r_y := curve.Add(sx, sy, px, py)

		// calculate c[i+1] = H(m, L_i, R_i)
		l := append(l_x.Bytes(), l_y.Bytes()...)
		r := append(r_x.Bytes(), r_y.Bytes()...)
		C_i := sha3.Sum256(append(sig.M[:], append(l, r...)...))

		if i == ringsize-1 {
			C[0] = new(big.Int).SetBytes(C_i[:])
		} else {
			C[i+1] = new(big.Int).SetBytes(C_i[:])
		}
	}

	return bytes.Equal(sig.C.Bytes(), C[0].Bytes())
}

func Link(sig_a *RingSign, sig_b *RingSign) bool {
	return sig_a.I.X.Cmp(sig_b.I.X) == 0 && sig_a.I.Y.Cmp(sig_b.I.Y) == 0
}
