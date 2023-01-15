package ring

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/athanorlabs/go-dleq/types"
)

// Serialize converts the signature to a byte array.
func (r *RingSig) Serialize() ([]byte, error) {
	sig := []byte{}
	size := len(r.ring.pubkeys)

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(size))
	sig = append(sig, b[:]...)
	sig = append(sig, r.c.Encode()...)
	sig = append(sig, r.image.Encode()...)

	for i := 0; i < size; i++ {
		sig = append(sig, r.s[i].Encode()...)
		sig = append(sig, r.ring.pubkeys[i].Encode()...)
	}

	return sig, nil
}

// Deserialize converts the byteified signature into a *RingSig.
func (sig *RingSig) Deserialize(curve Curve, in []byte) error {
	reader := bytes.NewBuffer(in)
	pointLen := curve.CompressedPointSize()

	size := binary.BigEndian.Uint32(reader.Next(4))
	if len(in) < int(size)*pointLen {
		return errors.New("input too short")
	}

	// WARN: this assumes the groups have an encoded scalar length of 32!
	// which is fine for ed25519 and secp256k1, but may need to be changed
	// if other curves are added.
	const scalarLen = 32

	var err error
	sig.c, err = curve.DecodeToScalar(reader.Next(scalarLen))
	if err != nil {
		return err
	}

	sig.image, err = curve.DecodeToPoint(reader.Next(pointLen))
	if err != nil {
		return err
	}

	sig.ring = &Ring{
		pubkeys: make([]types.Point, size),
		curve:   curve,
	}
	sig.s = make([]types.Scalar, size)

	for i := 0; i < int(size); i++ {
		sig.s[i], err = curve.DecodeToScalar(reader.Next(scalarLen))
		if err != nil {
			return err
		}

		sig.ring.pubkeys[i], err = curve.DecodeToPoint(reader.Next(pointLen))
		if err != nil {
			return err
		}
	}

	return nil
}
