package ring

import (
	"testing"

	"github.com/athanorlabs/go-dleq/types"
)

const idx = 0

func benchmarkSign(b *testing.B, curve types.Curve, keyring *Ring, privkey types.Scalar, size, idx int) {
	for i := 0; i < b.N; i++ {
		_, err := keyring.Sign(testMsg, privkey)
		if err != nil {
			panic(err)
		}
	}
}

func mustKeyRing(curve types.Curve, privkey types.Scalar, size, idx int) *Ring {
	keyring, err := NewKeyRing(curve, size, privkey, idx)
	if err != nil {
		panic(err)
	}
	return keyring
}

func BenchmarkSign2_Secp256k1(b *testing.B) {
	const size = 2
	curve := Secp256k1()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func BenchmarkSign4_Secp256k1(b *testing.B) {
	const size = 4
	curve := Secp256k1()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func BenchmarkSign8_Secp256k1(b *testing.B) {
	const size = 8
	curve := Secp256k1()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func BenchmarkSign16_Secp256k1(b *testing.B) {
	const size = 16
	curve := Secp256k1()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func BenchmarkSign32_Secp256k1(b *testing.B) {
	const size = 2
	curve := Secp256k1()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func BenchmarkSign64_Secp256k1(b *testing.B) {
	const size = 64
	curve := Secp256k1()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func BenchmarkSign128_Secp256k1(b *testing.B) {
	const size = 128
	curve := Secp256k1()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func BenchmarkSign2_Ed25519(b *testing.B) {
	const size = 2
	curve := Ed25519()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func BenchmarkSign4_Ed25519(b *testing.B) {
	const size = 4
	curve := Ed25519()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func BenchmarkSign8_Ed25519(b *testing.B) {
	const size = 8
	curve := Ed25519()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func BenchmarkSign16_Ed25519(b *testing.B) {
	const size = 16
	curve := Ed25519()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func BenchmarkSign32_Ed25519(b *testing.B) {
	const size = 32
	curve := Ed25519()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func BenchmarkSign64_Ed25519(b *testing.B) {
	const size = 64
	curve := Ed25519()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func BenchmarkSign128_Ed25519(b *testing.B) {
	const size = 128
	curve := Ed25519()
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)
	benchmarkSign(b, curve, keyring, privkey, size, idx)
}

func benchmarkVerify(b *testing.B, sig *RingSig) {
	for i := 0; i < b.N; i++ {
		ok := sig.Verify(testMsg)
		if !ok {
			panic("did not verify signature")
		}
	}
}

func mustSig(curve types.Curve, size int) *RingSig {
	privkey := curve.NewRandomScalar()
	keyring := mustKeyRing(curve, privkey, size, idx)

	sig, err := keyring.Sign(testMsg, privkey)
	if err != nil {
		panic(err)
	}

	return sig
}

func BenchmarkVerify2_Secp256k1(b *testing.B) {
	const size = 2
	curve := Secp256k1()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}

func BenchmarkVerify4_Secp256k1(b *testing.B) {
	const size = 4
	curve := Secp256k1()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}

func BenchmarkVerify8_Secp256k1(b *testing.B) {
	const size = 8
	curve := Secp256k1()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}

func BenchmarkVerify16_Secp256k1(b *testing.B) {
	const size = 16
	curve := Secp256k1()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}

func BenchmarkVerify32_Secp256k1(b *testing.B) {
	const size = 32
	curve := Secp256k1()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}

func BenchmarkVerify64_Secp256k1(b *testing.B) {
	const size = 64
	curve := Secp256k1()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}

func BenchmarkVerify128_Secp256k1(b *testing.B) {
	const size = 128
	curve := Secp256k1()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}

func BenchmarkVerify2_Ed25519(b *testing.B) {
	const size = 2
	curve := Ed25519()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}

func BenchmarkVerify4_Ed25519(b *testing.B) {
	const size = 4
	curve := Ed25519()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}

func BenchmarkVerify8_Ed25519(b *testing.B) {
	const size = 8
	curve := Ed25519()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}

func BenchmarkVerify16_Ed25519(b *testing.B) {
	const size = 16
	curve := Ed25519()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}

func BenchmarkVerify32_Ed25519(b *testing.B) {
	const size = 32
	curve := Ed25519()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}

func BenchmarkVerify64_Ed25519(b *testing.B) {
	const size = 64
	curve := Ed25519()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}

func BenchmarkVerify128_Ed25519(b *testing.B) {
	const size = 128
	curve := Ed25519()
	sig := mustSig(curve, size)
	benchmarkVerify(b, sig)
}
