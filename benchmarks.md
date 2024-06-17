# Benchmarks

The current library benchmarks for signing and verification are located below. For ring signatures, the signing and verification time are linearly proportional to the number of members of the ring (or "anonymity set"), which is what's observed.

> Note: the number directly after `BenchmarkSign` or `BenchmarkVerify` in the test name is the ring size being benchmarked. 

> Note: the ns/op value on the right is the time it took for signing or verification (depending on the test). The middle value is the number of times the operation was executed by the Go benchmarker.

Summary:
- secp256k1 signing and verification is around 0.41ms per ring member
- ed25519 signing and verification is around is around 0.12ms per ring member

```
goos: linux
goarch: amd64
pkg: github.com/noot/ring-go
cpu: 12th Gen Intel(R) Core(TM) i7-1280P

BenchmarkSign2_Secp256k1-20                 1075           1113687 ns/op
BenchmarkSign4_Secp256k1-20                  651           1832647 ns/op
BenchmarkSign8_Secp256k1-20                  334           3389785 ns/op
BenchmarkSign16_Secp256k1-20                 184           6279636 ns/op
BenchmarkSign32_Secp256k1-20                  86          12556732 ns/op
BenchmarkSign64_Secp256k1-20                  44          24592647 ns/op
BenchmarkSign128_Secp256k1-20                 21          47949180 ns/op

BenchmarkSign2_Ed25519-20                   3184            338455 ns/op
BenchmarkSign4_Ed25519-20                   2102            561543 ns/op
BenchmarkSign8_Ed25519-20                   1141           1024334 ns/op
BenchmarkSign16_Ed25519-20                   601           1959393 ns/op
BenchmarkSign32_Ed25519-20                   312           3812862 ns/op
BenchmarkSign64_Ed25519-20                   158           7554431 ns/op
BenchmarkSign128_Ed25519-20                   72          15137610 ns/op

BenchmarkVerify2_Secp256k1-20               1647            759506 ns/op
BenchmarkVerify4_Secp256k1-20                788           1507848 ns/op
BenchmarkVerify8_Secp256k1-20                391           3060683 ns/op
BenchmarkVerify16_Secp256k1-20               193           6173042 ns/op
BenchmarkVerify32_Secp256k1-20                93          12352394 ns/op
BenchmarkVerify64_Secp256k1-20                45          25246452 ns/op
BenchmarkVerify128_Secp256k1-20               21          51882164 ns/op

BenchmarkVerify2_Ed25519-20                 4797            238406 ns/op
BenchmarkVerify4_Ed25519-20                 2349            457389 ns/op
BenchmarkVerify8_Ed25519-20                 1244            932592 ns/op
BenchmarkVerify16_Ed25519-20                 636           1823156 ns/op
BenchmarkVerify32_Ed25519-20                 320           3781398 ns/op
BenchmarkVerify64_Ed25519-20                 156           7524581 ns/op
BenchmarkVerify128_Ed25519-20                 78          14955353 ns/op
```
