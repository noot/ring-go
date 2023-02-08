# Benchmarks

The current library benchmarks for signing and verification are located below. For ring signatures, the signing and verification time are linearly proportional to the number of members of the ring (or "anonymity set"), which is what's observed.

> Note: the number directly after `BenchmarkSign` or `BenchmarkVerify` in the test name is the ring size being benchmarked. 

> Note: the ns/op value on the right is the time it took for signing or verification (depending on the test). The middle value is the number of times the operation was executed by the Go benchmarker.

Summary:
- secp256k1 signing and verification is around 0.92ms per ring member
- ed25519 signing and verification is around is around 0.42ms per ring member

```
goos: linux
goarch: amd64
pkg: github.com/noot/ring-go
cpu: Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz

BenchmarkSign2_Secp256k1
BenchmarkSign2_Secp256k1-8       	     439	   2720747 ns/op
BenchmarkSign4_Secp256k1
BenchmarkSign4_Secp256k1-8       	     265	   4592636 ns/op
BenchmarkSign8_Secp256k1
BenchmarkSign8_Secp256k1-8       	     144	   8119283 ns/op
BenchmarkSign16_Secp256k1
BenchmarkSign16_Secp256k1-8      	      70	  15489045 ns/op
BenchmarkSign32_Secp256k1
BenchmarkSign32_Secp256k1-8      	     442	   2655179 ns/op
BenchmarkSign64_Secp256k1
BenchmarkSign64_Secp256k1-8      	      18	  58920929 ns/op
BenchmarkSign128_Secp256k1
BenchmarkSign128_Secp256k1-8     	       9	 118205504 ns/op

BenchmarkSign2_Ed25519
BenchmarkSign2_Ed25519-8         	     984	   1164415 ns/op
BenchmarkSign4_Ed25519
BenchmarkSign4_Ed25519-8         	     600	   1979553 ns/op
BenchmarkSign8_Ed25519
BenchmarkSign8_Ed25519-8         	     321	   3646679 ns/op
BenchmarkSign16_Ed25519
BenchmarkSign16_Ed25519-8        	     165	   7196753 ns/op
BenchmarkSign32_Ed25519
BenchmarkSign32_Ed25519-8        	      78	  13598390 ns/op
BenchmarkSign64_Ed25519
BenchmarkSign64_Ed25519-8        	      38	  26774796 ns/op
BenchmarkSign128_Ed25519
BenchmarkSign128_Ed25519-8       	      19	  53311008 ns/op

BenchmarkVerify2_Secp256k1
BenchmarkVerify2_Secp256k1-8     	     615	   1839778 ns/op
BenchmarkVerify4_Secp256k1
BenchmarkVerify4_Secp256k1-8     	     322	   3585093 ns/op
BenchmarkVerify8_Secp256k1
BenchmarkVerify8_Secp256k1-8     	     158	   7380894 ns/op
BenchmarkVerify16_Secp256k1
BenchmarkVerify16_Secp256k1-8    	      80	  14837867 ns/op
BenchmarkVerify32_Secp256k1
BenchmarkVerify32_Secp256k1-8    	      38	  29946344 ns/op
BenchmarkVerify64_Secp256k1
BenchmarkVerify64_Secp256k1-8    	      18	  62373088 ns/op
BenchmarkVerify128_Secp256k1
BenchmarkVerify128_Secp256k1-8   	       8	 131062030 ns/op

BenchmarkVerify2_Ed25519
BenchmarkVerify2_Ed25519-8       	    1414	    813219 ns/op
BenchmarkVerify4_Ed25519
BenchmarkVerify4_Ed25519-8       	     688	   1655943 ns/op
BenchmarkVerify8_Ed25519
BenchmarkVerify8_Ed25519-8       	     328	   3284147 ns/op
BenchmarkVerify16_Ed25519
BenchmarkVerify16_Ed25519-8      	     180	   6590478 ns/op
BenchmarkVerify32_Ed25519
BenchmarkVerify32_Ed25519-8      	      87	  13433058 ns/op
BenchmarkVerify64_Ed25519
BenchmarkVerify64_Ed25519-8      	      40	  27083394 ns/op
BenchmarkVerify128_Ed25519
BenchmarkVerify128_Ed25519-8     	      19	  55970502 ns/op
```