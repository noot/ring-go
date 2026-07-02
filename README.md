# ring-go <!-- omit in toc -->

Implementation of linkable ring signatures using elliptic curve crypto in Go.
It supports ring signatures over both ed25519 and secp256k1.

- [Requirements](#requirements)
- [Install](#install)
- [References](#references)
- [Usage](#usage)
- [Signing paths: on-chain vs off-chain](#signing-paths-on-chain-vs-off-chain)

## Requirements

go 1.26

## Install

`go get github.com/pokt-network/ring-go`

## References

This implementation is based off of [Ring Confidential Transactions](https://eprint.iacr.org/2015/1098.pdf), in particular section 2, which defines MLSAG (Multilayered Linkable Spontaneous Anonymous Group signatures).

## Usage

See `examples/main.go`.

```go
package main

import (
    "fmt"

    ring "github.com/pokt-network/ring-go"
    "golang.org/x/crypto/sha3"
)

func signAndVerify(curve ring.Curve) {
    privKey := curve.NewRandomScalar()
    msgHash := sha3.Sum256([]byte("helloworld"))

    // size of the public key ring (anonymity set)
    const size = 16

    // our key's secret index within the set
    const idx = 7

    keyring, err := ring.NewKeyRing(curve, size, privKey, idx)
    if err != nil {
        panic(err)
    }

    sig, err := keyring.Sign(msgHash, privKey)
    if err != nil {
        panic(err)
    }

    ok := sig.Verify(msgHash)
    if !ok {
        fmt.Println("failed to verify :(")
        return
    }

    fmt.Println("verified signature!")
}

func main() {
    fmt.Println("using secp256k1...")
    signAndVerify(ring.Secp256k1())
    fmt.Println("using ed25519...")
    signAndVerify(ring.Ed25519())
}
```

## Signing paths: on-chain vs off-chain

There are two ways to sign. They produce interchangeable signatures — `Verify`
and `Link` behave identically — but they differ in **how much work they do**,
which matters if you run inside consensus.

### `Sign` — default, consensus-safe

```go
sig, err := keyring.Sign(msgHash, privKey)
```

`Sign` (and `Verify`) perform a fixed amount of work that does not depend on any
cache, shared state, or call history. The cost is therefore **deterministic
across nodes**. Use this path on-chain / in gas-metered code. It carries no
extra state and requires no setup.

### `SignWithContext` — off-chain fast path

```go
ctx, err := keyring.NewSignerContext(privKey) // pre-compute once (does NOT store the key)
ctx.SkipSelfCheck = true                       // optional, off-chain only

sig, err := keyring.SignWithContext(msgHash, privKey, ctx) // key passed per call; reuse ctx
```

`NewSignerContext` pre-computes, once, the values that are constant across
messages for a given `(privKey, ring)`: the signer's public key, key image, and
the hash-to-curve of every ring member. Signing many messages then reuses that
work. All precomputed state lives on the caller-owned `SignerContext`; the
`Ring` is never mutated.

The context holds **no secret material** — every field is derived from public
data (the key image and public key are already published in signatures). The
private key is **not** retained; it is supplied per call to `SignWithContext`,
exactly as with `Sign`. So a `SignerContext` is safe to hold, reuse, and pass
around.

> ⚠️ **Off-chain only.** Because `SignWithContext` does less work than `Sign`,
> its cost is **not** identical across calls or nodes. Do **not** use it on
> consensus-critical or gas-metered paths — use `Sign` there. A context is tied
> to one ring and one key: pass the key it was built for (a mismatch yields an
> invalid signature, caught by the self-check). Setting `SkipSelfCheck = true`
> drops the closing self-checks (~4 scalar multiplications) — and with them the
> mismatch guard — an off-chain speed trade only.

### Benchmarked gains

Measured with `go test -bench . -benchmem` (Apple M1). Allocations are
deterministic and machine-independent; wall-clock is directional and varies by
machine, so reproduce it on your own hardware. Numbers below keep the self-check
on (`SkipSelfCheck = false`); enabling it saves a little more.

| curve · ring size | `Sign` allocs/op | `SignWithContext` allocs/op | reduction |
| ----------------- | ---------------: | --------------------------: | --------: |
| secp256k1 · 8     |              235 |                         205 |    ~-13%  |
| secp256k1 · 32    |              861 |                         762 |    ~-11%  |
| ed25519 · 8       |              202 |                         169 |    ~-16%  |

The saving comes from not recomputing every ring member's hash-to-curve on each
signature; it grows with how many times you reuse the same context. Run the
suite yourself with `make benchmark_all` (see `bench_test.go`).

