# ring-go
implementation of linkable ring signatures using elliptic curve crypto in go

### requirements
go 1.19

### get
`go get github.com/noot/ring-go`

### references
this implementation is based off of Ring Confidential Transactions. https://eprint.iacr.org/2015/1098.pdf

### usage

See `examples/main.go`.

```go
package main

import (
	"fmt"

	ring "github.com/noot/ring-go"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

func main() {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}

	msg := "helloworld"
	msgHash := sha3.Sum256([]byte(msg))
	const size = 16
	const idx = 7

	keyring, err := ring.GenNewKeyRing(size, privkey, idx)
	if err != nil {
		panic(err)
	}

	sig, err := ring.Sign(msgHash, keyring, privkey, idx)
	if err != nil {
		panic(err)
	}

	ok := ring.Verify(sig)
	if !ok {
		fmt.Println("failed to verify :(")
		return
	}

	fmt.Println("verified signature!")
}
```