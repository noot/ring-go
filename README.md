# ring-go
implementation of ring signatures using ecc in go

### requirements
go 1.10

### get
`go get github.com/noot/ring-go`

### usage
the algorithm including `Sign()` and `Verify()` are located in `ring/ring.go`.
`message.txt` contains a message to be signed with a ring.
in `main.go` a private key is imported, a ring of random public keys is generated, and a ring signature is created using the random public keys as well as the public key corresponding to the provided private key.

### todo
* implement signing with key images
* implement binary/hex signature output

### references
this implementation is loosely based off of Ring Confidential Transactions. https://eprint.iacr.org/2015/1098.pdf
