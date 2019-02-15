package ringverify

import (
	//"context"
	"crypto/ecdsa"
	//"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noot/ring-go/ring"
	"golang.org/x/crypto/sha3"

	//ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type testAccount struct {
	addr         common.Address
	contract     *RingVerify
	contractAddr common.Address
	backend      *backends.SimulatedBackend
	txOpts       *bind.TransactOpts
}

func setup() (*testAccount, error) {
	genesis := make(core.GenesisAlloc)
	privKey, _ := crypto.GenerateKey()
	pubKeyECDSA, ok := privKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}

	// strip off the 0x and the first 2 characters 04 which is always the EC prefix and is not required.
	publicKeyBytes := crypto.FromECDSAPub(pubKeyECDSA)[4:]
	var pubKey = make([]byte, 48)
	copy(pubKey[:], []byte(publicKeyBytes))

	addr := crypto.PubkeyToAddress(privKey.PublicKey)
	txOpts := bind.NewKeyedTransactor(privKey)
	txOpts.GasLimit = 6700000
	startingBalance, _ := new(big.Int).SetString("100000000000000000000000000000000000000", 10)
	genesis[addr] = core.GenesisAccount{Balance: startingBalance}
	backend := backends.NewSimulatedBackend(genesis, 210000000000)

	contractAddr, _, contract, err := DeployRingVerify(txOpts, backend)
	if err != nil {
		return nil, err
	}

	return &testAccount{addr, contract, contractAddr, backend, txOpts}, nil
}

// deploys a new Ethereum contract, binding an instance of BridgeContract to it.
func DeployRingVerify(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *RingVerify, error) {
	rvabi, err := abi.JSON(strings.NewReader(RingVerifyABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	fp, err := filepath.Abs("./build/RingVerify.bin")
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	bin, err := ioutil.ReadFile(fp)
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	address, tx, contract, err := bind.DeployContract(auth, rvabi, bin, backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &RingVerify{RingVerifyCaller: RingVerifyCaller{contract: contract}, RingVerifyTransactor: RingVerifyTransactor{contract: contract}, RingVerifyFilterer: RingVerifyFilterer{contract: contract}}, nil
}

func TestSetup(t *testing.T) {
	_, err := setup()
	if err != nil {
		t.Errorf("Cannot deploy RingVerify: %v", err)
	}
}

func TestVerify(t *testing.T) {
	test, err := setup()
	if err != nil {
		t.Errorf("Cannot deploy RingVerify: %v", err)
	}	

	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	msg := "helloworld"
	msgHash := sha3.Sum256([]byte(msg))
	keyring, err := ring.GenNewKeyRing(2, privkey, 0)
	if err != nil {
		t.Error(err)
	}
	
	sig, err := ring.Sign(msgHash, keyring, privkey, 0)
	if err != nil {
		t.Error("error when signing with ring size of 2")
	} else {
		t.Log("signing ok with ring size of 2")
	}

	sigBytes, err := sig.Serialize()
	if err != nil {
		t.Error(err)
	}

	_, err = test.contract.Verify(test.txOpts, sigBytes)
	if err != nil {
		t.Error(err)
	}
}