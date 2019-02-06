// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package ringverify

import (
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = abi.U256
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// RingVerifyABI is the input ABI used to generate the binding from.
const RingVerifyABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"_sig\",\"type\":\"bytes\"}],\"name\":\"verify\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"ok\",\"type\":\"bool\"}],\"name\":\"Verify\",\"type\":\"event\"}]"

// RingVerify is an auto generated Go binding around an Ethereum contract.
type RingVerify struct {
	RingVerifyCaller     // Read-only binding to the contract
	RingVerifyTransactor // Write-only binding to the contract
	RingVerifyFilterer   // Log filterer for contract events
}

// RingVerifyCaller is an auto generated read-only Go binding around an Ethereum contract.
type RingVerifyCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RingVerifyTransactor is an auto generated write-only Go binding around an Ethereum contract.
type RingVerifyTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RingVerifyFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type RingVerifyFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RingVerifySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type RingVerifySession struct {
	Contract     *RingVerify       // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// RingVerifyCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type RingVerifyCallerSession struct {
	Contract *RingVerifyCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts     // Call options to use throughout this session
}

// RingVerifyTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type RingVerifyTransactorSession struct {
	Contract     *RingVerifyTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts     // Transaction auth options to use throughout this session
}

// RingVerifyRaw is an auto generated low-level Go binding around an Ethereum contract.
type RingVerifyRaw struct {
	Contract *RingVerify // Generic contract binding to access the raw methods on
}

// RingVerifyCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type RingVerifyCallerRaw struct {
	Contract *RingVerifyCaller // Generic read-only contract binding to access the raw methods on
}

// RingVerifyTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type RingVerifyTransactorRaw struct {
	Contract *RingVerifyTransactor // Generic write-only contract binding to access the raw methods on
}

// NewRingVerify creates a new instance of RingVerify, bound to a specific deployed contract.
func NewRingVerify(address common.Address, backend bind.ContractBackend) (*RingVerify, error) {
	contract, err := bindRingVerify(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &RingVerify{RingVerifyCaller: RingVerifyCaller{contract: contract}, RingVerifyTransactor: RingVerifyTransactor{contract: contract}, RingVerifyFilterer: RingVerifyFilterer{contract: contract}}, nil
}

// NewRingVerifyCaller creates a new read-only instance of RingVerify, bound to a specific deployed contract.
func NewRingVerifyCaller(address common.Address, caller bind.ContractCaller) (*RingVerifyCaller, error) {
	contract, err := bindRingVerify(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &RingVerifyCaller{contract: contract}, nil
}

// NewRingVerifyTransactor creates a new write-only instance of RingVerify, bound to a specific deployed contract.
func NewRingVerifyTransactor(address common.Address, transactor bind.ContractTransactor) (*RingVerifyTransactor, error) {
	contract, err := bindRingVerify(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &RingVerifyTransactor{contract: contract}, nil
}

// NewRingVerifyFilterer creates a new log filterer instance of RingVerify, bound to a specific deployed contract.
func NewRingVerifyFilterer(address common.Address, filterer bind.ContractFilterer) (*RingVerifyFilterer, error) {
	contract, err := bindRingVerify(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &RingVerifyFilterer{contract: contract}, nil
}

// bindRingVerify binds a generic wrapper to an already deployed contract.
func bindRingVerify(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(RingVerifyABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RingVerify *RingVerifyRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _RingVerify.Contract.RingVerifyCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RingVerify *RingVerifyRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RingVerify.Contract.RingVerifyTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RingVerify *RingVerifyRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RingVerify.Contract.RingVerifyTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RingVerify *RingVerifyCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _RingVerify.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RingVerify *RingVerifyTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RingVerify.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RingVerify *RingVerifyTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RingVerify.Contract.contract.Transact(opts, method, params...)
}

// Verify is a paid mutator transaction binding the contract method 0x8e760afe.
//
// Solidity: function verify(_sig bytes) returns(bool)
func (_RingVerify *RingVerifyTransactor) Verify(opts *bind.TransactOpts, _sig []byte) (*types.Transaction, error) {
	return _RingVerify.contract.Transact(opts, "verify", _sig)
}

// Verify is a paid mutator transaction binding the contract method 0x8e760afe.
//
// Solidity: function verify(_sig bytes) returns(bool)
func (_RingVerify *RingVerifySession) Verify(_sig []byte) (*types.Transaction, error) {
	return _RingVerify.Contract.Verify(&_RingVerify.TransactOpts, _sig)
}

// Verify is a paid mutator transaction binding the contract method 0x8e760afe.
//
// Solidity: function verify(_sig bytes) returns(bool)
func (_RingVerify *RingVerifyTransactorSession) Verify(_sig []byte) (*types.Transaction, error) {
	return _RingVerify.Contract.Verify(&_RingVerify.TransactOpts, _sig)
}

// RingVerifyVerifyIterator is returned from FilterVerify and is used to iterate over the raw logs and unpacked data for Verify events raised by the RingVerify contract.
type RingVerifyVerifyIterator struct {
	Event *RingVerifyVerify // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *RingVerifyVerifyIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RingVerifyVerify)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(RingVerifyVerify)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *RingVerifyVerifyIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RingVerifyVerifyIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RingVerifyVerify represents a Verify event raised by the RingVerify contract.
type RingVerifyVerify struct {
	Ok  bool
	Raw types.Log // Blockchain specific contextual infos
}

// FilterVerify is a free log retrieval operation binding the contract event 0xa0c1fc382db99c490561b48be7ef277080a844c158e8a35ba8aabd16c0320450.
//
// Solidity: e Verify(ok indexed bool)
func (_RingVerify *RingVerifyFilterer) FilterVerify(opts *bind.FilterOpts, ok []bool) (*RingVerifyVerifyIterator, error) {

	var okRule []interface{}
	for _, okItem := range ok {
		okRule = append(okRule, okItem)
	}

	logs, sub, err := _RingVerify.contract.FilterLogs(opts, "Verify", okRule)
	if err != nil {
		return nil, err
	}
	return &RingVerifyVerifyIterator{contract: _RingVerify.contract, event: "Verify", logs: logs, sub: sub}, nil
}

// WatchVerify is a free log subscription operation binding the contract event 0xa0c1fc382db99c490561b48be7ef277080a844c158e8a35ba8aabd16c0320450.
//
// Solidity: e Verify(ok indexed bool)
func (_RingVerify *RingVerifyFilterer) WatchVerify(opts *bind.WatchOpts, sink chan<- *RingVerifyVerify, ok []bool) (event.Subscription, error) {

	var okRule []interface{}
	for _, okItem := range ok {
		okRule = append(okRule, okItem)
	}

	logs, sub, err := _RingVerify.contract.WatchLogs(opts, "Verify", okRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RingVerifyVerify)
				if err := _RingVerify.contract.UnpackLog(event, "Verify", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}
