// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package ringmixer

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

// RingMixerABI is the input ABI used to generate the binding from.
const RingMixerABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"_to\",\"type\":\"address\"},{\"name\":\"_sig\",\"type\":\"bytes\"}],\"name\":\"withdraw\",\"outputs\":[{\"name\":\"ok\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"SIGLEN\",\"outputs\":[{\"name\":\"\",\"type\":\"uint8\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"VAL\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"SIZE\",\"outputs\":[{\"name\":\"\",\"type\":\"uint8\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"sigs\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_x\",\"type\":\"uint256\"},{\"name\":\"_y\",\"type\":\"uint256\"}],\"name\":\"deposit\",\"outputs\":[],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"_addr\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_x\",\"type\":\"uint256\"},{\"indexed\":false,\"name\":\"_y\",\"type\":\"uint256\"}],\"name\":\"PublicKeySubmission\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[],\"name\":\"DepositsCompleted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"_to\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"Transaction\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[],\"name\":\"WithdrawalsCompleted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[],\"name\":\"RoundFinished\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"ok\",\"type\":\"bool\"}],\"name\":\"Verify\",\"type\":\"event\"}]"

// RingMixer is an auto generated Go binding around an Ethereum contract.
type RingMixer struct {
	RingMixerCaller     // Read-only binding to the contract
	RingMixerTransactor // Write-only binding to the contract
	RingMixerFilterer   // Log filterer for contract events
}

// RingMixerCaller is an auto generated read-only Go binding around an Ethereum contract.
type RingMixerCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RingMixerTransactor is an auto generated write-only Go binding around an Ethereum contract.
type RingMixerTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RingMixerFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type RingMixerFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RingMixerSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type RingMixerSession struct {
	Contract     *RingMixer        // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// RingMixerCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type RingMixerCallerSession struct {
	Contract *RingMixerCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts    // Call options to use throughout this session
}

// RingMixerTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type RingMixerTransactorSession struct {
	Contract     *RingMixerTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// RingMixerRaw is an auto generated low-level Go binding around an Ethereum contract.
type RingMixerRaw struct {
	Contract *RingMixer // Generic contract binding to access the raw methods on
}

// RingMixerCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type RingMixerCallerRaw struct {
	Contract *RingMixerCaller // Generic read-only contract binding to access the raw methods on
}

// RingMixerTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type RingMixerTransactorRaw struct {
	Contract *RingMixerTransactor // Generic write-only contract binding to access the raw methods on
}

// NewRingMixer creates a new instance of RingMixer, bound to a specific deployed contract.
func NewRingMixer(address common.Address, backend bind.ContractBackend) (*RingMixer, error) {
	contract, err := bindRingMixer(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &RingMixer{RingMixerCaller: RingMixerCaller{contract: contract}, RingMixerTransactor: RingMixerTransactor{contract: contract}, RingMixerFilterer: RingMixerFilterer{contract: contract}}, nil
}

// NewRingMixerCaller creates a new read-only instance of RingMixer, bound to a specific deployed contract.
func NewRingMixerCaller(address common.Address, caller bind.ContractCaller) (*RingMixerCaller, error) {
	contract, err := bindRingMixer(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &RingMixerCaller{contract: contract}, nil
}

// NewRingMixerTransactor creates a new write-only instance of RingMixer, bound to a specific deployed contract.
func NewRingMixerTransactor(address common.Address, transactor bind.ContractTransactor) (*RingMixerTransactor, error) {
	contract, err := bindRingMixer(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &RingMixerTransactor{contract: contract}, nil
}

// NewRingMixerFilterer creates a new log filterer instance of RingMixer, bound to a specific deployed contract.
func NewRingMixerFilterer(address common.Address, filterer bind.ContractFilterer) (*RingMixerFilterer, error) {
	contract, err := bindRingMixer(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &RingMixerFilterer{contract: contract}, nil
}

// bindRingMixer binds a generic wrapper to an already deployed contract.
func bindRingMixer(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(RingMixerABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RingMixer *RingMixerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _RingMixer.Contract.RingMixerCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RingMixer *RingMixerRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RingMixer.Contract.RingMixerTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RingMixer *RingMixerRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RingMixer.Contract.RingMixerTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RingMixer *RingMixerCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _RingMixer.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RingMixer *RingMixerTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RingMixer.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RingMixer *RingMixerTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RingMixer.Contract.contract.Transact(opts, method, params...)
}

// SIGLEN is a free data retrieval call binding the contract method 0x5a68da31.
//
// Solidity: function SIGLEN() constant returns(uint8)
func (_RingMixer *RingMixerCaller) SIGLEN(opts *bind.CallOpts) (uint8, error) {
	var (
		ret0 = new(uint8)
	)
	out := ret0
	err := _RingMixer.contract.Call(opts, out, "SIGLEN")
	return *ret0, err
}

// SIGLEN is a free data retrieval call binding the contract method 0x5a68da31.
//
// Solidity: function SIGLEN() constant returns(uint8)
func (_RingMixer *RingMixerSession) SIGLEN() (uint8, error) {
	return _RingMixer.Contract.SIGLEN(&_RingMixer.CallOpts)
}

// SIGLEN is a free data retrieval call binding the contract method 0x5a68da31.
//
// Solidity: function SIGLEN() constant returns(uint8)
func (_RingMixer *RingMixerCallerSession) SIGLEN() (uint8, error) {
	return _RingMixer.Contract.SIGLEN(&_RingMixer.CallOpts)
}

// SIZE is a free data retrieval call binding the contract method 0xbdffd282.
//
// Solidity: function SIZE() constant returns(uint8)
func (_RingMixer *RingMixerCaller) SIZE(opts *bind.CallOpts) (uint8, error) {
	var (
		ret0 = new(uint8)
	)
	out := ret0
	err := _RingMixer.contract.Call(opts, out, "SIZE")
	return *ret0, err
}

// SIZE is a free data retrieval call binding the contract method 0xbdffd282.
//
// Solidity: function SIZE() constant returns(uint8)
func (_RingMixer *RingMixerSession) SIZE() (uint8, error) {
	return _RingMixer.Contract.SIZE(&_RingMixer.CallOpts)
}

// SIZE is a free data retrieval call binding the contract method 0xbdffd282.
//
// Solidity: function SIZE() constant returns(uint8)
func (_RingMixer *RingMixerCallerSession) SIZE() (uint8, error) {
	return _RingMixer.Contract.SIZE(&_RingMixer.CallOpts)
}

// VAL is a free data retrieval call binding the contract method 0x7cb461a2.
//
// Solidity: function VAL() constant returns(uint256)
func (_RingMixer *RingMixerCaller) VAL(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _RingMixer.contract.Call(opts, out, "VAL")
	return *ret0, err
}

// VAL is a free data retrieval call binding the contract method 0x7cb461a2.
//
// Solidity: function VAL() constant returns(uint256)
func (_RingMixer *RingMixerSession) VAL() (*big.Int, error) {
	return _RingMixer.Contract.VAL(&_RingMixer.CallOpts)
}

// VAL is a free data retrieval call binding the contract method 0x7cb461a2.
//
// Solidity: function VAL() constant returns(uint256)
func (_RingMixer *RingMixerCallerSession) VAL() (*big.Int, error) {
	return _RingMixer.Contract.VAL(&_RingMixer.CallOpts)
}

// Sigs is a free data retrieval call binding the contract method 0xbfe5d9e1.
//
// Solidity: function sigs( uint256) constant returns(bytes)
func (_RingMixer *RingMixerCaller) Sigs(opts *bind.CallOpts, arg0 *big.Int) ([]byte, error) {
	var (
		ret0 = new([]byte)
	)
	out := ret0
	err := _RingMixer.contract.Call(opts, out, "sigs", arg0)
	return *ret0, err
}

// Sigs is a free data retrieval call binding the contract method 0xbfe5d9e1.
//
// Solidity: function sigs( uint256) constant returns(bytes)
func (_RingMixer *RingMixerSession) Sigs(arg0 *big.Int) ([]byte, error) {
	return _RingMixer.Contract.Sigs(&_RingMixer.CallOpts, arg0)
}

// Sigs is a free data retrieval call binding the contract method 0xbfe5d9e1.
//
// Solidity: function sigs( uint256) constant returns(bytes)
func (_RingMixer *RingMixerCallerSession) Sigs(arg0 *big.Int) ([]byte, error) {
	return _RingMixer.Contract.Sigs(&_RingMixer.CallOpts, arg0)
}

// Deposit is a paid mutator transaction binding the contract method 0xe2bbb158.
//
// Solidity: function deposit(_x uint256, _y uint256) returns()
func (_RingMixer *RingMixerTransactor) Deposit(opts *bind.TransactOpts, _x *big.Int, _y *big.Int) (*types.Transaction, error) {
	return _RingMixer.contract.Transact(opts, "deposit", _x, _y)
}

// Deposit is a paid mutator transaction binding the contract method 0xe2bbb158.
//
// Solidity: function deposit(_x uint256, _y uint256) returns()
func (_RingMixer *RingMixerSession) Deposit(_x *big.Int, _y *big.Int) (*types.Transaction, error) {
	return _RingMixer.Contract.Deposit(&_RingMixer.TransactOpts, _x, _y)
}

// Deposit is a paid mutator transaction binding the contract method 0xe2bbb158.
//
// Solidity: function deposit(_x uint256, _y uint256) returns()
func (_RingMixer *RingMixerTransactorSession) Deposit(_x *big.Int, _y *big.Int) (*types.Transaction, error) {
	return _RingMixer.Contract.Deposit(&_RingMixer.TransactOpts, _x, _y)
}

// Withdraw is a paid mutator transaction binding the contract method 0x4bb78b14.
//
// Solidity: function withdraw(_to address, _sig bytes) returns(ok bool)
func (_RingMixer *RingMixerTransactor) Withdraw(opts *bind.TransactOpts, _to common.Address, _sig []byte) (*types.Transaction, error) {
	return _RingMixer.contract.Transact(opts, "withdraw", _to, _sig)
}

// Withdraw is a paid mutator transaction binding the contract method 0x4bb78b14.
//
// Solidity: function withdraw(_to address, _sig bytes) returns(ok bool)
func (_RingMixer *RingMixerSession) Withdraw(_to common.Address, _sig []byte) (*types.Transaction, error) {
	return _RingMixer.Contract.Withdraw(&_RingMixer.TransactOpts, _to, _sig)
}

// Withdraw is a paid mutator transaction binding the contract method 0x4bb78b14.
//
// Solidity: function withdraw(_to address, _sig bytes) returns(ok bool)
func (_RingMixer *RingMixerTransactorSession) Withdraw(_to common.Address, _sig []byte) (*types.Transaction, error) {
	return _RingMixer.Contract.Withdraw(&_RingMixer.TransactOpts, _to, _sig)
}

// RingMixerDepositsCompletedIterator is returned from FilterDepositsCompleted and is used to iterate over the raw logs and unpacked data for DepositsCompleted events raised by the RingMixer contract.
type RingMixerDepositsCompletedIterator struct {
	Event *RingMixerDepositsCompleted // Event containing the contract specifics and raw log

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
func (it *RingMixerDepositsCompletedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RingMixerDepositsCompleted)
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
		it.Event = new(RingMixerDepositsCompleted)
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
func (it *RingMixerDepositsCompletedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RingMixerDepositsCompletedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RingMixerDepositsCompleted represents a DepositsCompleted event raised by the RingMixer contract.
type RingMixerDepositsCompleted struct {
	Raw types.Log // Blockchain specific contextual infos
}

// FilterDepositsCompleted is a free log retrieval operation binding the contract event 0xe1a14c1263a6d59b1fb1644a0fd870d6bdb07ff65dd7daac744d0519671cf8f2.
//
// Solidity: e DepositsCompleted()
func (_RingMixer *RingMixerFilterer) FilterDepositsCompleted(opts *bind.FilterOpts) (*RingMixerDepositsCompletedIterator, error) {

	logs, sub, err := _RingMixer.contract.FilterLogs(opts, "DepositsCompleted")
	if err != nil {
		return nil, err
	}
	return &RingMixerDepositsCompletedIterator{contract: _RingMixer.contract, event: "DepositsCompleted", logs: logs, sub: sub}, nil
}

// WatchDepositsCompleted is a free log subscription operation binding the contract event 0xe1a14c1263a6d59b1fb1644a0fd870d6bdb07ff65dd7daac744d0519671cf8f2.
//
// Solidity: e DepositsCompleted()
func (_RingMixer *RingMixerFilterer) WatchDepositsCompleted(opts *bind.WatchOpts, sink chan<- *RingMixerDepositsCompleted) (event.Subscription, error) {

	logs, sub, err := _RingMixer.contract.WatchLogs(opts, "DepositsCompleted")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RingMixerDepositsCompleted)
				if err := _RingMixer.contract.UnpackLog(event, "DepositsCompleted", log); err != nil {
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

// RingMixerPublicKeySubmissionIterator is returned from FilterPublicKeySubmission and is used to iterate over the raw logs and unpacked data for PublicKeySubmission events raised by the RingMixer contract.
type RingMixerPublicKeySubmissionIterator struct {
	Event *RingMixerPublicKeySubmission // Event containing the contract specifics and raw log

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
func (it *RingMixerPublicKeySubmissionIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RingMixerPublicKeySubmission)
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
		it.Event = new(RingMixerPublicKeySubmission)
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
func (it *RingMixerPublicKeySubmissionIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RingMixerPublicKeySubmissionIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RingMixerPublicKeySubmission represents a PublicKeySubmission event raised by the RingMixer contract.
type RingMixerPublicKeySubmission struct {
	Addr common.Address
	X    *big.Int
	Y    *big.Int
	Raw  types.Log // Blockchain specific contextual infos
}

// FilterPublicKeySubmission is a free log retrieval operation binding the contract event 0xf4bc0035099d472fc7d0bc842e1826c350b3ab3b1f925eadc1dd8e6819d35e1d.
//
// Solidity: e PublicKeySubmission(_addr address, _x uint256, _y uint256)
func (_RingMixer *RingMixerFilterer) FilterPublicKeySubmission(opts *bind.FilterOpts) (*RingMixerPublicKeySubmissionIterator, error) {

	logs, sub, err := _RingMixer.contract.FilterLogs(opts, "PublicKeySubmission")
	if err != nil {
		return nil, err
	}
	return &RingMixerPublicKeySubmissionIterator{contract: _RingMixer.contract, event: "PublicKeySubmission", logs: logs, sub: sub}, nil
}

// WatchPublicKeySubmission is a free log subscription operation binding the contract event 0xf4bc0035099d472fc7d0bc842e1826c350b3ab3b1f925eadc1dd8e6819d35e1d.
//
// Solidity: e PublicKeySubmission(_addr address, _x uint256, _y uint256)
func (_RingMixer *RingMixerFilterer) WatchPublicKeySubmission(opts *bind.WatchOpts, sink chan<- *RingMixerPublicKeySubmission) (event.Subscription, error) {

	logs, sub, err := _RingMixer.contract.WatchLogs(opts, "PublicKeySubmission")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RingMixerPublicKeySubmission)
				if err := _RingMixer.contract.UnpackLog(event, "PublicKeySubmission", log); err != nil {
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

// RingMixerRoundFinishedIterator is returned from FilterRoundFinished and is used to iterate over the raw logs and unpacked data for RoundFinished events raised by the RingMixer contract.
type RingMixerRoundFinishedIterator struct {
	Event *RingMixerRoundFinished // Event containing the contract specifics and raw log

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
func (it *RingMixerRoundFinishedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RingMixerRoundFinished)
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
		it.Event = new(RingMixerRoundFinished)
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
func (it *RingMixerRoundFinishedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RingMixerRoundFinishedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RingMixerRoundFinished represents a RoundFinished event raised by the RingMixer contract.
type RingMixerRoundFinished struct {
	Raw types.Log // Blockchain specific contextual infos
}

// FilterRoundFinished is a free log retrieval operation binding the contract event 0xb39c645aef2ec42857f91918de2794aa7e86c524d4461c4bac26d13e870c6015.
//
// Solidity: e RoundFinished()
func (_RingMixer *RingMixerFilterer) FilterRoundFinished(opts *bind.FilterOpts) (*RingMixerRoundFinishedIterator, error) {

	logs, sub, err := _RingMixer.contract.FilterLogs(opts, "RoundFinished")
	if err != nil {
		return nil, err
	}
	return &RingMixerRoundFinishedIterator{contract: _RingMixer.contract, event: "RoundFinished", logs: logs, sub: sub}, nil
}

// WatchRoundFinished is a free log subscription operation binding the contract event 0xb39c645aef2ec42857f91918de2794aa7e86c524d4461c4bac26d13e870c6015.
//
// Solidity: e RoundFinished()
func (_RingMixer *RingMixerFilterer) WatchRoundFinished(opts *bind.WatchOpts, sink chan<- *RingMixerRoundFinished) (event.Subscription, error) {

	logs, sub, err := _RingMixer.contract.WatchLogs(opts, "RoundFinished")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RingMixerRoundFinished)
				if err := _RingMixer.contract.UnpackLog(event, "RoundFinished", log); err != nil {
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

// RingMixerTransactionIterator is returned from FilterTransaction and is used to iterate over the raw logs and unpacked data for Transaction events raised by the RingMixer contract.
type RingMixerTransactionIterator struct {
	Event *RingMixerTransaction // Event containing the contract specifics and raw log

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
func (it *RingMixerTransactionIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RingMixerTransaction)
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
		it.Event = new(RingMixerTransaction)
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
func (it *RingMixerTransactionIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RingMixerTransactionIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RingMixerTransaction represents a Transaction event raised by the RingMixer contract.
type RingMixerTransaction struct {
	To    common.Address
	Value *big.Int
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterTransaction is a free log retrieval operation binding the contract event 0x8d6db82aa3f20a3487b6bea41ef75a3605c4348c95cd94e9e46dc27a048f778a.
//
// Solidity: e Transaction(_to indexed address, _value uint256)
func (_RingMixer *RingMixerFilterer) FilterTransaction(opts *bind.FilterOpts, _to []common.Address) (*RingMixerTransactionIterator, error) {

	var _toRule []interface{}
	for _, _toItem := range _to {
		_toRule = append(_toRule, _toItem)
	}

	logs, sub, err := _RingMixer.contract.FilterLogs(opts, "Transaction", _toRule)
	if err != nil {
		return nil, err
	}
	return &RingMixerTransactionIterator{contract: _RingMixer.contract, event: "Transaction", logs: logs, sub: sub}, nil
}

// WatchTransaction is a free log subscription operation binding the contract event 0x8d6db82aa3f20a3487b6bea41ef75a3605c4348c95cd94e9e46dc27a048f778a.
//
// Solidity: e Transaction(_to indexed address, _value uint256)
func (_RingMixer *RingMixerFilterer) WatchTransaction(opts *bind.WatchOpts, sink chan<- *RingMixerTransaction, _to []common.Address) (event.Subscription, error) {

	var _toRule []interface{}
	for _, _toItem := range _to {
		_toRule = append(_toRule, _toItem)
	}

	logs, sub, err := _RingMixer.contract.WatchLogs(opts, "Transaction", _toRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RingMixerTransaction)
				if err := _RingMixer.contract.UnpackLog(event, "Transaction", log); err != nil {
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

// RingMixerVerifyIterator is returned from FilterVerify and is used to iterate over the raw logs and unpacked data for Verify events raised by the RingMixer contract.
type RingMixerVerifyIterator struct {
	Event *RingMixerVerify // Event containing the contract specifics and raw log

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
func (it *RingMixerVerifyIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RingMixerVerify)
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
		it.Event = new(RingMixerVerify)
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
func (it *RingMixerVerifyIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RingMixerVerifyIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RingMixerVerify represents a Verify event raised by the RingMixer contract.
type RingMixerVerify struct {
	Ok  bool
	Raw types.Log // Blockchain specific contextual infos
}

// FilterVerify is a free log retrieval operation binding the contract event 0xa0c1fc382db99c490561b48be7ef277080a844c158e8a35ba8aabd16c0320450.
//
// Solidity: e Verify(ok indexed bool)
func (_RingMixer *RingMixerFilterer) FilterVerify(opts *bind.FilterOpts, ok []bool) (*RingMixerVerifyIterator, error) {

	var okRule []interface{}
	for _, okItem := range ok {
		okRule = append(okRule, okItem)
	}

	logs, sub, err := _RingMixer.contract.FilterLogs(opts, "Verify", okRule)
	if err != nil {
		return nil, err
	}
	return &RingMixerVerifyIterator{contract: _RingMixer.contract, event: "Verify", logs: logs, sub: sub}, nil
}

// WatchVerify is a free log subscription operation binding the contract event 0xa0c1fc382db99c490561b48be7ef277080a844c158e8a35ba8aabd16c0320450.
//
// Solidity: e Verify(ok indexed bool)
func (_RingMixer *RingMixerFilterer) WatchVerify(opts *bind.WatchOpts, sink chan<- *RingMixerVerify, ok []bool) (event.Subscription, error) {

	var okRule []interface{}
	for _, okItem := range ok {
		okRule = append(okRule, okItem)
	}

	logs, sub, err := _RingMixer.contract.WatchLogs(opts, "Verify", okRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RingMixerVerify)
				if err := _RingMixer.contract.UnpackLog(event, "Verify", log); err != nil {
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

// RingMixerWithdrawalsCompletedIterator is returned from FilterWithdrawalsCompleted and is used to iterate over the raw logs and unpacked data for WithdrawalsCompleted events raised by the RingMixer contract.
type RingMixerWithdrawalsCompletedIterator struct {
	Event *RingMixerWithdrawalsCompleted // Event containing the contract specifics and raw log

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
func (it *RingMixerWithdrawalsCompletedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RingMixerWithdrawalsCompleted)
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
		it.Event = new(RingMixerWithdrawalsCompleted)
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
func (it *RingMixerWithdrawalsCompletedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RingMixerWithdrawalsCompletedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RingMixerWithdrawalsCompleted represents a WithdrawalsCompleted event raised by the RingMixer contract.
type RingMixerWithdrawalsCompleted struct {
	Raw types.Log // Blockchain specific contextual infos
}

// FilterWithdrawalsCompleted is a free log retrieval operation binding the contract event 0x8fda7bd885c433d2d69d977879dd701b0af22ac1fc1dd3ff82ca2ea34eec3bf9.
//
// Solidity: e WithdrawalsCompleted()
func (_RingMixer *RingMixerFilterer) FilterWithdrawalsCompleted(opts *bind.FilterOpts) (*RingMixerWithdrawalsCompletedIterator, error) {

	logs, sub, err := _RingMixer.contract.FilterLogs(opts, "WithdrawalsCompleted")
	if err != nil {
		return nil, err
	}
	return &RingMixerWithdrawalsCompletedIterator{contract: _RingMixer.contract, event: "WithdrawalsCompleted", logs: logs, sub: sub}, nil
}

// WatchWithdrawalsCompleted is a free log subscription operation binding the contract event 0x8fda7bd885c433d2d69d977879dd701b0af22ac1fc1dd3ff82ca2ea34eec3bf9.
//
// Solidity: e WithdrawalsCompleted()
func (_RingMixer *RingMixerFilterer) WatchWithdrawalsCompleted(opts *bind.WatchOpts, sink chan<- *RingMixerWithdrawalsCompleted) (event.Subscription, error) {

	logs, sub, err := _RingMixer.contract.WatchLogs(opts, "WithdrawalsCompleted")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RingMixerWithdrawalsCompleted)
				if err := _RingMixer.contract.UnpackLog(event, "WithdrawalsCompleted", log); err != nil {
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
