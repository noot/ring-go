# Ring Signature based mixing on Ethereum
This is a report written by me, @noot, for my University of Toronto course ESC499. It's written assuming the person reading knows nothing about blockchain and/or Ethereum and/or cryptography. If you have some background knowledge, you can skip the intro :)

### Introduction and Background
##### Ethereum
   A **blockchain** is a decentralized network of Byzantine fault tolerant nodes which transition from one state to another through network consensus. Byzantine fault tolerance is an idea first introduced regarding distributed computer systems, particularly multi-core processors.  If one part of the system is faulty and gives incorrect signals to the rest of the system, we want to be assured that the system overall maintains the correct state. In a **proof-of-work** blockchain, such as Ethereum, as long as over 50% of the nodes are honest, we can be assured that the correct state is maintained.
   
   Ethereum is a blockchain which includes, alongside the transaction-based state, a quasi-Turing-complete stack machine also known as the Ethereum Virtual Machine (**EVM**).  This allows for the execution of **smart contracts** on the network.  Smart contracts are pieces of software that live on the network, written in a Turing-complete language (commonly Solidity) and executed on the EVM.  Smart contracts are deterministic and are able to make changes to state if certain conditions are met.  
   
   On Ethereum, addresses may be either user accounts *or* smart contracts.  Transactions can be directed towards either a user account, usually involving transfer of ether, or a smart contract, involving execution of one of its functions.  A user account has a corresponding **private key** which can be used to access the funds in the account.  A contract *does not* have a corresponding private key; no one *owns* the contract once it is deployed. Functionality for ownership must be programmed into the contract from the start; there is no inherent owner of the contract.
   
   All transactions on the network involve the native currency or **fuel** called ether.  Every transaction on the network uses a certain amount of **gas** which is used to prevent smart contracts from using all the network capacity.  For example, an infinite loop cannot occur as it will eventually run out of gas.
   
   Each Ethereum block consists of a **block header** which contains information about the current state of the network.  This current state includes both account balances (`txHash` and `receiptHash`) and values stored in smart contracts (`root` or `stateRoot`). The following is the structure of the block header in go-ethereum, commonly known as **geth**: [1] (https://github.com/ethereum/go-ethereum/blob/master/core/types/block.go#L70)
   
  ```
   type Header struct {
    ParentHash  common.Hash    
    UncleHash   common.Hash    
    Coinbase    common.Address 
    Root        common.Hash    
    TxHash      common.Hash   
    ReceiptHash common.Hash    
    Bloom       Bloom          
    Difficulty  *big.Int       
    Number      *big.Int       
    GasLimit    uint64        
    GasUsed     uint64        
    Time        *big.Int     
    Extra       []byte        
    MixDigest   common.Hash    
    Nonce       BlockNonce    
}
```
   In this report, the `gasLimit` and `gasUsed` parameters are relevant.  Each transaction included in the block has a certain gas cost associated with it.  The `gasLimit` of a block is the maximum amount of gas that can be consumed by the total of transactions in the block. The `gasUsed` is the amount of gas used actually by all of the transactions. `gasUsed` can range from 0 to `gasLimit.`
   
   Transactions in Ethereum consist of a `to` address, a `from` address, a `value` in ether, and a `data` field, as well as information about gas.  Additionally, the transaction needs to be cryptographically signed by the account it is coming from. The following is a `transaction` struct: 
   
```
   type transaction struct {
	AccountNonce uint64         
	GasPrice     *big.Int       
	GasLimit     uint64          
	To	     *common.Address 
	Value        *big.Int        
	Data         []byte          

	// Signature values
	V *big.Int 
	R *big.Int 
	S *big.Int 
}
```
 
  Relevant to this report is `data`, `to`, `value`, `gasPrice`, `gasLimit`, and v, r, s (the cryptographic signature parameters.)  Notice there is no `from` field; the sender of the transaction is inferred from the signature.
  
  In a transaction, `value` and `gasPrice` are measured in *wei*, not in ether. Wei is the smallest denomination of the currency; 10^18 wei == 1 ether.
  
  `data` is a byte array of data used in contract calls. When the `to` address is the address of a contract, `data` contains encoded information about which function to call and with what parameters.  If the `to` address is a user account, `data` is irrelevant.  
  
  `value` is the amount of wei that is being transferred from the sender to the recipient in this transaction. The `gasLimit` specifies the maximum amount of gas that may be used by this transaction and `gasPrice` specified the price of gas, in wei per unit of gas.  Multiplying `gasLimit` by `gasPrice` gives the actual maximum cost, in wei, of the gas used by this transaction.
   
  Transactions on the Ethereum network are signed using elliptic curve cryptography. Specifically,  the elliptic curve digital signature alogorithm, or ECDSA, is used.  A user may have an account on the network, which consists of: a public key; a private key; and an address.  A valid transaction submitted to the network will be included in a block, thus changing the state of the network.

* explain precompiles
* explain addresses / signing
  
##### Cryptography
write summaries of:
* elliptic curve crypto / discrete log problem
* ECDSA 
* Ethereum accounts
* ring signatures
* zero-knowledge protocols

### Problem Formulation
##### Motivation
  The Ethereum network currently provides no privacy.  All transactions made are visible to the public.  Once an address is revealed to belong to a certain person, all the transactions they have made can be linked to them.  However, this causes problems.  For example, someone may be getting paid in ether and they don’t want their salary to be public; someone may wish to deploy a smart contract to the network, but the contents of the contract may cause legal trouble; someone may wish to post a note via transaction data to the network but cannot do it anonymously.  There are other blockchain-based networks that provide transactional privacy, such as Monero; however, they do not provide the computational capacity that Ethereum does. 
  
  A mixer is a third-party application which attempts to solve this problem.  Users submit a deposit in ether and a withdraw address.  The mixer then combines all the funds in a pool and sends the ether to the withdraw address, obfuscating the sender.  However, a major problem with this approach is centralization.  If the third-party wishes to no longer operate the mixer, they can exit with all the funds.  A centralized mixer takes away the value of a decentralized system.  A decentralized mixer in the form of a smart contract would solve this problem.
  
##### Formulation
 To implement a decentralized mixer, ring signatures are useful.  Ring signatures are a cryptographic algorithm used to sign a message as a group. [2] Given a ring signature, one cannot determine which member of the ring generated the signature; it can only be proven that one member of the ring generated the signature.  To generate a ring signature, one needs a message, their public and private keypair, and a list of other public keys that will be included in the ring.  Ethereum uses the secp256k1 elliptic curve, **expand and possibly move to background** which has a key size of 256 bits or 32 bytes.  The maximum ring size that has currently been stored on the network is five. [3] This is not sufficient for anonymity; for plausible deniability, a ring size of nine or more is needed.
  
  The cost of storing a ring signature on the network is extremely high.  Instead, we can reduce costs by moving some of the computation off-chain.  Within an Ethereum client (a piece of software that connects to the Ethereum network), there exist what are called “pre-compiled contracts.”  These are pieces of code that can be run by any smart contract on the network for a pre-determined gas cost.  The price of calling a pre-compiled contract is much lower than if one was to implement the pre-compiled contract within the smart contract.  Thus, pre-compiled contracts can be used to reduce the costs of commonly-used operations on the network.  An example of a pre-compiled contract is ECRECOVER, which given a signed message, recovers the public key used to sign the message.
  
By creating a pre-compiled contract which performs signing with a ring and verification of a ring-signed message, we will be able to use ring signatures on the Ethereum network.  In this thesis, I would like to explore the addition of ring signatures to the EVM.

To allow for efficient computation of ring signatures on the Ethereum network, the following need to be implemented:
1. An algorithm for signing (ring-sign) and verification (ring-verify) of ring signatures using elliptic curve cryptography.  The Cryptonote whitepaper proposes a one-time ring signature algorithm using ECC. [4]
2. An implementation of this algorithm, preferably in Go, as the official Ethereum client (go-ethereum) is written in Go.  Additionally, it can be implemented in Rust (for parity-ethereum), if time permits.
3. Integration of the algorithm with an Ethereum client (go-ethereum or parity-ethereum) as a pre-compiled contract.
4. A smart contract that acts as a mixer using the ring-sign and ring-verify pre-compiled contracts.
	Following these steps, a user will be able to deposit to the mixer contract and transfer their ether with the ability to obfuscate their address, adding privacy to Ethereum.

### Literature Review
Ethereum-based:
* Mobius
* Miximus
other:
* Monero
* zcash

### Implementation
* explain how ring signatures are used
* how mixer will work
* expand on what I've done so far

### Obstacles
what issues have I had so far?

### Results
fill in when completed

### Discussion
discuss:
* gas costs / $$ cost
* usability / steps needed for user

### Conclusion
* next steps

### References
[1] Ethereum Yellow Paper. https://ethereum.github.io/yellowpaper/paper.pdf
[2] How to leak a secret. https://people.csail.mit.edu/rivest/pubs/RST01.pdf
[3] Implementation of a ring signature mixer in a smart contract. https://ropsten.etherscan.io/address/0x5e10d764314040b04ac7d96610b9851c8bc02815#code
[4] Cryptonote whitepaper. https://cryptonote.org/whitepaper.pdf
