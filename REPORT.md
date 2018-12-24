# Ring Signature based mixing on Ethereum
This is a report written by me, @noot, for my University of Toronto course ESC499. It's written assuming the person reading knows nothing about blockchain and/or Ethereum and/or cryptography. If you have some background knowledge, you can skip the intro :)

### Introduction and Background
##### Ethereum
   A **blockchain** is a decentralized network of Byzantine fault tolerant nodes which transition from one state to another through network consensus. Ethereum is a blockchain which includes, alongside the transaction-based state, a quasi-Turing complete stack machine also known as the Ethereum Virtual Machine (**EVM**).  This allows for the execution of **smart contracts** on the network.  Smart contracts are pieces of software that live on the network, written in a Turing-complete language (commonly Solidity) and executed on the EVM.  Smart contracts are deterministic and are able to make changes to state if certain conditions are met.  
   All transactions on the network involve the native currency or **fuel** called ether.  Every transaction on the network uses a certain amount of **gas** which is used to prevent smart contracts from using all the network capacity.  For example, an infinite loop cannot occur as it will eventually run out of gas.
   Each Ethereum block consists of a **block header** which contains information about the current state of the network.  This current state includes both account balances and values stored in smart contracts.
  Transactions on the Ethereum network are signed using elliptic curve cryptography. **EXPAND ON THIS** Specifically,  the elliptic curve digital signature alogorithm, or ECDSA, is used.  A user may have an account on the network, which consists of: a public key; a private key; and an address.  A valid transaction submitted to the network will be included in a block, thus changing the state of the network.

> explain precompiles
> explain addresses / signing
  
##### Cryptography
write summaries of:
> elliptic curve crypto / discrete log problem
> ECDSA 
> Ethereum accounts
> ring signatures

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
> Mobius
> Miximus
other:
> Monero
> zcash

### Implementation
> explain how ring signatures are used
> how mixer will work
> expand on what I've done so far

### Difficulties
what issues have I had so far?

### Results
fill in when completed

### Discussion
discuss:
> gas costs / $$ cost
> usability / steps needed for user

### Conclusion
> next steps

### References
[1] Ethereum Yellow Paper. https://ethereum.github.io/yellowpaper/paper.pdf
[2] How to leak a secret. https://people.csail.mit.edu/rivest/pubs/RST01.pdf
[3] Implementation of a ring signature mixer in a smart contract. https://ropsten.etherscan.io/address/0x5e10d764314040b04ac7d96610b9851c8bc02815#code
[4] Cryptonote whitepaper. https://cryptonote.org/whitepaper.pdf
