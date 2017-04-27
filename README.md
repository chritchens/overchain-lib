# Overchain, a protocol for decentralized sidechains #


## Description ##


Overchain is a protocol to build Bitcoin 2-way pegged decentralized sidechains. So far I'd suggest the pegged sidechains to use a proof-of-stake on Bitcoin funds, in order for the system to be workable. This means that in those sidechains, nodes with the higher Bitcoin stake would have an higher chance to have their blocks added to the sidechain blockchain. In any case, I think it's sidechain dependant.


## How it works ##


It is easier to show how it works through an example. We will review the workings of a fictional sidechain named XBitcoin (in the text referred also as XBTC). XBTC is a peer-to-peer network with a blockchain similar to bitcoin, but not having any proof-of-work mining operation. XBTC nodes are called 'notaries', and they build blocks in order to gain a reward collected from users transactions. They register deposits, withdraws and normal transactions. The conversion rate from BTC to XBTC is 1:1.

To make things easier wallets are not multisig, although in the code is given the option.


### Overchain Messages ###


**BTC wallet**: a Bitcoin wallet. It is made by a pair of signing keys plus the set of their transactions.

**XBTC wallet**: XBitcoin sidechain wallet. It is made by a pair of signing keys plus the set of their transactions.

**BTC deposit tx**: a Bitcoin transaction used to deposit Bitcoin funds from a Bitcoin wallet to an XBitcoin wallet. It contains:

  1. a nulldata output containing:

    - the code of the wallet sidechain, in this case, XBTC.

    - the hash160 of the XBitcoin wallet public key.

    - an amount of burned Bitcoin coins, which is a fee to XBitcoin notaries.

  2. a pay-to-publickey-hash output where the used public key is the same of the XBitcoin wallet to fund. This amount is the fund to the XBitcoin wallet of choice.
  
  3. possibly other outputs using another kind of scripts or other public keys. They are not relevant to the Overchain protocol.

**XBTC deposit tx**: a special XBitcoin transaction used to register Bitcoin coins into an XBitcoin wallets. It has a witness to the Bitcoin deposit depositing that amount and a proof of its ownership by the message creator. It is a timestamped and cryptographically authenticated message containing:

  1. the referenced Bitcoin deposit transaction.
 
  2. the fee from the Bitcoin nulldata output, converted to XBitcoin coins (1:1).
 
  3. the fund from the Bitcoin pay-to-publickey-hash output, converted to XBitcoin coins (1:1).
 
  4. the signature of the transaction by the XBitcoin wallet funded and referenced in the Bitcoin nulldata output.

**BTC deposit UTXO**: a Bitcoin unspent deposit transaction output. It is the Bitcoin pay-to-publickey-hash output to the XBitcoin wallet while unspent.

**XBTC deposit UTXO**: an XBitcoin unspent deposit transaction output. It is the XBitcoin fund output while unspent.

**BTC withdraw tx**: a Bitcoin transaction used to withdraw funds from an XBitcoin wallet back to a Bitcoin wallet. It is just a spent of deposited Bitcoin funds (BTC deposit UTXOs) by public keys different from the XBitcoin wallet one.

**XBTC withdraw tx**: a special XBitcoin transaction used to register a Bitcoin withdraw funds from an XBitcoin wallet. It has a witness to the Bitcoin withdraw. It is automatically added by the notaries when if they notice the fact while validating transactions spending those funds. It just contains the referenced Bitcoin withdraw transaction and it is added directly in XBitcoin blocks. Withdrawn funds are not spendable.


### Depositing Bitcoin coins to XBitcoin ###


**BTC deposit tx**: the user creates, sign and broadcast a BTC deposit tx to her XBTC wallet. The BTC deposit tx indicates in a nulldata output that it is a deposit to her XBTC wallet, referenced by a hashed public key. The outputs of the BTC deposit depositing the funds are pay-to-public key-hash outputs where the public key used it the XBTC wallet public key.

**XBTC deposit tx**: the user creates, sign and broadcast a XBTC deposit tx containing Bob BTC deposit tx, the converted fee and fund and his signature demonstrating that he is the effectively the owner of that public key funded by Bob.

**XBTC node**: validates incoming XBTC deposit txs checking that the referenced Bitcoin transactions are valid, exist and have at least 6 confirms, and that the XBTC deposit txs signatures are valid. In the case they are valid, the XBTC deposit txs are stored and broadcasted to other nodes. In the case the node is a notary, it will add to its blocks the valid XBTC deposit txs, priorityzing those with the higher fees. XBTC deposit tx fees collected are locked for a number of blocks, partly unlocked after that number of blocks have been confirmed, completely unlocked after a certain number of blocks have been confirmed after their complete withdraw.


### Sending and receiving XBitcoin coins ###


Every XBTC wallet owner can send and receive XBitcoin coins. Every XBitcoin satoshi originates from a XBTC deposit transaction. Those transactions are the "roots" of the direct acyclic graph of the transactions registered in the XBitcoin blockchain.


### Withdrawing Bitcoin coins from XBitcoin ###


**BTC withdraw tx**: the user creates, sign and broadcast a BTC withdraw tx by spending BTC deposit UTXOs with her XBTC wallet public key.

**XBTC withdraw tx**: notaries create and add to their block a XBTC withdraw tx referencing the BTC withdraw tx. 6 confirmations are needed before it is considered confirmed. Before that, any spending of that BTC deposit UTXO is invalid.

**XBTC nodes**: when a XBTC user tries to spend an XBTC UTXO, nodes check that the BTC UTXO referenced by the incoming XBTC UTXO spending request is still unspent. In the case it has been spent, notaries build a XBTC withdraw tx and add it to the blockchain, other nodes just treat the incoming XBTC spending operation as invalid. In the case the BTC UTXO is still unspent, the spending is considered valid, every node store and broadcast it and notaries add it to the blocks they are working on
according to its fees.


### XBitcoin block selection and rewards ###

In XBitcoin nodes which make it to have their blocks added to the blockchain get rewarded with the fees collected from deposits and transactions. Those fees will be spendable only after a period of 100 blocks. The nodes which can have their blocks selected are those which can prove to own Bitcoin funds above a certain minimum value dinamically set in order to ensure a block confirmation time of 6 minutes. Those who wins are those with the higher funds, then stake. This makes of XBitcoin a proof-of-stake currency backed by Bitcoin.


## Code ##


The code will provide a library to build Overchain messages, clients and servers usable by 2-way pegged sidechains. At this point it is not even an alpha: it is unfinished, unpolished, poorly tested, undocumented. If you want to collaborate, just drop a mail to chritchens@gmail.com.





