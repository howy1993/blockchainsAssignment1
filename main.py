import json
import hashlib
from anytree import Node, RenderTree
from hashlib import sha256 as H

# transaction
# {"number": <hash of input, output, and signature fields>,
#   "input": [{"number": <transaction number>, "output": {"value": <value>, "pubkey": <sender public key>}}, ...],
#   "output": [{"value": <value>, "pubkey": <receiver public key>}, ...],
#   "sig": <signature of input and output fields using sender private key>
# }
class Transaction:
    def __init__(self, inputs, outputs, sig):
        self.input = inputs
        self.output = outputs
        self.sig = sig
        self.number = H(b'inputs')
        self.number.update(b'outputs')

    def verifyNumberHash():
        temp = H(b'inputs')
        temp.update(b'outputs')
        if temp != number:
            return 0
        else:
            return 1

# block
# {"tx": <a single transaction>,
#  "prev": <hash of the previous block>,
#  "nonce": <the nonce value, used for proof-of-work>,
#  "pow": <the proof-of-work, a hash of the tx, prev, and nonce fields>
# }
class Block:
    def __init__(self, tx:Transaction, prev):
        self.tx = tx
        self.prev = prev

class Node:
    def __init__(genBlock:Block, txList):
        self.root = Node("root", blockNumber=1, block=genBlock, height=1)
        self.utxoPool = txList
        self.currentMaxHeight = 1

    def verifyNotUsed(_tx:Transaction):
        if root.search.find(node.block.tx.number == "") != None:
            return 1
        else:
            return 0

    def verifyInputUTXO(_tx:Transaction):
        
        return 1

    def verifyInputOutput(_tx:Transaction):
        return True

    def verifyDoubleSpend(_tx:Transaction):
        return True

    def verifySum(_tx:Transaction):
        return True
        #tx.inputs

    def verify(_tx:Transaction):
        flag = _tx.verifyNumberHash
        flag *= verifyNotUsed(_tx)
        flag *= verifyInputUTXO(_tx)
        flag *= verifyInputOutput(_tx)
        flag *= verifyDoubleSpend(_tx)
        flag *= verifySum(_tx)
        return bool(flag)


    def maxHeight():
        return True


    def mineBlock(Transaction):
        return 1

    def anytreePrintNodeView():
        return 1
