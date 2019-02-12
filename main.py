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
        return 1

    def verifyNumberHash():
        return 1

# block
# {"tx": <a single transaction>,
#  "prev": <hash of the previous block>,
#  "nonce": <the nonce value, used for proof-of-work>,
#  "pow": <the proof-of-work, a hash of the tx, prev, and nonce fields>
# }
class Block:
    def __init__(self, tx:Transaction, prev):
        return 1

class Node:
    def __init__(genBlock:Block, txList):
        return 1

    def verifyNotUsed(_tx:Transaction):
        return 1

    def verifyInputUTXO(_tx:Transaction):
        return 1

    def verifyInputOutput(_tx:Transaction):
        return 1

    def verifyDoubleSpend(_tx:Transaction):
        return 1

    def verifySum(_tx:Transaction):
        return 1

    def verify(_tx:Transaction):
        return 1

    def maxHeight():
        return 1

    def mineBlock(Transaction):
        return 1

    def anytreePrintNodeView():
        return 1
