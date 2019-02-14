import json
import nacl.encoding
import nacl.signing
from anytree import Node, RenderTree
from hashlib import sha256 as H

# transaction
# {"number": <hash of input, output, and signature fields>,
#   "input": [{"number": <transaction number>, "output": {"value": <value>, "pubkey": <sender public key>}}, ...],
#   "output": [{"value": <value>, "pubkey": <receiver public key>}, ...],
#   "sig": <signature of input and output fields using sender private key>
# }

class Output:
    def __init__(value, pubkey):
        self.value = value
        self.pubkey = pubkey

class Input:
    def __init__(number, output):
        self.number = number
        self.output:Output = output #each input holds 1 output

class Transaction:
    def __init__(self, inputs, outputs, sig):
        self.input = inputs
        self.outputs = outputs
        self.sig = sig
        self.number = H(b'inputs').update(b'outputs').update(b'sig')

    def verify_number_hash():
        temp = H(b'inputs').update(b'outputs').update(b'sig')
        if temp != number:
            return 0
        else:
            return 1

    # TODO: multiple inputs, multiple outputs? list?
    def pretty_print_tx(tx):
        print(json.dumps(
        [{"number": tx.number,
          "input": [{"number": tx.input.number, "output": {"value": 5, "pubkey": 5}}],
          "output": [{"value": 5, "pubkey": 5}],
          "sig":5
         }]
         ))

# block
# {"tx": <a single transaction>,
#  "prev": <hash of the previous block>,
#  "nonce": <the nonce value, used for proof-of-work>,
#  "pow": <the proof-of-work, a hash of the tx, prev, and nonce fields>
# }
class Block:
    def __init__(self, tx:Transaction, prev, nonce, pow):
        self.tx = tx
        self.prev = prev
        self.nonce = nonce
        self.pow = pow

class Node:
    def __init__(gen_block:Block, tx_list):
        self.root = Node("root", block_number=1, block=gen_block, height=1)
        self.tx_pool = txList
        self.current_max_height = 1

    def verify_not_used(local_tx:Transaction):
        #TODO: double check
        #if root.search.find(node.block.tx.number == _tx.number) != None:
        if 1:
            return 1
        else:
            return 0

    def verify_input_UTXO(local_tx:Transaction):
        flag = 1
        for x in local_tx.input:
            if 1:
            #if root.search.find( == x.number) != None:
                flag *= 1
            else:
                flag = 0
        return flag

    def verify_input_output(tx:Transaction):
        flag = 1
        for x in tx.input:
            if 1:
                return 1
            else:
                return 1

    def verify_double_spend(tx:Transaction):
        return 1

    def verify_sum(tx:Transaction):
        return 1
        #tx.inputs

    def verify(tx:Transaction):
        flag = tx.verifyNumberHash
        flag *= verify_not_used(tx)
        flag *= verify_input_UTXO(tx)
        flag *= verify_input_output(tx)
        flag *= verify_double_spend(tx)
        flag *= verify_sum(tx)
        return bool(flag)


    def maxHeight():
        return True


    def mineBlock(Transaction):
        return 1

    def anytreePrintNodeView():
        return 1


# Generate 8 random pksk pairs
for i in range (0,8):
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = hex(signing_key.verify_key)
    verify_key_hex = hex(verify_key.encode(encoder=nacl.encoding.HexEncoder))

# Generate genesis tx for gen block. All 8 pksk pairs get 100 coins
for i in range (0,8):
    output_list = Output(int(100), verify_key)

gen_transaction = Transaction(None, output_list)

# Generate genesis block
gen_block = Block(gen_transaction, H(1), H(2), H(3))
