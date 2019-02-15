import json
import nacl.encoding
import nacl.signing
from hashlib import sha256 as H

# transaction
# {"number": <hash of input, output, and signature fields>,
#   "input": [{"number": <transaction number>, "output": {"value": <value>, "pubkey": <sender public key>}}, ...],
#   "output": [{"value": <value>, "pubkey": <receiver public key>}, ...],
#   "sig": <signature of input and output fields using sender private key>
# }

class Output:
    def __init__(self, value, pubkey):
        self.value = value
        self.pubkey = pubkey

    def compare(obj2):
        if self.value == obj2.value:
            if self.pubkey == obj2.pubkey:
                return 1
        else:
            return 0

class Input:
    def __init__(self, number, output):
        self.number = number
        self.output:Output = output #each input holds 1 output

class Transaction:
    def __init__(self, inputs, outputs, sig):
        self.input = inputs
        self.outputs = outputs
        self.sig = sig
        #TODO: self.number = hash()

    def verify_number_hash():
        #TODO: self.number = hash()
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
    def __init__(self, tx:Transaction, prev, nonce, pow):
        self.tx = tx
        self.prev = prev
        self.nonce = nonce
        self.pow = pow

# Self-made tree/node structure that stores height
class TreeNode:
    def __init__(self, currBlock:Block, prevBlock:Block, height):
        self.block = currBlock
        self.prevBlock = prevBlock
        self.height = height

class Node:
    def __init__(self, gen_block:Block):
        self.root = TreeNode(gen_block, None, 1)
        self.current_max_height = 1
        self.tx_list = []
        self.treenode_list = []
        self.treenode_list.append(self.root)
        self.node_list = []

    def verify_not_used(local_tx:Transaction):
        for x in treenode_list:
            if local_tx.number == x.block.tx.number:
                return 0
        return 1

    def verify_tx_inputs(local_tx:Transaction):
        flag = 1
        for x in local_tx.input:
            for y in self.tx_list:
                if local_tx.input.number == self.tx_list:
                    flag+=1
        return max(flag - len(local_tx.input),0)

    def verify_input_output(tx:Transaction):
        flag = 1
        for x in local_tx.input:
            for y in treenode_list:
                if local_tx.input.number == y.block.tx.number:
                    flag+=1
        return max(flag - len(local_tx.input),0)

    def verify_public_key_signatures(tx:Transaction):
        #check same public key
        pubkey1 = tx.input(1).output.pubkey
        for x in tx.input:
            if x.output.pubkey != pubkey1:
                return 0
        #TODO: check if signature covers the tx
        message = b'0'
        if verify(message, tx.sig, encoder=nacl.encoding.HexEncoder):
            return 1
        else:
            return 0


    def verify_double_spend(tx:Transaction, treenode:TreeNode):
        flag = 1
        for x in tx.input:
            while treenode.prev != None:
                for y in treenode.block.tx.inputs:
                    if y.output.compare(x.output):
                        return 0
        else:
            return 1


    def verify_sum(tx:Transaction):
        input_sum = 0
        output_sum = 0
        for x in tx.inputs:
            input_sum += x.output.value
        for y in tx.outputs:
            output_sum += y.value
        return (x == y)

    def verify(tx:Transaction):
        flag = tx.verifyNumberHash
        flag *= verify_not_used(tx)
        flag *= verify_input_UTXO(tx)
        flag *= verify_input_output(tx)
        flag *= verify_double_spend(tx)
        flag *= verify_sum(tx)
        return bool(flag)

    def mineBlock(tx:Transaction):
        #TODO: hashed block under target/increment nonce stuff here
        #once verified, push nonce/pow/prev into a new block and send it out
        new_block = Block(tx, prev, nonce, pow)
        treenode_list.append(TreeNode(new_block, prev, prevBlock.height+1))
        sendBlock(new_block)
        for x in tx.outputs:
            self.tx_list.append(x)

    def sendBlock():
        self.sendBlock = new_block
        #TODO: sending block over threads



##
## Start of test.
##

signing_key = []
verify_key = []
verify_key_hex = []

# Generate 8 random pksk pairs
for i in range (0,8):
    signing_key_new = nacl.signing.SigningKey.generate()
    verify_key_new = signing_key_new.verify_key
    verify_key_hex_new = verify_key_new.encode(encoder=nacl.encoding.HexEncoder)
    signing_key.append(signing_key_new)
    verify_key.append(verify_key_new)
    verify_key_hex.append(verify_key_hex_new)

# Generate contents for gen block. All 8 pksk pairs get 100 coins
for i in range (0,8):
    output_list = Output(100, verify_key)

empty_input_list = []
gen_transaction = Transaction(empty_input_list, output_list, 0)

# Generate genesis block
gen_block = Block(gen_transaction, b'0', b'0', b'0')

#Initialize nodes with genesis block
node_list = []
for i in range (0,10):
    node_list.append(Node(gen_block))

for i in range (0,10):
    node_list[i-1].node_list = node_list
    #node_list[i-1].tx_list.append()
