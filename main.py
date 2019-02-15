import json
import nacl.encoding
import nacl.signing
from hashlib import sha256 as H

# Serializes a list of JSON objects from a specific transaction
# input(s): json object, term (input or output)
# output(s): a serialization of the list of inputs or outputs
def serialize(tx, term):
    s = []
    for t in tx[term]:
        if term == "input":
            s.append(t["number"])
            s.append(str(t["output"]["value"]))
            s.append(t["output"]["pubkey"])
        elif term == "output":
            s.append(str(t["value"]))
            s.append(t["pubkey"])

    return ''.join(s)

def generate_number(tx):
    serials = []
    # serialize each transaction (each input and output)
    for ele in ["input", "output"]:
        res = serialize(tx, ele)
        serials.append(res)
    # add signature
    serials.append(tx["sig"])

    joinedSerials = "".join(serials)
    encodedSerials = joinedSerials.encode('utf-8')
    # hash the serialized data
    hashedSerials = H(encodedSerials)

    return hashedSerials

# Serializes transaction, previous hash, and nonce value
# input(s): transaction
# output(s):
def serialize_block(tx, prev, nonce):

    # serialize specifically for a transaction
    serials = []
    for t in ["number", "input", "output", "sig"]:
        res = serialize(tx, t)
        serials.append(res)
    serials.append(prev)
    serials.append(str(nonce))
    joinedSerials = "".join(serials)

    return joinedSerials

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
        self.number = 0

    def gen_number():
        number = generate_number(self)

    def verify_number_hash():
        temp = generate_number(self)
        return (temp == self.number)

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
        message = serialize(tx.input, "input")
        message += serialize(tx.outputs, "output")
        verify_key = nacl.signing.VerifyKey(verify_key_hex, encoder=nacl.encoding.HexEncoder)
        return verify(message, tx.sig, encoder=nacl.encoding.HexEncoder)


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

    def mineBlock(tx:Transaction, prev:Block):
        pow = 0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF + hex(1)
        nonce = 0
        while (pow > 0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF):
            nonce += 1
            block_message = serialize_block(tx.number, prev, nonce)
            pow = H(block_message.encode('utf-8'))
        #Once verified, push nonce/pow/prev into a new block and send it out
        new_block = Block(tx, prev, nonce, pow)
        treenode_list.append(TreeNode(new_block, prev, prevBlock.height+1))
        sendBlock(new_block)
        for x in tx.outputs:
            self.tx_list.append(x)
        #TODO: update what the longest chain is

    def sendBlock():
        self.sendBlock = new_block
        #TODO: sending block over threads

    def receiveBlock():
        #TODO: validate block?
        #TODO: update longest chain
        return 1


def main():
    jObj = json.dumps([
        {
            "number": "fc12f4bc8657dd0139a978cd1bd64b94e5b780dc61f292830626ead7f830c221",
            "input": [
                {
                    "number": "1234",
                    "output": {
                        "value": 123,
                        "pubkey": "asdf"
                    }
                },
                {
                    "number": "5678",
                    "output": {
                        "value": 456,
                        "pubkey": "fdsa"
                    }
                }
            ],
            "output": [
                {
                    "value": 40.87722055316936,
                    "pubkey": "f55fcd64b06bae4f5f13ef7c33b0d71c8c2a9a0b446bdd9158e88fb1ec131b2f"

                 },
                {
                    "value": 62.70091885420593,
                    "pubkey": "f31afc7d3b351ed6627a6fe73e59c56cc85142b6ce75c91a6cb48ada8b18df7f"
                },
                {
                    "value": 61.567598039085006,
                    "pubkey": "a4358fe73763794164b5cc88605da3a9c877e157f2eef135fa717d9ba6e2f403"
                },
                {
                    "value": 32.036403371644184,
                    "pubkey": "8ae86a3d0886ed284558f1f1877e56ce7a471bd00db16effc506f10911916bcf"
                },
                {
                    "value": 74.85502582411641,
                    "pubkey": "807cfae7317ed443aacf114ff26dd9c69bcdc757f6c742d8cc1a2667be4e7ca5"
                }
            ],
            "sig": "ec17086bd4c0a566893a508454f6ed332c360de2d86834e5ffeddeec4ec24da907dc505d595692415a1ade7f7bd9d03cf2e01acbd3335f1eef3b1ecfb9548a06"
        }])



    serials = []
    # serialize each transaction (each input and output)
    for tx in json.loads(jObj):
        for ele in ["input", "output"]:
            res = serialize(tx, ele)
            serials.append(res)
        # add signature
        serials.append(tx["sig"])

    joinedSerials = "".join(serials)
    encodedSerials = joinedSerials.encode('utf-8')
    # hash the serialized data
    hashedSerials = H(encodedSerials)


    nums = []
    # for each transaction, generate a number
    for tx in json.loads(jObj):
        nums.append(generate_number(tx))


    for n in nums:
        print(n.hexdigest())


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

output_list = []
# Generate contents for gen block. All 8 pksk pairs get 100 coins
for i in range (0,8):
    output_list.append(Output(100, verify_key_hex[i]))

empty_input_list = []
gen_transaction = Transaction(empty_input_list, output_list[i], 0)
gen_transaction.gen_number

# Generate genesis block
gen_block = Block(gen_transaction, b'0', b'0', b'0')

#Initialize nodes with genesis block
node_list = []
for i in range (0,10):
    node_list.append(Node(gen_block))

for i in range (0,10):
    node_list[i-1].node_list = node_list


if __name__ == "__main__":
    main()

print(node_list[1].)
