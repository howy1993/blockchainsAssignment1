import json
import nacl.encoding
import nacl.signing
import queue
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

# Generates a transaction number from a given transaction JSON object
# input(s): a transaction JSON object
# output(s): a serialization of the JSON elements into a number
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

# Helper function for test code for serializing list
# input(s): list, term
# output(s): serialized list
def serialize_list(l, term):
    s = []
    for ele in l:
        if term == "input":
            s.append(str(ele["number"]))
            s.append(ele["output"])
        elif term == "output":
            s.append(str(ele["value"]))
            s.append(ele["pubkey"])
    return ''.join(s)


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
        self.output = outputs
        self.sig = sig
        self.number = 0

    def gen_number():
        print(self.number)
        print("gen number is here")
        self.number = generate_number(self.jsonify())
        return self.number

    def verify_number_hash():
        temp = generate_number(self.jsonify())
        return (temp == self.number)

    def jsonify():
        jsonObj = {}
        jsonObj["input"] = self.input
        jsonObj["output"] = self.output
        jsonObj["sig"] = self.sig
        jsonObj["number"] = self.number
        return json.dumps(jsonObj)



# block
# {"tx": <a single transaction>,
#  "prev": <hash of the previous block>,
#  "nonce": <the nonce value, used for proof-of-work>,
#  "pow": <the proof-of-work, a hash of the tx, prev, and nonce fields>
# }
class Block:
    def __init__(self, tx:Transaction, prev, nonce, proofow):
        self.tx = tx
        self.prev = prev
        self.nonce = nonce
        self.pow = proofow

    def jsonify():
        jsonObj = {}
        jsonObj["tx"] = self.tx
        jsonObj["prev"] = self.prev
        jsonObj["nonce"] = self.nonce
        jsonObj["pow"] = self.proofow
        return json.dumps(jsonObj)

# Self-made tree/node structure that stores height
class TreeNode:
    def __init__(self, currBlock:Block, prevBlock:Block, height):
        self.block = currBlock
        self.prevBlock = prevBlock
        self.height = height

class Node:
    def __init__(self, gen_block:Block):
        self.root = TreeNode(gen_block, None, 1)
        self.treenode_list = []
        self.treenode_list.append(self.root)
        self.node_list = []
        self.current_max_height_tree_node = self.root
        self.q = queue.Queue()

    # Checks that tx number is has not been used in any prevBlocks
    def verify_not_used(local_tx:Transaction):
        y = current_max_height_tree_node
        while(y != None):
            if local_tx.number == y.block.tx.number:
                return 0
            else:
                y = y.prevBlock
        return 1

    # Output exists in named transaction - this function checks for/matches numbers and output to an earlier tx
    def verify_tx_inputs(local_tx:Transaction):
        flag = 1
        flag2 = 1
        for x in local_tx.input:
            y = current_max_height_tree_node
            flag2+=1
            while(flag < flag2):
                if x.number == y.block.tx.number:
                    for z in y.block.tx.output:
                        if z.compare(x.output):
                            flag+=1
                elif y != None:
                    y = y.prevBlock
                else:
                    return max(flag - len(tx.input),0)
        return max(flag - len(local_tx.input), 0)
    # Checks public key for all inputs, checks signature
    def verify_public_key_signatures(tx:Transaction):
        #check same public key
        pubkey1 = tx.input(1).output.pubkey
        for x in tx.input:
            if x.output.pubkey != pubkey1:
                return 0
        #serializes content and verifies signature to key
        message = serialize(tx.input, "input")
        message += serialize(tx.output, "output")
        verify_key = nacl.signing.VerifyKey(verify_key_hex, encoder=nacl.encoding.HexEncoder)
        return verify(message, tx.sig, encoder=nacl.encoding.HexEncoder)

    # ? Not sure if this logic is right
    def verify_double_spend(tx:Transaction):
        flag = 1
        flag2 = 1
        for x in tx.input:
            y = current_max_height_tree_node
            flag2+=1
            while(flag < flag2):
                for z in y.block.tx.input:
                    if x.number == z.number:
                        flag+=1
                    elif y != None:
                        y = y.prevBlock
                    else:
                        return max(flag - len(tx.input),0)
        return max(flag - len(tx.input),0)

    # Checks sum of inputs vs outputs
    def verify_sum(tx:Transaction):
        input_sum = 0
        output_sum = 0
        for x in tx.input:
            input_sum += x.output.value
        for y in tx.output:
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

    def update_longest_chain(new_block_tree_node):
        if (new_block_tree_node.height > self.current_max_height_tree_node.height):
                self.current_max_height_tree_node = new_block_tree_node

    def mine_block(tx:Transaction, prev:Block):
        proofow = 0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF + hex(1)
        nonce = 0
        while (proofow > 0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF):
            nonce += 1
            block_message = serialize_block(tx.number, prev, nonce)
            proofow = H(block_message.encode('utf-8'))
        #Once verified, push nonce/pow/prev into a new block and send it out
        new_block = Block(tx, prev, nonce, proofow)
        new_treenode = TreeNode(new_block, prev, prevBlock.height+1)
        treenode_list.append(new_treenode)
        update_longest_chain(new_block_tree_node)
        sendBlock(new_block)

    def send_block(new_block):
        #for x in node_list:
        #    x.q
        return 1

    def receive_block():
        #TODO: validate block?
        #update_longest_chain(new_block)
        return 1

    def mining():
        while(not no_more_tx): #global variable
            #sleep(random)

            if (not q.empty()):
                new_block = q.get()

            if(not global_tx_pool.empty() and lock == 0):
                lock = 1
                new_tx = q.get()
                if verify(new_tx):
                    mine_block(new_tx, current_max_height_tree_node.block)
                send_block(new_block)
                lock = 0

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
print("before")
print(gen_transaction)
print("after")
gen_transaction_number = gen_transaction.gen_number

# Generate genesis block
gen_block = Block(gen_transaction, b'0', None, b'0')

#Initialize nodes with genesis block
node_list = []
for i in range (0,10):
    node_list.append(Node(gen_block))

for i in range (0,10):
    node_list[i-1].node_list = node_list

global_tx_pool = []
no_more_tx = 1
lock = 0
inputs_from_gen_tx = []
outputs_from_gen_tx = []
print(gen_transaction_number)

for i in range (0,3):
    print(i)
    print(verify_key_hex[i+3])
    inputs_from_gen_tx.append(Input(gen_transaction_number, Output(100, verify_key_hex[i])))
    outputs_from_gen_tx.append(Output(100, verify_key_hex[i+3]))

message = serialize_list(inputs_from_gen_tx, "input")
message += serialize_list(outputs_from_gen_tx, "output")
print(message)
message = message.encode("utf-8")
print(message)
sig = signing_key[i].sign(message)
global_tx_pool.append(Transaction(inputs_from_gen_tx, outputs_from_gen_tx, sig))


if __name__ == "__main__":
    main()
