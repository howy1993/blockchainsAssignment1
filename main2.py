import json
import nacl.encoding
import nacl.signing
import queue
import time
from hashlib import sha256 as H
from typing import NewType

print('')
print('')
# Serializes a list of JSON objects from a specific transaction
# input(s): json object, term (input or output)
# output(s): a serialization of the list of inputs or outputs
def serialize(tx, term):
    # load the json data
    data = json.loads(tx)
    s = []
    for t in data[term]:
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

    d = json.loads(tx)
    # add signature
    serials.append(str(d["sig"]))
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
            s.append(str(ele.number))
            s.append(str(ele.output.value))
            s.append(str(ele.output.pubkey))
        elif term == "output":
            s.append(str(ele.value))
            s.append(str(ele.pubkey))
    return ''.join(s)


class Output:
    def __init__(self, value, pubkey):
        self.value = value
        self.pubkey = pubkey

    def compare(self, obj2):
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

    def gen_number(self):
        j = self.jsonify()
        number = generate_number(j)
        self.number = number.hexdigest()

    def verify_number_hash(self):
        test1 = self.jsonify()
        test2 = generate_number(test1)
        test2 = test2.hexdigest()
        if (test2 == self.number):
            return 1
        return 0

    def jsonify(self):
        jsonObj = {}

        inputList = []
        for i in self.input:
            inputsOutDict = {}
            inputsOutDict["output"] = {}
            inputsOutDict["number"] = i.number
            inputsOutDict["output"]["value"] = i.output.value
            inputsOutDict["output"]["pubkey"] = str(i.output.pubkey)
            inputList.append(inputsOutDict)
        jsonObj["input"] = inputList

        outputList = []
        for o in self.output:
            outputDict = {}
            outputDict["value"] = o.value
            outputDict["pubkey"] = str(o.pubkey)
            outputList.append(outputDict)
        jsonObj["output"] = outputList
        jsonObj["sig"] = str(self.sig)
        jsonObj["number"] = self.number

        return json.dumps(jsonObj, indent=4)


    def show(self):
        print("input: {0}\noutput: {1}\nsig: {2}\nnumber: {3}\n"
                .format(self.input, self.output, self.sig, self.number))


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
    def verify_not_used(self, local_tx:Transaction, treenode:TreeNode):
        y = treenode
        while(y != None):
            if (local_tx.number == y.block.tx.number):
                return 0
            else:
                y = y.prevBlock
        return 1

    # Output exists in named transaction - this function checks for/matches numbers and output to an earlier tx
    def verify_tx_inputs(self, local_tx:Transaction):
        flag = 1
        flag2 = 1
        for x in local_tx.input:
            y = self.current_max_height_tree_node
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
    def verify_public_key_signatures(self, tx:Transaction):
        #check same public key
        return 1
        pubkey1 = tx.input[0].output.pubkey
        for x in tx.input:
            if x.output.pubkey != pubkey1:
                return 0
        #serializes content and verifies signature to key
        message = serialize_list(tx.input, "input")
        message += serialize_list(tx.output, "output")
        message = message.encode("utf-8")
        verify_key = nacl.signing.VerifyKey(pubkey1, encoder=nacl.encoding.HexEncoder)
        return verify_key.verify(message, tx.sig)


    # ? Not sure if this logic is right
    def verify_double_spend(self, tx:Transaction):
        if (self.current_max_height_tree_node == self.root):
            return 1
        flag = 1
        flag2 = 1
        for x in tx.input:
            y = self.current_max_height_tree_node
            flag2+=1
            while(flag < flag2):
                print(flag)
                print(len(y.block.tx.input))
                for z in y.block.tx.input:
                    if x.number == z.number:
                        print("it came here")
                        flag+=1
                    elif y != None:
                        print("it came here tho")
                        y = y.prevBlock
                    else:
                        print("it came here last")
                        return max(flag - len(tx.input),0)
                time.sleep(1)


        return max(flag - len(tx.input),0)

    # Checks sum of inputs vs outputs
    def verify_sum(self, tx:Transaction):
        input_sum = 0
        output_sum = 0
        for x in tx.input:
            input_sum += x.output.value
        for y in tx.output:
            output_sum += y.value
        return (input_sum == output_sum)

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

    def receive_block(self):
        #TODO: validate block?
        #update_longest_chain(new_block)
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
gen_transaction = Transaction(empty_input_list, output_list, 0)

j = gen_transaction.jsonify()



# generate the number for the transaction
gen_transaction.gen_number()
gen_transaction_number = gen_transaction.number

# Generate genesis block
gen_block = Block(gen_transaction, b'0', None, b'0')
#Initialize nodes with genesis block
node_list = []
for i in range(0,10):
    node_list.append(Node(gen_block))

for i in range(0,10):
    node_list[i-1].node_list = node_list

global_tx_pool = []
no_more_tx = 1
lock = 0
inputs_from_gen_tx = []
outputs_from_gen_tx = []

for i in range (0, 3):
    new1 = []
    new2 = []
    new1.append(Input(gen_transaction_number, Output(100, verify_key_hex[i])))
    new2.append(Output(100, verify_key_hex[i+3]))
    inputs_from_gen_tx.append(new1)
    outputs_from_gen_tx.append(new2)

def verify(node:Node, tx:Transaction, treenode:TreeNode):
    flag = NewType('flag', int)
    flag = tx.verify_number_hash()
    flag *= node.verify_not_used(tx, treenode)
    flag *= node.verify_tx_inputs(tx)
    flag *= node.verify_public_key_signatures(tx)
    flag *= node.verify_double_spend(tx)
    flag *= node.verify_sum(tx)
    return bool(flag)

def mining(node:Node):

    while(True): #global variable
        #sleep(random)
        print(len(global_tx_pool))

        if (not node.q.empty()):
            new_block = node.q.get()

        if((len(global_tx_pool)!=0)):
            #lock = 1
            new_tx = global_tx_pool[0]
            del global_tx_pool[0]
            if verify(node, new_tx, node.current_max_height_tree_node):
                print("verify is: ", verify(node, new_tx, node.current_max_height_tree_node))
                node.mine_block(new_tx, node.current_max_height_tree_node.block)
            #node.send_block(new_block)
            #lock = 0

        if(len(global_tx_pool)==0):
            return


tempsig = []

for i in range(0,3):
    message = serialize_list(inputs_from_gen_tx[i], "input")
    message += serialize_list(outputs_from_gen_tx[i], "output")
    message = message.encode("utf-8")
    tempsig.append(signing_key[i].sign(message))

for x in range (0,3):
    temptx = Transaction(inputs_from_gen_tx[i], outputs_from_gen_tx[i], tempsig[i])
    temptx.gen_number()
    global_tx_pool.append(temptx)



mining(node_list[1])


if __name__ == "__main__":
    main()
