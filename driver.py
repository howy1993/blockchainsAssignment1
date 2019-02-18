import json
import nacl.encoding
import nacl.signing
import queue
from threading import Thread
import time
import random
from hashlib import sha256 as H

global_txpool = []
global_txpool_driver = []
node_list = []
doneflag = 2

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
    for ele in ["input", "output"]:
        res = serialize(tx, ele)
        serials.append(res)

    d = json.loads(tx)
    serials.append(d["sig"])
    joinedSerials = "".join(serials)
    encodedSerials = joinedSerials.encode('utf-8')
    hashedSerials = H(encodedSerials)

    return hashedSerials


# Serializes transaction, previous hash, and nonce value
# input(s): transaction, prev hash, and nonce
# output(s): string concatenation
def serialize_pre_block(tx, prev, nonce):
    serials = []
    for t in ["number", "input", "output", "sig"]:
        res = serialize(tx.jsonify(), t)
        serials.append(res)
    serials.append(prev)
    serials.append(str(nonce))
    joinedSerials = "".join(serials)

    return joinedSerials


# creates a serialization of a Block object
# input(s): b which is a Block object
# output(s): string serialization of the Block attributes
def serialize_block(b):
    s = []
    s.append(b.tx.serialize_self())
    s.append(str(b.prev))
    s.append(str(b.nonce))
    s.append(str(b.pow))

    return ''.join(s)


# Creates a block list in JSON
# inputs(s): treenode block with highest height
# output(s): list of dict blocks
def blocklist(tnode):
    currNode = tnode
    blockchain = []
    # with given block with highest height, iterate backwards to genesis
    while (currNode is not None):
        # create JSON from current block
        db = dictBlock(currNode)
        blockchain = [db] + blockchain
        currNode = currNode.prevBlock
    return blockchain


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


# Creates a JSON file for a block
# input(s): a TreeNode (which contains a block)
# output(s): a JSON representation of a block (from a TreeNode)
def JsonBlock(tnode):
    jsonBlock = {}
    # load json into dict
    data = json.loads(tnode.block.tx.jsonify())
    jsonBlock["tx"] = data
    jsonBlock["prev"] = tnode.block.prev
    jsonBlock["nonce"] = str(tnode.block.nonce)
    jsonBlock["pow"] = str(tnode.block.pow)
    return json.dumps(jsonBlock, indent=4)


# Creates a dictionary representation of a block
# input(s): a treenode
# output(s): a dictionary represntation of a block
def dictBlock(tnode):
    dBlock = {}
    # load json into dictionary
    data = json.loads(tnode.block.tx.jsonify())
    dBlock["tx"] = data
    dBlock["prev"] = tnode.block.prev
    dBlock["nonce"] = str(tnode.block.nonce)
    dBlock["pow"] = str(tnode.block.pow)
    return dBlock


class Output:
    def __init__(self, value, pubkey):
        self.value = value
        self.pubkey = pubkey

    def compare(self, obj2):
        if self.value == obj2.value:
            if self.pubkey == obj2.pubkey:
                return 1
        return 0


class Input:
    def __init__(self, number, output):
        self.number = number
        self.output:Output = output  # each input holds 1 output


class Transaction:
    def __init__(self, inputs, outputs, sig, number):
        self.input = inputs
        self.output = outputs
        self.sig = sig
        self.number = number

    def serialize_self(self):
        s = []
        s.append(serialize(self.jsonify(), "input"))
        s.append(serialize(self.jsonify(), "output"))
        s.append(self.sig.signature.hex())
        s.append(str(self.number))
        return ''.join(s)

    def gen_number(self):
        j = self.jsonify()
        number = generate_number(j)
        self.number = number.hexdigest()

    def verify_number_hash(self):
        jsonT = self.jsonify()
        temp = generate_number(jsonT)
        temp = temp.hexdigest()
        return (temp == self.number)

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
        jsonObj["sig"] = self.sig.signature.hex()
        jsonObj["number"] = self.number

        return json.dumps(jsonObj)


    def show(self):
        print("input: {0}\noutput: {1}\nsig: {2}\nnumber: {3}\n".format(self.input, self.output, self.sig.signature, self.number))


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
        jsonObj["tx"] = self.tx.jsonify()
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
    def __init__(self, gen_block:Block, name):
        self.max_height_treenode = TreeNode(gen_block, None, 1)
        self.treenode_list = []
        self.treenode_list.append(self.max_height_treenode)
        self.node_list = []
        self.q = queue.Queue()
        self.txq = queue.Queue()
        self.name = str(name)

    # Checks that tx number has not been used in any prevBlocks
    def verify_not_used(self, local_tx:Transaction, treenode:TreeNode):
        y = treenode
        while(y is not None):
            if local_tx.number == y.block.tx.number:
                return 0
            else:
                y = y.prevBlock
        return 1

    def node_name(self):
        return self.name

    # Output exists in named transaction - this function checks for/matches numbers and output to an earlier tx
    def verify_tx_inputs(self, local_tx:Transaction, treenode:TreeNode):
        flag = 1
        for x in local_tx.input:
            y = treenode
            while(y != None):
                if x.number == y.block.tx.number:
                    found = 0
                    for z in y.block.tx.output:
                        if z.compare(x.output):
                            flag += 1
                            found = 1
                    if found == 1:
                        y = None
                    else:
                        return 0
                else:
                    y = y.prevBlock
        return max(flag - len(local_tx.input), 0)

    # Checks public key for all inputs, checks signature
    def verify_public_key_signatures(self, tx:Transaction):
        # check same public key
        if len(tx.input) == 0:
            return 0
        pubkey1 = tx.input[0].output.pubkey
        for x in tx.input:
            if x.output.pubkey != pubkey1:
                return 0

        message = serialize_list(tx.input, "input")
        message += serialize_list(tx.output, "output")
        message = message.encode("utf-8")
        verify_key = nacl.signing.VerifyKey(pubkey1, encoder=nacl.encoding.HexEncoder)
        try:
            return verify_key.verify(message, tx.sig.signature)
        except Exception:
            return 0

    # checks for double spend
    def verify_double_spend(self, tx:Transaction, treenode:TreeNode):
        for x in tx.input:
            i = treenode
            while (i != None):
                for y in i.block.tx.input:
                    if y.number == x.number:
                        if y.output.compare(x.output):
                            return 0
                i = i.prevBlock
        return 1

    # Checks sum of inputs vs outputs
    def verify_sum(self, tx:Transaction):
        input_sum = 0
        output_sum = 0
        for x in tx.input:
            input_sum += x.output.value
        for y in tx.output:
            output_sum += y.value
        return (input_sum == output_sum)

    def verify(self, tx:Transaction, treenode:TreeNode):
        if (tx.input == None):
            return 0
        flag = tx.verify_number_hash()
        flag *= self.verify_not_used(tx, treenode)
        flag *= self.verify_tx_inputs(tx, treenode)
        flag *= self.verify_public_key_signatures(tx)
        flag *= self.verify_double_spend(tx, treenode)
        flag *= self.verify_sum(tx)
        return bool(flag)


    def verify_pow(self, block:Block):
        #Check that PoW is below target
        return (block.pow < hex(0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))

    # verifying prevhash exists in the blockchain
    def verify_prev_hash(self, block:Block):
        #Check that PoW generated from hashing block with appropriate nonce
        flag = 0
        for x in self.treenode_list:
            block_serialized = serialize_block(x.block)
            block_encoded = block_serialized.encode('utf-8')
            prevhash = H(block_encoded).hexdigest()
            if (prevhash == block.prev):
                flag = 1
        return flag

    # implements validate tx in block too
    def verify_block(self, block:Block, treenode:TreeNode):
        return (self.verify(block.tx, treenode) == 1 ==
                self.verify_pow(block) == self.verify_prev_hash(block))

    #updates longest chain for node. if overtaken, returns txs to global pool
    def update_longest_chain(self, new_block_tree_node):
        if (new_block_tree_node.height > self.max_height_treenode.height):
            y = self.max_height_treenode
            self.max_height_treenode = new_block_tree_node
            if (new_block_tree_node.prevBlock != y):
                while (y != None):
                    global_txpool.append(y.block.tx)
                    y = y.prevBlock


    def mine_block(self, tx:Transaction, prev:Block):
        proofow = hex(0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF + 1)
        target = hex(0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        nonce = 0
        while (proofow > target):
            nonce += 1
            prev_serialized = serialize_block(prev)
            prev_encoded = prev_serialized.encode('utf-8')
            prevhash = H(prev_encoded).hexdigest()
            block_message = serialize_pre_block(tx, prevhash, nonce)
            proofow = H(block_message.encode('utf-8'))
            proofow = proofow.digest()
            proofow = proofow.hex()
        # Once verified, push nonce/pow/prev into a new block and send it out
        new_block = Block(tx, prevhash, nonce, proofow)
        new_treenode = TreeNode(new_block, self.max_height_treenode, self.max_height_treenode.height+1)
        self.treenode_list.append(new_treenode)
        self.update_longest_chain(new_treenode)
        self.send_block(new_block)

    def send_block(self, new_block):
        for x in self.node_list:
            if (x != self):
                x.q.put(new_block)

    def receive_block(self, new_block:Block):
        linked_treenode = None
        block_serialized = serialize_block(new_block)
        block_encoded = block_serialized.encode('utf-8')
        currhash = H(block_encoded).hexdigest()
        for x in self.treenode_list:
            block_serialized = serialize_block(x.block)
            block_encoded = block_serialized.encode('utf-8')
            prevhash = H(block_encoded).hexdigest()
            if (new_block.prev == prevhash):
                linked_treenode = x
            if (currhash == prevhash):
                return
        if (linked_treenode == None):
            return
        if self.verify_block(new_block, linked_treenode):
                new_treenode = TreeNode(new_block, linked_treenode, linked_treenode.height+1)
                self.treenode_list.append(new_treenode)
                self.update_longest_chain(new_treenode)

    def mining(self, i):
        global doneflag
        global global_txpool
        while(doneflag != 0):
            if (doneflag == 1):
                doneflag = 0
            if (not self.q.empty()):
                new_block = self.q.get()
                self.receive_block(new_block)
            if (not self.txq.empty()):
                new_tx = self.txq.get()
                if self.verify(new_tx, self.max_height_treenode):
                    self.mine_block(new_tx, self.max_height_treenode.block)
            if(len(global_txpool) != 0):
                new_tx = global_txpool[0]
                del global_txpool[0]
                for x in range(0,10):
                    node_list[x].txq.put(new_tx)
                if self.verify(new_tx, self.max_height_treenode):
                    self.mine_block(new_tx, self.max_height_treenode.block)

    # Writes the node's blockchain to a file
    # input(s): nodename
    # output(s): none
    def writeBFile(self):
        fname = "node_{}_blockchain.json".format(self.name)
        el = blocklist(self.max_height_treenode)
        with open(fname, 'w') as outfile:
            json.dump(el,  outfile, indent=4)

def myfunc(gen_block, i):
    node_list[i].mining(i)
    node_list[i].writeBFile()

def main():
    ## Start of test.
    signing_key = []
    bytes_gen_array = []
    verify_key = []
    verify_key_hex = []

    # deterministic public keys
    bytes_gen_array.append(b'00000000000000000000000000000000')
    bytes_gen_array.append(b'00000000000000000000000000000001')
    bytes_gen_array.append(b'00000000000000000000000000000002')
    bytes_gen_array.append(b'00000000000000000000000000000003')
    bytes_gen_array.append(b'00000000000000000000000000000004')
    bytes_gen_array.append(b'00000000000000000000000000000005')
    bytes_gen_array.append(b'00000000000000000000000000000006')
    bytes_gen_array.append(b'00000000000000000000000000000007')

    # Generate 8 random pksk pairs and give them coins
    for i in range(0, 8):
        signing_key_new = nacl.signing.SigningKey(bytes_gen_array[i])
        signing_key.append(signing_key_new)
        verify_key_new = signing_key_new.verify_key
        verify_key_hex_new = verify_key_new.encode(encoder=nacl.encoding.HexEncoder)
        verify_key.append(verify_key_new)
        verify_key_hex.append(verify_key_hex_new)

    output_list = []
    for i in range(0, 8):
        output_list.append(Output(100, verify_key_hex[i%8]))
    empty_input_list = []
    arbi_signing_key = nacl.signing.SigningKey(b'00000000000000000000000000000007')
    arbi_signed = arbi_signing_key.sign(b"arbitrary signing key")
    gen_transaction = Transaction(empty_input_list, output_list, arbi_signed, 0)
    gen_transaction.gen_number()
    j = gen_transaction.jsonify()
    gen_transaction.gen_number()
    gen_tx_num = gen_transaction.number

    arbiPrev = H(b'arbitrary prev').hexdigest()
    arbiNonce = H(b'arbitrary nonce').hexdigest()
    arbiPow = H(b'arbitrary pow').hexdigest()

    # Generate genesis block
    gen_block = Block(gen_transaction, arbiPrev, arbiNonce, arbiPow)
    inputs_from_gen_tx = []
    outputs_from_gen_tx = []
    sig = []

    for i in range(0, 8):
        new1 = []
        new2 = []
        new1.append(Input(gen_tx_num, Output(100, verify_key_hex[i%8])))
        k = (i+3)%8
        new2.append(Output(100,verify_key_hex[k]))
        inputs_from_gen_tx.append(new1)
        outputs_from_gen_tx.append(new2)

    for i in range(0, 8):
        message = serialize_list(inputs_from_gen_tx[i%8], "input")
        message += serialize_list(outputs_from_gen_tx[i%8], "output")
        message = message.encode("utf-8")
        sig.append(signing_key[i%8].sign(message))

    for i in range(0,10):
        node_list.append(Node(gen_block, i))

    for x in range(0,10):
        node_list[x].node_list = node_list
        mythread = Thread(target=myfunc, args=(gen_block, x))
        mythread.start()

    for i in range(0, 8):
        global_txpool_driver.append(Transaction(inputs_from_gen_tx[i], outputs_from_gen_tx[i], sig[i], 0))
        global_txpool_driver[i].gen_number()

    #creates and inserts bad txs here
    garbagelist = []
    garbagelist.append(Input(gen_tx_num, Output(0, verify_key_hex[3])))
    garbage_tx_1 = Transaction(garbagelist, outputs_from_gen_tx[3], sig[3], 0)
    garbage_tx_1.gen_number()
    global_txpool_driver.insert(3, garbage_tx_1)

    garbagelist2 = []
    garbagelist2.append(Output(0, verify_key_hex[5]))
    garbage_tx_2 = Transaction(inputs_from_gen_tx[5], garbagelist2, sig[5], 0)
    garbage_tx_2.gen_number()
    global_txpool_driver.insert(5, garbage_tx_2)

    newnumber = global_txpool_driver[2].number
    garbage_tx_3 = Transaction(inputs_from_gen_tx[3], outputs_from_gen_tx[3], sig[3], newnumber)
    global_txpool_driver.insert(2, garbage_tx_3)

    garbage_tx_4 = global_txpool_driver[1]
    global_txpool_driver.append(garbage_tx_4)

    #empty txs
    garbage_tx_5 = Transaction(None, None, sig[3], 0)
    global_txpool_driver.insert(7, garbage_tx_5)
    garbage_tx_6 = Transaction(None, None, None, None)
    global_txpool_driver.insert(8, garbage_tx_6)

    good_tx_inputs = []
    good_tx_inputs.append(Input(global_txpool_driver[0].number, global_txpool_driver[0].output[0]))
    message = serialize_list(good_tx_inputs, "input")
    message += serialize_list(global_txpool_driver[0].output, "output")
    message = message.encode("utf-8")
    gensig = signing_key[3].sign(message)
    good_tx = Transaction(good_tx_inputs, global_txpool_driver[0].output, gensig, 0)
    good_tx.gen_number()
    global_txpool_driver.append(good_tx)

    print("driver pool length:", len(global_txpool_driver))

    while(len(global_txpool_driver) != 0):
        time.sleep(random.random())
        global_txpool.append(global_txpool_driver[0])
        del global_txpool_driver[0]

    time.sleep(3)
    global doneflag
    while(doneflag == 2):
        counter = 0
        for x in range(0,9):
            currheight1 = node_list[i].max_height_treenode.height
            currheight2 = node_list[i-1].max_height_treenode.height
            if (currheight1 == currheight2):
                counter += 1
        if counter == 9:
            doneflag = 1

if __name__ == "__main__":
    main()
