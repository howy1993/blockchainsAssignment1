import json
import formatting
import queue
import nacl.signing
from hashlib import sha256 as H


# A tx output contains a value and a receipient public key
class Output:
    def __init__(self, value, pubkey):
        self.value = value
        self.pubkey = pubkey

    # Compares two Tx Output objects
    # input(s): A second Tx Output object
    # output(s): True if they are equal, false otherwise
    def compare(self, obj2):
        if self.value == obj2.value:
            if self.pubkey == obj2.pubkey:
                return 1
        return 0

# A transaction input contains a Tx number as well as a Tx Output object
class Input:
    def __init__(self, number, output):
        self.number = number
        self.output:Output = output  # each input holds 1 output

# A transaction object includes a list of Tx Inputs, a list of Tx Outputs,
# a Tx number and a signature covering the entire transaction
class Transaction:
    def __init__(self, inputs, outputs, sig, number):
        self.input = inputs
        self.output = outputs
        self.sig = sig
        self.number = number

    def serialize_self(self):
        s = []
        s.append(formatting.serialize(self.jsonify(), "input"))
        s.append(formatting.serialize(self.jsonify(), "output"))
        s.append(self.sig.signature.hex())
        s.append(str(self.number))
        return ''.join(s)

    def gen_number(self):
        j = self.jsonify()
        number = formatting.generate_number(j)
        self.number = number.hexdigest()

    def verify_number_hash(self):
        jsonT = self.jsonify()
        temp = formatting.generate_number(jsonT)
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

# A block contains 1 transaction object, the hash of the previous
# block, the proof-of-work, and the nonce that allows the entire
# block hash in JSON form to be below a target.
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

# TreeNode class allows each mining node to store heights of blocks
# We use a tree to keep track of height of orphan blocks.
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

        message = formatting.serialize_list(tx.input, "input")
        message += formatting.serialize_list(tx.output, "output")
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
            block_serialized = formatting.serialize_block(x.block)
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
            prev_serialized = formatting.serialize_block(prev)
            prev_encoded = prev_serialized.encode('utf-8')
            prevhash = H(prev_encoded).hexdigest()
            block_message = formatting.serialize_pre_block(tx, prevhash, nonce)
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
        block_serialized = formatting.serialize_block(new_block)
        block_encoded = block_serialized.encode('utf-8')
        currhash = H(block_encoded).hexdigest()
        for x in self.treenode_list:
            block_serialized = formatting.serialize_block(x.block)
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

    # Writes the node's blockchain to a file
    # input(s): nodename
    # output(s): none
    def writeBFile(self):
        fname = "node_{}_blockchain.json".format(self.name)
        el = formatting.blocklist(self.max_height_treenode)
        with open(fname, 'w') as outfile:
            json.dump(el,  outfile, indent=4)
