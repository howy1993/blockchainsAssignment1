import json
import nacl.encoding
import nacl.signing
import queue
from hashlib import sha256 as H


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
    print("generating number of transaction!")
    serials = []
    # serialize each transaction (each input and output)
    for ele in ["input", "output"]:
        res = serialize(tx, ele)
        serials.append(res)

    d = json.loads(tx)
    # add signature
    serials.append(d["sig"])
    joinedSerials = "".join(serials)
    encodedSerials = joinedSerials.encode('utf-8')
    # hash the serialized data
    hashedSerials = H(encodedSerials)

    return hashedSerials


# Serializes transaction, previous hash, and nonce value
# input(s): transaction, prev hash, and nonce
# output(s): string concatenation
def serialize_pre_block(tx, prev, nonce):
    # serialize specifically for a transaction
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
# output(s): list of JSON blocks
def blocklist(tnode):
    currNode = tnode
    blockchain = []

    # with given block with highest height, iterate backwards to genesis
    while (currNode.prevBlock is not None):
        # create JSON from current block
        jb = JsonBlock(tnode)
        blockchain = [jb] + blockchain
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

    # create hash of previous block
    prevBlock = tnode.block.prev
    prevBlockSerial = serialize_block(prevBlock)
    prevBlockEncode = prevBlockSerial.encode('utf-8')
    prevBlockHash = H(prevBlockEncode)
    jsonBlock["prev"] = prevBlockHash.hexdigest()
    jsonBlock["nonce"] = str(tnode.block.nonce)
    jsonBlock["pow"] = str(tnode.block.pow)
    return json.dumps(jsonBlock)


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
        self.output:Output = output  # each input holds 1 output


class Transaction:
    def __init__(self, inputs, outputs, sig):
        self.input = inputs
        self.output = outputs
        # is a signature object with both: sig.message, sig.signature
        self.sig = sig
        self.number = 0

    def serialize_self(self):
        s = []
        s.append(serialize(self.jsonify(), "input"))
        s.append(serialize(self.jsonify(), "output"))
        # convert signature (bytes) to hex format (str) for serialization
        # can revert sig (str) back to bytes with bytes.fromhex(sig)
        s.append(self.sig.signature.hex())
        s.append(str(self.number))
        return ''.join(s)

    def gen_number(self):
        j = self.jsonify()
        number = generate_number(j)
        self.number = number.hexdigest()

    def verify_number_hash(self):
        print("verifying number hash!")
        jsonT = self.jsonify()
        print("jsonT = {}".format(jsonT))
        temp = generate_number(jsonT)
        print("temp = {}".format(temp))
        print("self = {}".format(self.number))
        return (temp == self.number)

    def jsonify(self):
        print("jsonifying!")
        jsonObj = {}

        inputList = []
        print("self.input = {}".format(self.input))

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

        return json.dumps(jsonObj, indent=4)


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

    # Checks that tx number has not been used in any prevBlocks
    def verify_not_used(self, local_tx:Transaction, treenode:TreeNode):
        print("==== verify not used ====")
        y = treenode
        while(y is not None):
            if local_tx.number == y.block.tx.number:
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
            flag2 += 1
            while(flag < flag2):
                if x.number == y.block.tx.number:
                    for z in y.block.tx.output:
                        if z.compare(x.output):
                            flag += 1
                elif y.prevBlock is not None:
                    y = y.prevBlock
                else:
                    break
        return max(flag - len(local_tx.input), 0)

    # Checks public key for all inputs, checks signature
    def verify_public_key_signatures(self, tx:Transaction):
        # check same public key
        pubkey1 = tx.input[0].output.pubkey
        for x in tx.input:
            if x.output.pubkey != pubkey1:
                return 0
        # serializes content and verifies signature to key
        message = serialize_list(tx.input, "input")
        message += serialize_list(tx.output, "output")
        message = message.encode("utf-8")
        verify_key = nacl.signing.VerifyKey(pubkey1, encoder=nacl.encoding.HexEncoder)
        return verify_key.verify(message, tx.sig.signature)

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
                for z in y.block.tx.input:
                    if x.number == z.number:
                        flag+=1
                    elif y != None:
                        y = y.prevBlock
                    else:
                        return max(flag - len(tx.input),0)
        return max(flag - len(tx.input), 0)

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
        print("verifying!")
        flag = tx.verify_number_hash()
        flag *= self.verify_not_used(tx, treenode)
        flag *= self.verify_tx_inputs(tx)
        flag *= self.verify_public_key_signatures(tx)
        flag *= self.verify_double_spend(tx)
        flag *= self.verify_sum(tx)
        return bool(flag)
    
    def verify_pow(self, block:Block):
        #Check that PoW is below target
        return (block.pow < 0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

    def verify_prev_hash(self, block:Block):
        #Check that PoW generated from hashing block with appropriate nonce
        block_serialized = serialize_block(block)
        block_encoded = prev_serialized.encode('utf-8')
        prevhash = H(block_encoded).hexdigest()
        return (block.prev == prevhash)

    def verify_tx_in_block(self, block:Block, treenode:TreeNode):
        return self.verify(block.tx, treenode)

    def update_longest_chain(new_block_tree_node):
        if (new_block_tree_node.height > self.current_max_height_tree_node.height):
                self.current_max_height_tree_node = new_block_tree_node

    def mine_block(tx:Transaction, prev:Block):
        proofow = 0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF + 1
        target = 0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        nonce = 0
        print("mine block")
        while (proofow > target):
            nonce += 1
            prev_serialized = serialize_block(prev)
            prev_encoded = prev_serialized.encode('utf-8')
            prevhash = H(prev_encoded).hexdigest()
            block_message = serialize_pre_block(tx, prevhash, nonce)
            proofow = H(block_message.encode('utf-8'))
            proofow = proofow.digest()
            target = b'target'

        # Once verified, push nonce/pow/prev into a new block and send it out
        new_block = Block(tx, prev, nonce, proofow)
        new_treenode = TreeNode(new_block, self.current_max_height_tree_node, self.current_max_height_tree_node.height+1)
        self.treenode_list.append(new_treenode)
        self.update_longest_chain(new_treenode)
        self.send_block(new_block)

    def send_block(new_block):
        #for x in node_list:
        #    x.q
        return 1

    def receive_block(self):
        #TODO: validate block?
        #update_longest_chain(new_block)
        return 1

    def mining(self, global_tx_pool):
        print("starting mining...")
        while(True): #global variable
            #sleep(random)
            print("looping")
            print("q size = {}".format(self.q.qsize()))
            if (not self.q.empty()):
                new_block = self.q.get()

            print("global_tx_pool = {}".format(global_tx_pool))
            if(len(global_tx_pool) != 0):
                new_tx = global_tx_pool[0]
                del global_tx_pool[0]
                print("new_tx = {}".format(new_tx))
                if self.verify(new_tx, self.current_max_height_tree_node) == True:
                    print("verified")
                    self.mine_block(new_tx, self.current_max_height_tree_node.block)

            print("len global tx pool")
            if(len(global_tx_pool) == 0):
                return


def main():
    ## Start of test.
    signing_key = []
    verify_key = []
    verify_key_hex = []

    # Generate 8 random pksk pairs
    for i in range(0, 8):
        signing_key_new = nacl.signing.SigningKey.generate()
        verify_key_new = signing_key_new.verify_key
        verify_key_hex_new = verify_key_new.encode(encoder=nacl.encoding.HexEncoder)
        signing_key.append(signing_key_new)
        verify_key.append(verify_key_new)
        verify_key_hex.append(verify_key_hex_new)

    output_list = []
    # Generate contents for gen block. All 8 pksk pairs get 100 coins
    for i in range(0, 8):
        output_list.append(Output(100, verify_key_hex[i]))

    empty_input_list = []

    # generate arbitrary signature object (contains message and signature)
    arbi_signing_key = nacl.signing.SigningKey.generate()
    arbi_signed = arbi_signing_key.sign(b"arbitrary signing key")
    gen_transaction = Transaction(empty_input_list, output_list, arbi_signed)

    j = gen_transaction.jsonify()

    # generate the number for the transaction
    gen_transaction.gen_number()
    gen_transaction_number = gen_transaction.number

    #print("gen_transaction_number = {}".format(gen_transaction_number))
    
    arbiPrev = H(b'arbitrary prev').hexdigest()
    arbiNonce = H(b'arbitrary nonce').hexdigest()
    arbiPow = H(b'arbitrary pow').hexdigest()


    # Generate genesis block
    gen_block = Block(gen_transaction, arbiPrev, arbiNonce, arbiPow)

    # Initialize all nodes with genesis block
    node_list = []
    for i in range(0, 10):
        node_list.append(Node(gen_block))


    # populate each node's node_list with every other node
    for i in range(0, 10):
        node_list[i].node_list = node_list

    global_tx_pool = []
    no_more_tx = 1
    inputs_from_gen_tx = []
    outputs_from_gen_tx = []
    sig = []

    for i in range(0, 3):
        new1 = []
        new2 = []
        new1.append(Input(gen_transaction_number, Output(100, verify_key_hex[i])))
        new2.append(Output(100,verify_key_hex[i+3]))
        inputs_from_gen_tx.append(new1)
        outputs_from_gen_tx.append(new2)

    for i in range(0, 3):
        message = serialize_list(inputs_from_gen_tx[i], "input")
        message += serialize_list(outputs_from_gen_tx[i], "output")
        message = message.encode("utf-8")
        sig.append(signing_key[i].sign(message))

    
    for i in range(0, 3):
        global_tx_pool.append(Transaction(inputs_from_gen_tx[i], outputs_from_gen_tx[i], sig[i]))
    

    print("======mine node[1]=========")
    node_list[1].mining(global_tx_pool)
    print(node_list[1].current_max_height_tree_node.height)



if __name__ == "__main__":
    main()
