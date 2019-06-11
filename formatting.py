import json
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
