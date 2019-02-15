import json
import nacl.encoding
import nacl.signing
from hashlib import sha256 as H

DIFFICULTY = 0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


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
        elif term == "number":
            s.append(t["number"])
        elif term == "sig":
            s.append(t["sig"])
    return ''.join(s)

# Serializes transaction, previous hash, and nonce value
# input(s): transaction, prev value, nonce value
# output(s): a string of joined block contents
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



# Creates a JSON file for a block
# input(s): a TreeNode
# output(s): a JSON representation of a block
def JsonBlock(tnode):
    jsonBlock = {}
    jsonBlock["tx"] = tnode.block.tx
    jsonBlock["prev"] = tnode.block.prev
    jsonBlock["nonce"] = tnode.block.nonce
    jsonBlock["pow"] = tnode.block.pow
    return json.dumps(jsonBlock)

# Creates a block list in JSON
# inputs(s): treenode block with highest height
# output(s): list of JSON blocks
def blocklist(tnode):
    currNode = tnode
    blockchain = []
    
    # with given block with highest height, iterate backwards to genesis
    while (currNode.prevBlock != None):
        # create JSON from current block
        jb = JsonBlock(tnode)
        blockchain = [jb] + blockchain
        currNode = currNode.prevBlock

    return blockchain


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

if __name__ == "__main__":
    main()
