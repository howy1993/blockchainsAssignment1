import nacl.encoding
import queue
import time
import random
from hashlib import sha256 as H
from threading import Thread
import formatting
import structs



global_txpool = []
global_txpool_driver = []
node_list = []
doneflag = 2

def myfunc(gen_block, i):
    mining(node_list[i], i)
    node_list[i].writeBFile()

def mining(block, i):
    global doneflag
    global global_txpool
    while(doneflag != 0):
        if (doneflag == 1):
            doneflag = 0
        if (not block.q.empty()):
            new_block = block.q.get()
            block.receive_block(new_block)
        if (not block.txq.empty()):
            new_tx = block.txq.get()
            if block.verify(new_tx, block.max_height_treenode):
                block.mine_block(new_tx, block.max_height_treenode.block)
        if(len(global_txpool) != 0):
            new_tx = global_txpool[0]
            del global_txpool[0]
            for x in range(0,10):
                node_list[x].txq.put(new_tx)
            if block.verify(new_tx, block.max_height_treenode):
                block.mine_block(new_tx, block.max_height_treenode.block)

def main():
    ## Start of test.
    signing_key = []
    bytes_gen_array = []
    verify_key = []
    verify_key_hex = []

    # Deterministic bytes (unsure how to for-loop this)
    bytes_gen_array.append(b'00000000000000000000000000000000')
    bytes_gen_array.append(b'00000000000000000000000000000001')
    bytes_gen_array.append(b'00000000000000000000000000000002')
    bytes_gen_array.append(b'00000000000000000000000000000003')
    bytes_gen_array.append(b'00000000000000000000000000000004')
    bytes_gen_array.append(b'00000000000000000000000000000005')
    bytes_gen_array.append(b'00000000000000000000000000000006')
    bytes_gen_array.append(b'00000000000000000000000000000007')

    # Generates pk/sk keys using above deterministic bytes
    for i in range(0, 8):
        signing_key_new = nacl.signing.SigningKey(bytes_gen_array[i])
        signing_key.append(signing_key_new)
        verify_key_new = signing_key_new.verify_key
        verify_key_hex_new = verify_key_new.encode(encoder=nacl.encoding.HexEncoder)
        verify_key.append(verify_key_new)
        verify_key_hex.append(verify_key_hex_new)

    # Genesis Tx "premines" 100 coins to these 8 PKs
    output_list = []
    empty_input_list = []
    for i in range(0, 8):
        output_list.append(structs.Output(100, verify_key_hex[i%8]))
    arbi_signing_key = nacl.signing.SigningKey(b'00000000000000000000000000000007')
    gen_transaction = structs.Transaction(empty_input_list, output_list, arbi_signing_key.sign(b"arbitrary signing key"), 0)
    gen_transaction.gen_number()
    j = gen_transaction.jsonify()

    # Generates a genesis block containing above genesis Tx
    gen_block = structs.Block(gen_transaction, H(b'arbitrary prev').hexdigest(), H(b'arbitrary nonce').hexdigest(), H(b'arbitrary pow').hexdigest())

    # Creates good test transactions to populate global tx pool. 9 good transactions
    inputs_from_gen_tx = []
    outputs_from_gen_tx = []
    sig = []
    gen_tx_num = gen_transaction.number

    for i in range(0, 8):
        new1 = []
        new2 = []
        new1.append(structs.Input(gen_tx_num, structs.Output(100, verify_key_hex[i%8])))
        k = (i+3)%8
        new2.append(structs.Output(100,verify_key_hex[k]))
        inputs_from_gen_tx.append(new1)
        outputs_from_gen_tx.append(new2)

    for i in range(0, 8):
        message = formatting.serialize_list(inputs_from_gen_tx[i%8], "input")
        message += formatting.serialize_list(outputs_from_gen_tx[i%8], "output")
        message = message.encode("utf-8")
        sig.append(signing_key[i%8].sign(message))

    for i in range(0, 8):
        global_txpool_driver.append(structs.Transaction(inputs_from_gen_tx[i], outputs_from_gen_tx[i], sig[i], 0))
        global_txpool_driver[i].gen_number()

    good_tx_inputs = []
    good_tx_inputs.append(structs.Input(global_txpool_driver[0].number, global_txpool_driver[0].output[0]))
    message = formatting.serialize_list(good_tx_inputs, "input") + formatting.serialize_list(global_txpool_driver[0].output, "output")
    message = message.encode("utf-8")
    gensig = signing_key[3].sign(message)
    good_tx = structs.Transaction(good_tx_inputs, global_txpool_driver[0].output, gensig, 0)
    good_tx.gen_number()
    global_txpool_driver.append(good_tx)

    # Creates bad test transactions and adds them into global tx pool. 6 garbage transactions.
    garbagelist = []
    garbagelist.append(structs.Input(gen_tx_num, structs.Output(0, verify_key_hex[3])))
    garbage_tx_1 = structs.Transaction(garbagelist, outputs_from_gen_tx[3], sig[3], 0)
    garbage_tx_1.gen_number()
    global_txpool_driver.insert(3, garbage_tx_1)

    garbagelist2 = []
    garbagelist2.append(structs.Output(0, verify_key_hex[5]))
    garbage_tx_2 = structs.Transaction(inputs_from_gen_tx[5], garbagelist2, sig[5], 0)
    garbage_tx_2.gen_number()
    global_txpool_driver.insert(5, garbage_tx_2)

    newnumber = global_txpool_driver[2].number
    garbage_tx_3 = structs.Transaction(inputs_from_gen_tx[3], outputs_from_gen_tx[3], sig[3], newnumber)
    global_txpool_driver.insert(2, garbage_tx_3)

    garbage_tx_4 = global_txpool_driver[1]
    global_txpool_driver.append(garbage_tx_4)

    garbage_tx_5 = structs.Transaction(None, None, sig[3], 0)
    global_txpool_driver.insert(7, garbage_tx_5)
    garbage_tx_6 = structs.Transaction(None, None, None, None)
    global_txpool_driver.insert(8, garbage_tx_6)

    # Creates 10 nodes in this blockchain and starts test
    for i in range(0,10):
        node_list.append(structs.Node(gen_block, i))

    for x in range(0,10):
        node_list[x].node_list = node_list
        mythread = Thread(target=myfunc, args=(gen_block, x))
        mythread.start()

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
