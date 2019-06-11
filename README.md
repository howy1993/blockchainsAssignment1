## Overview
This implements a "minimum viable blockchain" in Python. Nodes run in separate threads validating transactions, performs proof-of-works and mines blocks. SHA256 hash is from hashlib and digital signatures use the ed25519 standard from pynacl. Upon termination of program, each node prints its view of the blockchain into json files labelled "node_i_blockchain.json", where i is the node number. 

The initial class assignment required a single file for submission. I've split the file into 3 different files for better readability. I've also added a test program, testdiff.py, that checks the diff between the node outputs

## Running the program and tests
python3 driver.py
python3 testdiff.py

## Tests
A driver program initializes 15 transactions into a global pool. 9 of these transactions are good and 6 are bad. For the bad transactions, we test: double spends, blank fields in transactions, input sum != output sum as well as invalid utxo references. Testdiff checks the view of node 0 against every other node i and outputs if there is a difference. 

## Authors
Howy
Daniel Hwang
