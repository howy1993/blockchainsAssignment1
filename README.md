## Overview
This implements a proof-of-work, UTXO blockchain in Python. Sha256 hash is from hashlib and digital signatures are ed25519 from pynacl.
JHU CS 601.641

## Running the program 
python3 driver.py

## Tests
A driver program initializes 15 transactions into a global pool. Nodes in different threads process these transactions into blocks.
We test several bad cases: double spends, blank fields in transactions, input sum != output sum as well as invalid utxo references. 

## Authors
Howy Ho
Daniel Hwang
