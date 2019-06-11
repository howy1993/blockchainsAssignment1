## Overview
This implements a "minimum viable blockchain" in Python. Nodes run in separate threads validating transactions, performs proof-of-works and mines blocks. SHA256 hash is from hashlib and digital signatures use the ed25519 standard from pynacl.

## Running the program 
python3 driver.py

## Tests
A driver program initializes 15 transactions into a global pool. Nodes in different threads process these transactions into blocks.
We test several bad cases: double spends, blank fields in transactions, input sum != output sum as well as invalid utxo references. 

## Authors
Howy
Daniel Hwang
