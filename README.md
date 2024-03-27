## Introduction
This is a simple blockchain implementation that supports proof of work and proof of memory .

## How to run the program

* modify dsc-config.yaml for multi-node testing.
Before starting the blockchain components, please modify 'dsc-config.yaml' to set the correct IP address for blockchain, metronome and pool if you want to test the DSC blochain on different machines.
* change PROOF_HASH_MEMORY_SIZE to smaller value to reduce the time to initiate validator in proof of memory mode. 

**Commands:**
* use "./dsc.py blockchain" to start blockchain.
* use "./dsc.py metronome" to start metronome.
* use "./dsc.py pool" to start pool.
* use "./dsc.py validator" to start validator.

**Test:**
* use "./test.py latency <transaction_number>" to test latency of the blockchain.
* use "./test.py throughput <transaction_number>" to test throughput of the blockchain.

### Wallet commands
"./dsc.py wallet -h" for help.

### dsc-config.yaml
Validator "ProofType:" can be "pow" or "pom", "pom" is proof of memory, "pow" is proof of work.
