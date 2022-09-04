# Solution to submit extrinsic from microcontroller like ESP8266 to Robonomics blockchain


# There are some predefined values to use
- URLRPC:  blockchain server address to connect
- PRIV_KEY: node private key
- SS58_ADR: linked ss58 address to private key of node
- SS58_DST_KEY: linked ss58 address to private key of destination node for TransferBalance extrinsic method

Note: to explore/create existing key/address can be used sub.py script from this repository or subkey utility from substrate

# Inplemented extrinsic methods
- DatalogRecord
- TransferBalance

# CI
There are in .github/workflows/ files:
- datalog-tiny-test.yml   ->  act -j libtests ->  to test parts of RpcRobonomics library on linux 
- datalog-tiny.yml        ->  act -j esp8622  ->  to build by arduino-cli  binary for target device

# Deploy 
Note: need to update in rpcjson.ino file STASSID  and STAPSK  macro definitions

