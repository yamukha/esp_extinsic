# solution to submit extrinsic from microcontroller like ESP8266 to Robonomics blockchain


# there are some predefined values to use
- URLRPC:  blockchain server address to connect
- PRIV_KEY: node private key
- SS58_ADR: linked ss58 address to private key of node
- SS58_DST_KEY: linked ss58 address to private key of destination node for TransferBalance extrinsic method

Note: to explore/create existing key/address can be used sub.py script from this repository or subkey utility from substrate

# inplemented extrinsic methods
DatalogRecord
TransferBalance
