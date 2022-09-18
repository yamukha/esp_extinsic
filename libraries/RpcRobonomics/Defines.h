#pragma once 

// Balance transfer extrinsic call in other case Datalog record call
//#define RPC_BALANCE_TX

//#define RPC_TO_LOCAL

#define KEYS_SIZE 32
#define SIGNATURE_SIZE 64

#define GENESIS_HASH_REMOTE     "631ccc82a078481584041656af292834e1ae6daab61d2875b4dd0c14bb9b17bc"

#ifdef RPC_TO_LOCAL
#define GENESIS_HASH     "c0ef85b9b694feb3f7e234b692982c9ae3a166af7b64360da8b7b6cb916e83b6"
#define URLRPC "http://192.168.0.102:9933"
#else
#define GENESIS_HASH     "631ccc82a078481584041656af292834e1ae6daab61d2875b4dd0c14bb9b17bc"
#define URLRPC "http://kusama.rpc.robonomics.network/rpc/"
#endif

#define PRIVKEY      "da3cf5b1e9144931a0f0db65664aab662673b099415a7f8121b7245fb0be4143"
#define SS58ADR       "5HhFH9GvwCST4kRVoFREE7qDJcjYteR5unhQCrBGhhGuRgNb"
#define BLOCK_HASH   "0xadb2edbde7e96a00d8c2fe37916bd76d395710d7f794d86c7339066b814f60d9"
//#define SS58DEST     "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
#define SS58KEY      "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
#define RECORD_DATA  "hey"
            
#define GET_PAYLOAD "{ \"jsonrpc\":\"2.0\", \"id\":1, \"method\":\"get_payload\", \"params\": [\"4GiRoiHkwqYdFpNJWrJrzPcRqaNWJayG1Lq5ZgLqoZwrZHjj\"]}"
