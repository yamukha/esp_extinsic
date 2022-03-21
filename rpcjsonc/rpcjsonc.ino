#include <cstdint>
#include <vector>
#include <string>
#include <array>

#include <Arduino.h>
#include  <Arduino_JSON.h>
//#include <ArduinoJson.h>
#include <Data.h>

#include <Crypto.h>
#include <Ed25519.h>
#include <RNG.h>
#include <utility/ProgMemUtil.h>

#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

#ifndef STASSID
//#define STASSID "AirTies_Air4240" 
#define STASSID "FLY-TL-WR741ND"
#define STAPSK  "xxxxxxxxxx"
#endif

// commment to old json parsing (used with remote robonomics), uncomment to new one (with localhost)
#define RESPONSE_STRING_ARRAY
#ifdef RESPONSE_STRING_ARRAY
//#define URLRPC "http://192.168.2.26:9933"
//#define URLRPC "http://192.168.2.25:9933"
//#define URLRPC "http://192.168.0.102:9933"
//#define URLRPC "http://192.168.0.103:9933"
//#define URLRPC "http://192.168.1.35:9933"
//#define URLRPC "http://192.168.0.102:9933"
//#define TRANSACTION "http://192.168.0.102:9933"
#define URLRPC "http://kusama.rpc.robonomics.network:80/rpc/"
#define TRANSACTION "http://kusama.rpc.robonomics.network:80/rpc/"
#else
#define URLRPC "http://kusama.rpc.robonomics.network:80/rpc/"
#define TRANSACTION "http://kusama.rpc.robonomics.network:80/rpc/"
#endif

typedef struct uint128_s
{
  uint64_t lsb;
  uint64_t msb;
}uint128_t;

enum TWSS58AddressType {
    TWSS58AddressTypePolkadot = 0,
    TWSS58AddressTypeKusama = 2,
};

static constexpr size_t kMinUint16 = (1ul << 6u);
static constexpr size_t kMinUint32 = (1ul << 14u);
static constexpr size_t kMinBigInteger = (1ul << 30u);
static constexpr uint64_t kMaxBigInteger = (1ul << 31u) * (1ul << 31u);

static constexpr uint8_t signedBit = 0x80;
static constexpr uint8_t extrinsicFormat = 4;
static constexpr uint8_t sigTypeEd25519 = 0x00;
static constexpr uint32_t multiAddrSpecVersion = 28;
static constexpr uint32_t multiAddrSpecVersionKsm = 2028;
static constexpr TWSS58AddressType network = TWSS58AddressTypeKusama;

#define GET_PAYLOAD "{ \"jsonrpc\":\"2.0\", \"id\":1, \"method\":\"get_payload\", \"params\": [\"4GiRoiHkwqYdFpNJWrJrzPcRqaNWJayG1Lq5ZgLqoZwrZHjj\"]}"
#define SYS_VERSION "{ \"jsonrpc\":\"2.0\", \"id\":1, \"method\":\"system_version\", \"params\": [] }"

bool isGetParameters = true;
Data edata;
uint64_t id_conter = 0; 
uint8_t sig[64];
uint8_t privateKey[32];
uint8_t publicKey[32];
  
bool encodeRawAccount(TWSS58AddressType network, uint32_t specVersion) {
    if ((network == TWSS58AddressTypePolkadot && specVersion >= multiAddrSpecVersion) ||
        (network == TWSS58AddressTypeKusama && specVersion >= multiAddrSpecVersionKsm)) {
            return false;
        }
    return true;
}

inline Data encodeAccountId(const Data& bytes, bool raw) {
    auto data = Data{};
    if (!raw) {
        // MultiAddress::AccountId
        // https://github.com/paritytech/substrate/blob/master/primitives/runtime/src/multiaddress.rs#L28
        append(data, 0x00);
        /*
        std::string id = "12D3KooWBTxFpuyLJ7MpjxNTogMTa8nSLCQV7BAhQiFSkvuuiM8E";
        std::vector<uint8_t> vec; 
        vec.assign(id.begin(), id.end());
        append(data, vec);
        */
       }
    append(data, bytes);
    return data;
}

inline void encode32LE(uint32_t val, std::vector<uint8_t>& data) {
    data.push_back(static_cast<uint8_t>(val));
    data.push_back(static_cast<uint8_t>((val >> 8)));
    data.push_back(static_cast<uint8_t>((val >> 16)));
    data.push_back(static_cast<uint8_t>((val >> 24)));
}

// ! need to rework !
/*inline Data encodeCompact(uint32_t value) {
    auto data = Data{};
    encode32LE(value, data);
    return data;
} */

// only up to uint64_t
inline Data encodeCompact(uint64_t value) {
    auto data = Data{};
    if (value < kMinUint16) {
      auto v =  static_cast<uint8_t>(value) << 2u;
      data.push_back(static_cast<uint8_t>(v));
      return data;
    } else if (value < kMinUint32) {
      auto v = static_cast <uint16_t>(value) << 2u;
      v += 0x01; // set 0b01 flag
      auto minor_byte = static_cast<uint8_t>(v & 0xffu);
      data.push_back(minor_byte);
      v >>= 8u;
      auto major_byte = static_cast<uint8_t>(v & 0xffu);
      data.push_back(major_byte); 
      return data;
    } else if (value < kMinBigInteger) {
      uint32_t v = static_cast<uint32_t>(v) << 2u;
      v += 0x02; // set 0b10 flag
      encode32LE(v, data);
      return data;
    } else if (value < kMaxBigInteger ) {
      auto length = sizeof(uint64_t);
      uint8_t header = (static_cast<uint8_t>(length) - 4) * 4;
      header += 0x03; // set 0b11 flag;
      data.push_back(header);
      auto v = value;
      for (size_t i = 0; i < length; ++i) {
        data.push_back(static_cast<uint8_t>(v & 0xff)); // push back least significant byte
        v >>= 8;
      }
      return data;
    } else { // too big
      return data;
    }
}

inline void encodeLengthPrefix(Data& data) {
    size_t len = data.size();
    auto prefix = encodeCompact(len);
    data.insert(data.begin(), prefix.begin(), prefix.end());
}

void setup() {

  Serial.begin(115200);
  Serial.println();

  WiFi.begin(STASSID, STAPSK);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  Serial.printf ("Connected to SSID %s own IP address \n", STASSID);
  Serial.println(WiFi.localIP());

  Ed25519::generatePrivateKey(privateKey);
  Ed25519::derivePublicKey(publicKey, privateKey);
  //Serial.println(sig);
}
  
void loop() {
  uint128_t x = {0,1};
  String block_hash = "0x631ccc82a078481584041656af292834e1ae6daab61d2875b4dd0c14bb9b17bc";
  
  if ((WiFi.status() == WL_CONNECTED)) {

    WiFiClient client;
    HTTPClient http;
    std::string param0;
    Data data;
    Data call;
                       
    JSONVar params; 
    String jsonString;
    if (isGetParameters) {
        param0 = "4GiRoiHkwqYdFpNJWrJrzPcRqaNWJayG1Lq5ZgLqoZwrZHjj";
        params [0] = param0.c_str();
        JSONVar get_payload;    
        get_payload["jsonrpc"] = "2.0";
        get_payload["id"] = (double) id_conter; // todo increment
        get_payload["method"] = "get_payload";
        get_payload["params"] = params;
        jsonString = JSON.stringify(get_payload);
    } else {
      // fill params as hex
      /*
        char param0 [2 * edata.size() + 2];
        param0 [0] = '0'; 
        param0 [1] = 'x'; 
        for (int i = 0; i < edata.size(); i++) {
           char ch [2]; 
           sprintf(ch,"%02x",edata[i]);
           param0[i*2 + 2] = ch[0];
           param0[i*2 + 3] = ch[1];
        }
        params [0] = param0;
        */
        param0.append("0x");
        char ch [2];   
        for (int i = 0; i < edata.size();i++) {
                sprintf(ch,"%02x",edata[i]);
                param0.append(ch);
        }
        params [0] = param0.c_str();
        //params [0] = "0x3902840016eb796bee0c857db3d646ee7070252707aec0c7d82b2eda856632f6a2306a5801566e85037eee8e228414f49c797ef01e086364783b21a3b9910dcfcf600e1c0fca9207805301fad5da07c50d21e1358c734bcdcc2bdd9b29f969d188c817918b5401f4001f030016eb796bee0c857db3d646ee7070252707aec0c7d82b2eda856632f6a2306a58025a6202";
        // sample - {"jsonrpc":"2.0","error":{"code":1010,"message":"Invalid Transaction","data":"Transaction has a bad signature"},"id":1}
        // local  - {"jsonrpc":"2.0","error":{"code":1002,"message":"Verification Error: Runtime error: Execution failed: Execution aborted due to trap: wasm trap: wasm `unreachable` instruction executed\nWASM backtrace:\n\n    0: 0x1c254a - <unknown>!rust_begin_unwind\n    1: 0x2934 - <unknown>!core::panicking::panic_fmt::h6314b5c91abe7349\n    2: 0x4b559 - <unknown>!TaggedTransactionQueue_validate_transaction\n","data":"Runtime error: Execution failed: Execution aborted due to trap: wasm trap: wasm `unreachable` instruction executed\nWASM backtrace:\n\n    0: 0x1c254a - <unknown>!rust_begin_unwind\n    1: 0x2934 - <unknown>!core::panicking::panic_fmt::h6314b5c91abe7349\n    2: 0x4b559 - <unknown>!TaggedTransactionQueue_validate_transaction\n"},"id":1}
        // remote - {"jsonrpc":"2.0","error":{"code":1002,"message":"Verification Error: Runtime error: Execution failed: Error calling api function: Failed to convert parameter `tx` from node to runtime of validate_transaction","data":"Runtime error: Execution failed: Error calling api function: Failed to convert parameter `tx` from node to runtime of validate_transaction"},"id":1}
        // then   - {"jsonrpc":"2.0","error":{"code":1012,"message":"Transaction is temporarily banned"},"id":1}
               
        JSONVar extrinsic;        
        extrinsic["jsonrpc"] = "2.0";
        extrinsic["id"] = (double) id_conter;
        extrinsic["method"] = "author_submitExtrinsic";
        extrinsic["params"] = params;
        jsonString = JSON.stringify(extrinsic);
        edata.clear();
    }
    id_conter++;

    int httpCode = 0 ;
    if (isGetParameters) { 
      Serial.printf("[HTTP] to %s\n", URLRPC);

      http.begin(client, URLRPC); 
      http.addHeader("Content-Type", "application/json");

      Serial.print("[HTTP] POST:\n");
      Serial.println(jsonString);
    
      httpCode = http.POST(jsonString);  // GET_PAYLOAD
    } else {
      Serial.printf("[HTTP] to %s\n", TRANSACTION); 

      http.begin(client, TRANSACTION); // TRANSACTION ot URLRPC ?
      http.addHeader("Content-Type", "application/json");
     // http.addHeader("Accept" , "text/plain");
      Serial.print("[HTTP] POST:\n");
      Serial.println(jsonString);
    
     httpCode = http.POST(jsonString);  // submitExtrinsic
    }
    
    if (httpCode > 0) {
      
      Serial.printf("[HTTP] POST code: %d\n", httpCode);
      if (httpCode == HTTP_CODE_OK) {
        const String& payload = http.getString();
        Serial.println("received:");
        Serial.println(payload);
 
       JSONVar myObject = JSON.parse(payload);
       if (JSON.typeof(myObject) == "undefined") {
        Serial.println("Parsing input failed!");
       }
       else {
         JSONVar keys = myObject.keys();
         bool res = false;
         JSONVar val;
         String genesis_hash;
         uint32_t version = 0;     // transaction version 

#ifdef RESPONSE_STRING_ARRAY         
         String nonce;
         String tip;     // uint256_t tip;    // balances::TakeFees   
         String specVersion; // Runtime spec version 
         String era;
         String tx_version;         
#else
         uint64_t nonce;
         uint64_t tip;     // uint256_t tip;    // balances::TakeFees   
         uint32_t specVersion; // Runtime spec version 
         String era;
         uint32_t tx_version;
#endif                  
         //"result" or "error"
         for (int i = 0; i < keys.length(); i++) {
             JSONVar value = myObject[keys[i]];
             String str  = JSON.stringify (keys[i]);
         
             if(strstr(str.c_str(),"result")) {
               res = true;
               val = value; //Serial.println( JSON.typeof(value)); 
             }
       
             if(strstr(str.c_str(),"error"))  {
               val = value;
               isGetParameters = true;
             }       
         }
                 
         if (res) {
           if (isGetParameters) {
              //  get: genesis_hash, nonce, spec_version, tip, era, tx_version
              //  ["0x631ccc82a078481584041656af292834e1ae6daab61d2875b4dd0c14bb9b17bc",0,16,0,"Immortal",1]
              //  get: nonce, spec_version, tip, era, tx_version
              // ["0x00","0x01000000","0x00","0x0000000000000000","0x0100000000000000"]
                            
              String block_hash = "0x631ccc82a078481584041656af292834e1ae6daab61d2875b4dd0c14bb9b17bc";
#ifdef RESPONSE_STRING_ARRAY                  
              genesis_hash =  block_hash;
              nonce =  (const char*) (val[0]);
              specVersion = (const char*)(val[1]);
              tip =  (const char*)(val[2]);
              era =  (const char*)(val[3]); 
              tx_version = (const char*) (val[4]);
#else
              nonce =  long (val[1]);
              specVersion = int(val[2]);
              tip =  long (val[3]);
              era =  (const char*)(val[4]); 
              tx_version = int (val[5]);
#endif 
              Serial.println(val);
              Serial.println(genesis_hash);
              Serial.println(nonce);
              Serial.println(specVersion);
              Serial.println(tip);
              Serial.println(era);
              Serial.println(tx_version);
              
              // encodePayload();              
              append(data, call);  
#ifdef RESPONSE_STRING_ARRAY
              // encodeEraNonceTip()              
              /*
              append(data, era, 2);
              append(data, nonce, 2);
              append(data, tip, 2);
              append(data, specVersion, 2);
              */
              
              /*
              std::vector<uint8_t> vec;       
              vec.assign(era.begin() + 2, era.end());
              append(data, vec);

              std::vector<uint8_t> vec1;
              vec1.assign(nonce.begin() + 2, nonce.end());
              append(data, vec1);
             
              std::vector<uint8_t> vec2;
              vec2.assign(tip.begin() + 2, tip.end());
              append(data, vec2);

              std::vector<uint8_t> vec3;
              vec3.assign(specVersion.begin() + 2, specVersion.end());
              append(data, vec3);
              */
              append(data, encodeCompact(0)); // era
              append(data,encodeCompact(0));  // nonce
              append(data, encodeCompact(0)); //tip
              encode32LE(1, data);           // specversion
              encode32LE(1, data); // version
              genesis_hash = "0x631ccc82a078481584041656af292834e1ae6daab61d2875b4dd0c14bb9b17bc";
              std::vector<uint8_t> genesisHash; 
              genesisHash.assign(genesis_hash.begin(), genesis_hash.end());
              append(data, genesisHash);
              std::vector<uint8_t> blockHash;  
              blockHash.assign(block_hash.begin(), block_hash.end());
              append(data,  blockHash);       
#else
              /*std::vector<uint8_t> vec;       // encodeEraNonceTip()
              vec.assign(era.begin(), era.end()); // era
              append(data, vec);
              */
              append(data, encodeCompact(0)); //  era "Immortal"
              append(data, encodeCompact(nonce));
              append(data, encodeCompact(tip));
              encode32LE(specVersion, data);
              encode32LE(version, data);
              
              genesis_hash =  (const char*)(val[0]);                         
              std::vector<uint8_t> genesisHash; 
              genesisHash.assign(genesis_hash.begin(), genesis_hash.end());
              append(data, genesisHash);
              std::vector<uint8_t> blockHash;  
              blockHash.assign(block_hash.begin(), block_hash.end());
              append(data,  blockHash);              
#endif
              // sign payload
              uint8_t payload[data.size()];
              std::copy(data.begin(), data.end(), payload);
              Ed25519::sign(sig, privateKey, publicKey, payload, data.size());
              
              // encodeSignature(publicKey, signature); 
              append(edata, Data{extrinsicFormat | signedBit});  // version header

              //append(edata, encodeAccountId(publicKey.bytes, encodeRawAccount(network, specVersion)));  // signer public key
#ifdef RESPONSE_STRING_ARRAY
              bool etype =  encodeRawAccount(network, 1); // specVersion = 1
#else 
              bool etype =  encodeRawAccount(network, specVersion);
#endif    
              std::vector<std::uint8_t> pubKey( reinterpret_cast<std::uint8_t*>(std::begin(publicKey)), reinterpret_cast<std::uint8_t*>(std::end(publicKey)));
              append(edata, encodeAccountId(pubKey,etype));  // signer public key
              append(edata, sigTypeEd25519); // signature type
              std::vector<byte> signature (sig,sig + 64);        // signanture is data
              append(edata, signature);      // signature
              
              // era / nonce / tip // append(edata, encodeEraNonceTip());
#ifdef RESPONSE_STRING_ARRAY
              /*
              append(edata, era, 2);
              append(edata, nonce, 2);
              append(edata, tip, 2);      
              */
              /*
              std::vector<uint8_t> vec7;       // encodeEraNonceTip()
              vec7.assign(era.begin() + 2, era.end());
              append(edata, vec7);

              std::vector<uint8_t> vec8;
              vec8.assign(nonce.begin() + 2, nonce.end());
              append(edata, vec8);
              
              std::vector<uint8_t> vec9;
              vec9.assign(tip.begin() + 2, tip.end());
              append(edata, vec9);
              */
              append(edata, encodeCompact(0)); // era
              append(edata,encodeCompact(0));  // nonce
              append(edata, encodeCompact(0)); //tip
              
#else
              append(edata, encodeCompact(0)); //  era "Immortal"
              append(edata, encodeCompact(nonce));
              append(edata,encodeCompact(tip));
#endif              
              append(edata, call); // call
              encodeLengthPrefix(edata); // append length
                            
              char pl[edata.size()];
              std::copy(edata.begin(), edata.end(), pl);
              Serial.println(edata.size());
              for (int i = 0; i < edata.size();i++) {
                Serial.printf("%02x",pl[i]);
              }              
              Serial.printf("\nRPC extrinstic done\n");
              isGetParameters = false;
           } else {
              // create JSON and POST
              Serial.printf("RPC tx done\n");
              isGetParameters = true;
           } // isGetParameters
         } 
         else {
             Serial.println(val);
             isGetParameters = true;
         }  // res    
      } // JSON
    }  //HTTP_CODE_OK
    else {
      Serial.printf("[HTTP] POST... failed, error: %s\n", http.errorToString(httpCode).c_str());
      isGetParameters = true;
    }
  } // httpCode > 0
  else {
      Serial.printf("[HTTP] httpCode %d, %s\n", httpCode, http.errorToString(httpCode).c_str());
      isGetParameters = true;
  }
  http.end();
  delay(2000);
  }// WiFI
}
