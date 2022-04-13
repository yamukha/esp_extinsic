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

// Balance transfer extrinsic call in other case Datalog record call
//#define RPC_BALANCE_TX

//#define RPC_TO_LOCAL
#ifdef RPC_TO_LOCAL
#define GENESIS_HASH     "c0ef85b9b694feb3f7e234b692982c9ae3a166af7b64360da8b7b6cb916e83b6"
#define CALL_BALANCE_TX  "0700008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a4804"
#define URLRPC "http://192.168.0.102:9933"
#define TRANSACTION "http://192.168.0.102:9933"
//#define URLRPC "http://192.168.2.26:9933"
//#define URLRPC "http://192.168.2.25:9933"
//#define URLRPC "http://192.168.0.102:9933"
//#define URLRPC "http://192.168.0.103:9933"
//#define URLRPC "http://192.168.1.35:9933"
#else
#define GENESIS_HASH     "631ccc82a078481584041656af292834e1ae6daab61d2875b4dd0c14bb9b17bc"
#define CALL_BALANCE_TX  "1f00008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a4804"
#define URLRPC "http://kusama.rpc.robonomics.network/rpc/"
#define TRANSACTION "http://kusama.rpc.robonomics.network/rpc/"
#endif

#define BLOCK_HASH   "0xadb2edbde7e96a00d8c2fe37916bd76d395710d7f794d86c7339066b814f60d9"
#define SS58DEST     "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
#define SS58KEY      "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"

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
uint64_t fee = 300; 
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

std::vector<uint8_t> hex2bytes (std::string hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
      std::string byteString = hex.substr(i, 2);
      uint8_t byte = (uint8_t) strtol(byteString.c_str(), NULL, 16);
      bytes.push_back(byte);
    }
    return bytes;
}

std::vector<uint8_t> callDatalogRecord (Data head, std::string str) {
    Data call;
    append(call, head);
    append(call, encodeCompact(str.length()));
    std::vector<uint8_t> rec(str.begin(), str.end());
    append(call, rec); 
    return call;
}

std::vector<uint8_t> callTransferBalance (Data head, std::string str, uint64_t fee ) {
    Data call;
    append(call, head); 
    std::vector<uint8_t> dst = hex2bytes (str.c_str()); // derived SS58KEY from SS58DST 
    append(call, dst); 
    append(call, encodeCompact(fee)); // value
    return call;
}

std::vector<uint8_t> doPayload (Data call, uint32_t era, uint64_t nonce, uint64_t tip, uint32_t sv, uint32_t tv, std::string gen, std::string block) {
    Data data;
    append(data, call);
    append(data, encodeCompact(era)); // era; note: it simplified to encode, maybe need to rewrite
    append(data, encodeCompact(nonce));
    append(data, encodeCompact(tip));
              
    encode32LE(sv, data);     // specversion
    encode32LE(tv, data);     // version
            
    std::vector<uint8_t> gh = hex2bytes(gen.c_str());
    append(data, gh);
    std::vector<uint8_t> bh = hex2bytes(block.c_str()); // block hash
    append(data, bh);     
    return data;
}

std::string swapEndian(String str) {
    std::string hex = str.c_str();
    std::string bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
      std::string s = hex.substr(i, 2);
      if ( !(strstr(s.c_str(),"0x")) && !(strstr(s.c_str(),"0X")) ) {
        std::string byteString = hex.substr(i, 2);
        bytes.insert(0,byteString);
      }
    }
    return bytes;
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

  //Ed25519::generatePrivateKey(privateKey);
  std::vector<uint8_t> vk = hex2bytes("da3cf5b1e9144931a0f0db65664aab662673b099415a7f8121b7245fb0be4143");
  std::copy(vk.begin(), vk.end(), privateKey);
  
  Ed25519::derivePublicKey(publicKey, privateKey);  
  //std::vector<uint8_t> pk = hex2bytes("f90bc712b5f2864051353177a9d627605d4bf7ec36c7df568cfdcea9f237c185");
  //std::copy(pk.begin(), pk.end(), publicKey);  
}
  
void loop() {
    
  if ((WiFi.status() == WL_CONNECTED)) {

    WiFiClient client;
    HTTPClient http;
    std::string param0;
    Data data;
                       
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
        param0.append("0x");
        char ch [2];   
        for (int i = 0; i < edata.size();i++) {
                sprintf(ch,"%02x",edata[i]);
                param0.append(ch);
        }
        params [0] = param0.c_str();
          
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
         String block_hash;
         uint32_t version = 0;  // transaction version 
         uint64_t nonce;
         uint64_t tip;          // uint256_t tip;    // balances::TakeFees   
         uint32_t specVersion;  // Runtime spec version 
         String era;
         uint32_t tx_version;
         uint32_t eraI;
                  
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
  
#ifdef RESPONSE_STRING_ARRAY                  
              genesis_hash =  GENESIS_HASH;
              String nonce_ =  (const char*) (val[0]);
              String specVersion_ = (const char*)(val[1]);
              String tip_ =  (const char*)(val[2]);
              era =  (const char*)(val[3]); 
              String tx_version_ = (const char*) (val[4]);

              std::string nonceS  = swapEndian (nonce_);
              nonce =  strtol(nonceS.c_str(), NULL, 16);

              std::string tipS = swapEndian (tip_);
              tip =  strtol(tipS.c_str(), NULL, 16);

              std::string specVer = swapEndian (specVersion_);
              specVersion =  strtol(specVer.c_str(), NULL, 16);

              std::string txVer = swapEndian (tx_version_);
              tx_version = strtol(txVer.c_str(), NULL, 16); 
  
              std::string eraS = swapEndian (era);
              eraI = strtol(eraS.c_str(), NULL, 16); 
                                      
#else
              genesis_hash = (const char*)(val[0]); // or block_hash ? 
              nonce =  long (val[1]);
              specVersion = int(val[2]);
              tip =  long (val[3]);
              era =  (const char*)(val[4]); 
              tx_version = int (val[5]);
              
              if (strstr(era.c_str(),"Immortal")) {
                eraI = 0;
              }
              else {
                std::string eraS = swapEndian (era);
                eraI = strtol(eraS.c_str(), NULL, 16); 
              } 
#endif 
              Serial.println(val);
              Serial.println(genesis_hash);
              Serial.printf("nonce: %ld\n",nonce);
              Serial.printf("specVersion: %ld\n",specVersion);
              Serial.printf("tip: %ld\n",tip); 
              Serial.printf("era: %ld\n",eraI);
              Serial.printf("tx_version: %ld\n",tx_version);
                            
              //  ==== encodePayload() ===            
#ifdef RPC_TO_LOCAL
#ifdef RPC_BALANCE_TX
              Data call = callTransferBalance(Data{7,0,0}, SS58KEY, ++fee); // call header for Balance transfer
#else
              Data call = callDatalogRecord(Data{0x10,0}, "ooo"); // call header for Datalog record + some payload
#endif
#else
#ifdef RPC_BALANCE_TX
              Data call = callTransferBalance(Data{0x1f, 0, 0}, SS58KEY, ++fee); // call header for Balance transfer
#else
              Data call = callDatalogRecord(Data{0x33,0}, "ooo"); // call header for Datalog record + some payload
#endif
#endif
              //append(data, call);               
              
#ifdef RESPONSE_STRING_ARRAY
              // == encodeEraNonceTip() == 
              data = doPayload (call, eraI, nonce, tip, specVersion, tx_version, GENESIS_HASH, GENESIS_HASH);
              /*append(data, encodeCompact(eraI)); // era; note: it simplified to encode, maybe need to rewrite
              append(data,encodeCompact(nonce)); // nonce
              append(data, encodeCompact(tip)); //tip
              
              encode32LE(specVersion, data);    // specversion
              encode32LE(tx_version, data);     // version 

              std::vector<uint8_t> gh = hex2bytes(GENESIS_HASH);
              append(data, gh);
              append(data, gh);
              */
#else
              append(data, encodeCompact(eraI)); // era; note: it simplified to encode, maybe need to rewrite
              append(data, encodeCompact(nonce));
              append(data, encodeCompact(tip));
              
              encode32LE(specVersion, data);  // specversion
              encode32LE(tx_version, data);      // version
            
              std::vector<uint8_t> gh = hex2bytes(GENESIS_HASH);
              append(data, gh);
              append(data, gh);     
#endif
              // sign payload
              uint8_t payload[data.size()];             
      
              std::copy(data.begin(), data.end(), payload);
              Ed25519::sign(sig, privateKey, publicKey, payload, data.size());
              Serial.printf("\Payload raw: len %d , data:\n", data.size());
              for (int i = 0; i < data.size(); i++) {
                Serial.printf("%02x",payload[i]);
              }
              Serial.printf("\nSigned payload: len %d , data:\n", 64);
              for (int i = 0; i < 64; i++) {
                Serial.printf("%02x",sig[i]);
              }
              
              // == encodeSignature(publicKey, signature) ; == 
              append(edata, Data{extrinsicFormat | signedBit});  // version header
              append(edata,0);
             
              //append(edata, encodeAccountId(publicKey.bytes, encodeRawAccount(network, specVersion)));  // signer public key
#ifdef RESPONSE_STRING_ARRAY
              bool etype =  encodeRawAccount(network, 16); // specVersion = 1
#else 
              bool etype =  encodeRawAccount(network, specVersion);
#endif    
              Serial.printf("\nAccountID type %d, data:\n", etype);
              for (int i = 0; i < 32; i++) {
                Serial.printf("%02x",publicKey[i]);
              }
              Serial.println("");
    
              std::vector<std::uint8_t> pubKey( reinterpret_cast<std::uint8_t*>(std::begin(publicKey)), reinterpret_cast<std::uint8_t*>(std::end(publicKey)));
              //append(edata, encodeAccountId(pubKey,etype));  // signer public key
              append(edata,pubKey);  // signer public key
              
              append(edata, sigTypeEd25519); // signature type
              std::vector<byte> signature (sig,sig + 64);    // signanture is signed data
              append(edata, signature);      // signatured payload
              
              // era / nonce / tip // append(edata, encodeEraNonceTip());
#ifdef RESPONSE_STRING_ARRAY
              append(edata, encodeCompact(eraI)); // era; note: it simplified to encode, maybe need to rewrite
              append(edata, encodeCompact(nonce)); 
              append(edata, encodeCompact(tip));                            
#else
              append(edata, encodeCompact(eraI)); // era; note: it simplified to encode, maybe need to rewrite
              append(edata, encodeCompact(nonce));
              append(edata,encodeCompact(tip));
#endif        
              append(edata, call);
              encodeLengthPrefix(edata); // append length
                            
              char pl[edata.size()];
              std::copy(edata.begin(), edata.end(), pl);
              Serial.printf("size %d\n", edata.size());
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
