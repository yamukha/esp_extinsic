#include <cstdint>
#include <vector>
#include <string>
#include <iterator> 
#include <array>
#include <Scheduler.h>

#include <Arduino.h>
#include  <Arduino_JSON.h>
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

// Balance transfer extrinsic call in other case Datalog record call
//#define RPC_BALANCE_TX

//#define RPC_TO_LOCAL
#ifdef RPC_TO_LOCAL
#ifdef RPC_BALANCE_TX
    Data head = Data{7,0};     // call header for Balance transfer
#else
    Data head = Data{0x10,0};  // call header for Datalog record + some payload
#endif
#else
#ifdef RPC_BALANCE_TX
    Data head = Data{0x1f,0};  // call header for Balance transfer
#else
    Data head = Data{0x33,0}; // call header for Datalog record + some payload
#endif
#endif 

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


typedef struct {
   std::string ghash;      // genesis hash
   std::string bhash;      // block_hash
   uint32_t version = 0;   // transaction version 
   uint64_t nonce;
   uint64_t tip;           // uint256_t tip;    // balances::TakeFees   
   uint32_t specVersion;   // Runtime spec version 
   uint32_t tx_version;
   uint32_t era;
} FromJson;

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

bool isGetParameters = true;
Data edata;
uint64_t id_counter = 0; 
uint64_t fee = 330; 
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
    append(call, 0); 
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

std::vector<uint8_t> doSign(Data data, uint8_t privateKey[32], uint8_t publicKey[32]) {
  
    uint8_t payload[data.size()];             
    uint8_t sig[64];
     
    std::copy(data.begin(), data.end(), payload);
    Ed25519::sign(sig, privateKey, publicKey, payload, data.size());
           
    std::vector<byte> signature (sig,sig + 64);   // signed data as bytes vector
    return signature;
}

std::vector<uint8_t> doEncode (Data signature, Data pubKey, uint32_t era, uint64_t nonce, uint64_t tip, Data call) {
    Data edata;
    append(edata, Data{extrinsicFormat | signedBit});  // version header
    append(edata,0);

    //std::vector<std::byte> pubKey( reinterpret_cast<std::byte*>(std::begin(publicKey)), reinterpret_cast<std::byte*>(std::end(publicKey)));
    append(edata,pubKey);  // signer public key
    append(edata, sigTypeEd25519); // signature type
    append(edata, signature);      // signatured payload
              
    // era / nonce / tip // append(edata, encodeEraNonceTip());
    append(edata, encodeCompact(era)); // era; note: it simplified to encode, maybe need to rewrite
    append(edata, encodeCompact(nonce)); 
    append(edata, encodeCompact(tip));                            
  
    append(edata, call);
    encodeLengthPrefix(edata); // append length
              
    return edata;
}

std::string swapEndian(std::string str) {
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

//  -- genesis_hash, nonce, spec_version, tip, era, tx_version
//  ["0x631ccc82a078481584041656af292834e1ae6daab61d2875b4dd0c14bb9b17bc",0,16,0,"Immortal",1]
//  -- nonce, spec_version, tip, era, tx_version
// ["0x00","0x01000000","0x00","0x0000000000000000","0x0100000000000000"]
FromJson parseJson (JSONVar val) {
   Serial.println(val);
   FromJson fj;
   
   std::string nonce_ =  (const char*) (val[0]);
   std::string specVersion_ = (const char*)(val[1]);
   std::string tip_ =  (const char*)(val[2]);
   std::string era_ =  (const char*)(val[3]); 
   std::string tx_version_ = (const char*) (val[4]);

   std::string nonceS  = swapEndian (nonce_);
   fj.nonce =  strtol(nonceS.c_str(), NULL, 16);

   std::string tipS = swapEndian (tip_);
   fj.tip =  strtol(tipS.c_str(), NULL, 16);

   std::string specVer = swapEndian (specVersion_);
   fj.specVersion =  strtol(specVer.c_str(), NULL, 16);

   std::string txVer = swapEndian (tx_version_);
   fj.tx_version = strtol(txVer.c_str(), NULL, 16); 
  
   std::string eraS = swapEndian (era_);
   fj.era = strtol(eraS.c_str(), NULL, 16);

   fj.ghash = GENESIS_HASH;
   fj.bhash = GENESIS_HASH;

#ifdef DEBUG_JSON                   
   Serial.println(fj.ghash.c_str());
   Serial.printf("nonce: %ld\n",fj.nonce);
   Serial.printf("specVersion: %ld\n",fj.specVersion);
   Serial.printf("tip: %ld\n",fj.tip); 
   Serial.printf("era: %ld\n",fj.era);
   Serial.printf("tx_version: %ld\n",fj.tx_version);
#endif

   return fj;
}

String getPayloadJs (std::string account, uint64_t id_cnt) {
   String jsonString;
   JSONVar params;
   params [0] = account.c_str();

   JSONVar get_payload;    
   get_payload["jsonrpc"] = "2.0";
   get_payload["id"] = (double) id_cnt; // to increment
   get_payload["method"] = "get_payload";
   get_payload["params"] = params;
   jsonString = JSON.stringify(get_payload); 
   return jsonString;
}

String fillParamsJs (std::vector<uint8_t> data, uint64_t id_cnt) {
    String jsonString;
    JSONVar params;
    std::string param0;
    
    param0.append("0x");
    char ch [2];   
    for (int i = 0; i < data.size();i++) {
        sprintf(ch,"%02x",data[i]);
        param0.append(ch);
    }
    params [0] = param0.c_str();
          
    JSONVar extrinsic;        
    extrinsic["jsonrpc"] = "2.0";
    extrinsic["id"] = (double) id_counter;
    extrinsic["method"] = "author_submitExtrinsic";
    extrinsic["params"] = params;
    jsonString = JSON.stringify(extrinsic);
 
    return jsonString;
}

typedef struct {
   std::string body;      // responce body
   uint32_t code;         // http responce code 200, 404, 500 etc.
} RpcResult;

class RobonomicsRpc { 
  public:     
    RobonomicsRpc (WiFiClient client, std::string url, std::string key)
        : wifi_(client), url_(url), key_(key), isGetParameters_ (true) 
        {};

    RpcResult DatalogRecord (std::string record) {

    Data edata_;
    
    for (int a = 0 ; a < 2;  a++) {

      HTTPClient http;    
      http.begin(wifi_, url_.c_str());
      http.addHeader("Content-Type", "application/json");
      Serial.print("[HTTP]+POST:\n"); 
      JSONVar params; 
      String jsonString;
      if (isGetParameters_) {
        jsonString = getPayloadJs ("5HhFH9GvwCST4kRVoFREE7qDJcjYteR5unhQCrBGhhGuRgNb",id_counter);
      } else {
        jsonString = fillParamsJs (edata_,id_counter);
        edata_.clear();
      }
      Serial.println("sent:");
      Serial.println(jsonString);
      id_counter++;
    
      int httpCode = http.POST(jsonString);

      if (httpCode > 0) {
          Serial.printf("[HTTP]+POST code: %d\n", httpCode);
            if (httpCode == HTTP_CODE_OK) {
              const String& payload = http.getString();
              Serial.println("received:");
              Serial.println(payload);
         
              JSONVar myObject = JSON.parse(payload);
              if (JSON.typeof(myObject) == "undefined") {
                  Serial.println("");
                  RpcResult r {"Parsing input failed!", -100};
                  return r;               
              } else {
                // RPC FSM                 
                JSONVar keys = myObject.keys();
                bool res_ = false;
                JSONVar val;
                FromJson fj;
                  
                //"result" or "error" 
                for (int i = 0; i < keys.length(); i++) { 
                  JSONVar value = myObject[keys[i]];
                  String str  = JSON.stringify (keys[i]);
                 
                  if(strstr(str.c_str(),"result")) {
                    res_ = true;
                    val = value;
                  }
       
                  if(strstr(str.c_str(),"error"))  {
                    val = value;
                    isGetParameters_ = true;
                  }
                }
                
                // -- 2nd stage: create and send extrinsic
                if (res_) {
                  Serial.println("Try 2nd stage with extrinsic"); 
                  if (isGetParameters_) {
                    fj = parseJson (val);
                    Data call = callDatalogRecord(head, record); // call header for Datalog record + some payload
                    Data data_ = doPayload (call, fj.era, fj.nonce, fj.tip, fj.specVersion, fj.tx_version, fj.ghash, fj.bhash);
                    Data signature_ = doSign (data_, privateKey, publicKey);
                    std::vector<std::uint8_t> pubKey( reinterpret_cast<std::uint8_t*>(std::begin(publicKey)), reinterpret_cast<std::uint8_t*>(std::end(publicKey)));               
                    edata_ = doEncode (signature_, pubKey, fj.era, fj.nonce, fj.tip, call);
                    Serial.printf("size %d\n", edata_.size()); 
                    isGetParameters_ = false;
                  } else {
                    isGetParameters_ = true;
                    RpcResult r {"O.K", httpCode};
                    return r;
                  }
                } else {
                  isGetParameters_ = true;
                  RpcResult r {"htpp O.K. but RPC error ", httpCode};
                  return r;
               }// res_
           } // json parse
        } else {
            isGetParameters_ = true;
            RpcResult r {"http not 200 error: ", httpCode};
            return r;
         } // httpCode == HTTP_CODE_OK
      } else {
        isGetParameters_ = true;
        RpcResult r {"http > 0 error: ", httpCode};
        return r;
      } // httpCode > 0
    } // for
    isGetParameters_ = true;
    RpcResult r {"http: ", HTTP_CODE_OK};
    return r; 
  };
    
  private:
    std::string url_;
    std::string key_;
    WiFiClient wifi_;
    bool isGetParameters_;
    //id_counter_;
};

class RpcTask : public Task {
  protected:
    void setup() {
       Serial.println("RPC task init");  
    }

    void loop() {
      if ((WiFi.status() == WL_CONNECTED)) { 
        WiFiClient client;
        Serial.println("RPC task run");
        RobonomicsRpc rpcProvider(client, URLRPC, PRIVKEY);
        RpcResult r = rpcProvider.DatalogRecord(std::to_string(id_counter));
        Serial.printf("[RPC] %ld %s\n", r.code, r.body.c_str());  
        delay(1000);
      }
    }

  private:
    uint8_t state;
} rpcTask;

class MainTask : public Task {
  void setup() {
     Serial.println("init MainTask");
  }
  
 void loop() {
    
  if ((WiFi.status() == WL_CONNECTED)) {

    WiFiClient client;
    HTTPClient http;
    Data data;
                     
    JSONVar params; 
    String jsonString;
    if (isGetParameters) {
        jsonString = getPayloadJs ("5HhFH9GvwCST4kRVoFREE7qDJcjYteR5unhQCrBGhhGuRgNb",id_counter);
    } else {     
        jsonString = fillParamsJs (edata,id_counter);
        edata.clear();
    }
    id_counter++;

    int httpCode = 0 ;
    Serial.printf("[HTTP] to %s\n", URLRPC); 
    http.begin(client, URLRPC); 
    http.addHeader("Content-Type", "application/json");
    // http.addHeader("Accept" , "text/plain");
    Serial.print("[HTTP] POST:\n");
    Serial.println(jsonString);
    
    httpCode = http.POST(jsonString);  // submitExtrinsic
        
    if (httpCode > 0) {
      
      Serial.printf("[HTTP] POST code: %d\n", httpCode);
      // 1st stage: get paramteres to form extrinsic
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
         FromJson fj;
                  
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
         // 2nd stage: create and send extrinsic        
         if (res) {
           if (isGetParameters) {
#ifdef RPC_BALANCE_TX
              Data call = callTransferBalance(head, SS58KEY, ++fee); // call header for Balance transfer
#else
              Data call = callDatalogRecord(head, RECORD_DATA); // call header for Datalog record + some payload
#endif        
              fj = parseJson (val);          
              data = doPayload (call, fj.era, fj.nonce, fj.tip, fj.specVersion, fj.tx_version, fj.ghash, fj.bhash);
              Data signature = doSign (data, privateKey, publicKey);
              std::vector<std::uint8_t> pubKey( reinterpret_cast<std::uint8_t*>(std::begin(publicKey)), reinterpret_cast<std::uint8_t*>(std::end(publicKey)));               
              edata = doEncode (signature, pubKey, fj.era, fj.nonce, fj.tip, call);
                            
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

private:
    uint8_t state;
} mainTask;

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
  // key from mnemonic = "old leopard transfer rib spatial phone calm indicate online fire caution review"
  // derived ss58 by python script "5HhFH9GvwCST4kRVoFREE7qDJcjYteR5unhQCrBGhhGuRgNb"
  std::vector<uint8_t> vk = hex2bytes("da3cf5b1e9144931a0f0db65664aab662673b099415a7f8121b7245fb0be4143");
  std::copy(vk.begin(), vk.end(), privateKey);
  
  Ed25519::derivePublicKey(publicKey, privateKey);  
  //std::vector<uint8_t> pk = hex2bytes("f90bc712b5f2864051353177a9d627605d4bf7ec36c7df568cfdcea9f237c185");
  //std::copy(pk.begin(), pk.end(), publicKey);  

  Scheduler.start(&mainTask);
  Scheduler.start(&rpcTask);
  Scheduler.begin();
}

void loop () {}
