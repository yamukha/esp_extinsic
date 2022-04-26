#include <cstdint>
#include <vector>
#include <string>
#include <iterator> 
#include <array>
#include <Scheduler.h>

#include <Arduino.h>
#include  <Arduino_JSON.h>
#include <Data.h>
#include <Utils.h>
#include <Call.h>
#include <Extrinsic.h>
#include <Encoder.h>

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
            
#define GET_PAYLOAD "{ \"jsonrpc\":\"2.0\", \"id\":1, \"method\":\"get_payload\", \"params\": [\"4GiRoiHkwqYdFpNJWrJrzPcRqaNWJayG1Lq5ZgLqoZwrZHjj\"]}"

uint64_t id_counter = 0; 
uint8_t privateKey[32];
uint8_t publicKey[32];

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
     Serial.printf("[MAIN] %ld\n", id_counter++);
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
