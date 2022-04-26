#include <vector>
#include <string>
#include <Scheduler.h>

#include <Arduino.h>
#include <Call.h>
#include <Defines.h>
#include <Extrinsic.h>

#include <Ed25519.h>

#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

#ifndef STASSID
//#define STASSID "AirTies_Air4240" 
#define STASSID "FLY-TL-WR741ND"
#define STAPSK  "xxxxxxxxxx"
#endif

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

uint64_t id_counter = 0; 
uint8_t privateKey[32];

typedef struct {
   std::string body;      // responce body
   uint32_t code;         // http responce code 200, 404, 500 etc.
} RpcResult;

class RobonomicsRpc { 
  public:     
    RobonomicsRpc (WiFiClient client, std::string url, std::string key, uint64_t id)
        : wifi_(client), url_(url), key_(key), isGetParameters_ (true), id_counter_(id)
        {  
          Ed25519::derivePublicKey(publicKey_, privateKey);  
          //std::vector<uint8_t> pk = hex2bytes("f90bc712b5f2864051353177a9d627605d4bf7ec36c7df568cfdcea9f237c185");
          //std::copy(pk.begin(), pk.end(), publicKey);  
         };

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
        jsonString = getPayloadJs ("5HhFH9GvwCST4kRVoFREE7qDJcjYteR5unhQCrBGhhGuRgNb",id_counter_);
      } else {
        jsonString = fillParamsJs (edata_,id_counter_);
        edata_.clear();
      }
      Serial.println("sent:");
      Serial.println(jsonString);
      id_counter_++;
    
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
                    Data signature_ = doSign (data_, privateKey, publicKey_);
                    std::vector<std::uint8_t> pubKey( reinterpret_cast<std::uint8_t*>(std::begin(publicKey_)), reinterpret_cast<std::uint8_t*>(std::end(publicKey_)));               
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
    uint8_t publicKey_[32];
    uint64_t id_counter_;
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
        RobonomicsRpc rpcProvider(client, URLRPC, PRIVKEY, id_counter);
        RpcResult r = rpcProvider.DatalogRecord(std::to_string(id_counter)); // id_counter as payload just for example
        id_counter = id_counter + 2;
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

  Scheduler.start(&mainTask);
  Scheduler.start(&rpcTask);
  Scheduler.begin();
}

void loop () {}
