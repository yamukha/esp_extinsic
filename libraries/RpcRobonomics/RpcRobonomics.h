#pragma once 

#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

#include "Call.h"
//#include <Defines.h>
#include <Extrinsic.h>
#include <Call.h>

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
typedef struct {
   std::string body;      // responce body
   uint32_t code;         // http responce code 200, 404, 500 etc.
} RpcResult;

class RobonomicsRpc { 
  public:     
    RobonomicsRpc (WiFiClient client, std::string url, std::string key, uint64_t id)
        : wifi_(client), url_(url), key_(key), isGetParameters_ (true), id_counter_(id)
        {  
          std::vector<uint8_t> vk = hex2bytes("da3cf5b1e9144931a0f0db65664aab662673b099415a7f8121b7245fb0be4143");
          std::copy(vk.begin(), vk.end(), privateKey_);
  
          Ed25519::derivePublicKey(publicKey_, privateKey_);  
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
                    Data signature_ = doSign (data_, privateKey_, publicKey_);
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
    uint8_t privateKey_[32];
    uint64_t id_counter_;
};
