#include <vector>
#include <string>
#include <Scheduler.h>

#include <Arduino.h>

#include <RpcRobonomics.h>

#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

#ifndef STASSID
#define STASSID "MY-SSID"
#define STAPSK  "MY-PSK"
#endif

uint64_t id_counter = 0; 

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
    }
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

  Scheduler.start(&mainTask);
  Scheduler.start(&rpcTask);
  Scheduler.begin();
}

void loop () {}
