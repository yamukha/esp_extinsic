#include <vector>
#include <string>

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

#include <RpcRobonomics.h>

#ifndef STASSID
#define STASSID "FLY-TL-WR741ND"
#define STAPSK  "xxxxxxxxxx"
#endif

uint64_t id_counter = 0; 

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

}

void loop () {
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
