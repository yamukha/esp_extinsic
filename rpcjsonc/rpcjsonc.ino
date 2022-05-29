#include <vector>
#include <string>

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

#include <RpcRobonomics.h>

// ss58 address and related to it ED25519 keypair, can be examined by subkey application or python script
#define PRIV_KEY      "da3cf5b1e9144931a0f0db65664aab662673b099415a7f8121b7245fb0be4143"
#define SS58_ADR       "5HhFH9GvwCST4kRVoFREE7qDJcjYteR5unhQCrBGhhGuRgNb"
#define SS58_DST       "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
#define SS58_DST_KEY   "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"

#ifndef STASSID
#define STASSID "FLY-TL-WR741ND"
#define STAPSK  "xxxxxxxxxx"
#endif

uint64_t id_counter = 0; 
uint64_t coins_count = 0; 

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
        RobonomicsRpc rpcProvider(client, URLRPC, PRIV_KEY, SS58_ADR, id_counter);
        //RpcResult r = rpcProvider.DatalogRecord(std::to_string(id_counter)); // id_counter as payload just for example
        RpcResult r = rpcProvider.TransferBalance(SS58_DST_KEY, coins_count); // coins_count as fee just for example
        coins_count++;
        id_counter = id_counter + 2;
        Serial.printf("[RPC] %ld %s\n", r.code, r.body.c_str());  
        delay(1000);
    }
}
