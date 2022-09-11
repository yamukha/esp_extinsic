#include  "../libraries/RpcRobonomics/Data.h"
#include  "../libraries/RpcRobonomics/Call.h"
#include  "../libraries/RpcRobonomics/Extrinsic.h"
#include  "../libraries/RpcRobonomics/Defines.h"

void test_callDatalogRecord() {
  auto record = "42";
  Data head = Data{0x33,0};
  Data call = callDatalogRecord(head, record);
}

void test_doPayload() {
    // doPayload (Data, uint32_t, uint64_t, uint64_t, uint32_t, uint32_t, std::string, std::string) 
   auto record = "42";
   Data head = Data {0x33,0};
   Data call = callDatalogRecord(head,record);
   uint32_t era =  0;
   uint64_t nonce = 0;
   uint64_t tip = 0;
   uint32_t specVersion =  0;
   uint32_t txVersion = 0;
   std::string ghash = "0x00" ;
   std::string bhash = "0x00";
   Data data = doPayload (call, era, nonce, tip, specVersion, txVersion, ghash, bhash);
}

void test_doSign () {
   //doSign(Data, uint8_t [32], uint8_t [32])
   Data data = Data {0x33,0};
   uint8_t publicKey[32];
   uint8_t privateKey[32];
   std::vector<uint8_t> vk = hex2bytes(PRIVKEY);
   std::copy(vk.begin(), vk.end(), privateKey);
   //TODO: prepare pubkey
   Data signature = doSign (data, privateKey, publicKey);

}
void  test_doEncode() {
    //doEncode (Data, Data, uint32_t, uint64_t, uint64_t, Data)
    Data signature = Data {0x33,0};
    uint8_t publicKey[32];
    std::vector<uint8_t> pubKey = hex2bytes(PRIVKEY);
    uint32_t era = 0;
    uint64_t  nonce = 0;
    uint64_t tip = 0;
    Data call = {0x33,0};
    Data edata = doEncode (signature, pubKey, era, nonce, tip, call);
}

int main () {
  test_callDatalogRecord();
  test_doPayload();
  test_doSign();
  test_doEncode();
}
