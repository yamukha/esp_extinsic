#include  "../libraries/RpcRobonomics/Data.h"
#include  "../libraries/RpcRobonomics/Call.h"
#include  "../libraries/RpcRobonomics/Extrinsic.h"
#include  "../libraries/RpcRobonomics/Defines.h"

// git clone https://github.com/weidai11/cryptopp
// cd cryptopp
// make libcryptopp.a libcryptopp.so
// sudo make install PREFIX=/usr/local
// 
// g++ test_call.c -o test_call -DUNIT_TEST -L/usr/local/lib -lcryptopp
// g++ test_call.c -o test_call -DUNIT_TEST -L/usr/local/lib -l:libcryptopp.a

#include "cryptopp/xed25519.h"
#include "cryptopp/osrng.h"

#include <iostream>
#include <cassert>

void printBytes (Data data) {
   for (auto val : data) 
      printf("%.2x", val);
   printf("\n");   
}

void printCharArray (uint8_t data[], uint8_t size) {
  for (int i = 0; i < size; i++) 
      printf(" %.2x", data [i]);
  printf("\n");
}

void compareBytes (Data data, Data pattern) {
  assert(std::equal(std::begin(data), std::end(data), std::begin(pattern)) && "Bytes vector is not equal to expected pattern");
}

void test_callDatalogRecord() {
  auto record = "42";
  Data head = Data{0x33,0};
  Data call = callDatalogRecord(head, record);

  Data callPattern = Data{0x33,0,8,0x34,0x32};
  assert(std::equal(std::begin(call), std::end(call), std::begin(callPattern)) && "Bytes vector is not equal to expected pattern");
}

void test_doPayload() {
    // doPayload (Data, uint32_t, uint64_t, uint64_t, uint32_t, uint32_t, std::string, std::string) 
   auto record = "42";
   Data head = Data {0x33,0};
   Data call = callDatalogRecord(head,record);
   uint32_t era =  0;
   uint64_t nonce = 0;
   uint64_t tip = 0;
   uint32_t specVersion =  0x17;
   uint32_t txVersion = 1;
   std::string ghash = "631ccc82a078481584041656af292834e1ae6daab61d2875b4dd0c14bb9b17bc";
   std::string bhash = "631ccc82a078481584041656af292834e1ae6daab61d2875b4dd0c14bb9b17bc";

   Data data = doPayload (call, era, nonce, tip, specVersion, txVersion, ghash, bhash);

   Data payloadPattern = Data {
        0x33, 0x00, 0x08, 0x34, 0x32, 0x00, 0x00, 0x00, 
        0x17, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x63, 0x1c, 0xcc, 0x82, 0xa0, 0x78, 0x48, 0x15, 
        0x84, 0x04, 0x16, 0x56, 0xaf, 0x29, 0x28, 0x34,
        0xe1, 0xae, 0x6d, 0xaa, 0xb6, 0x1d, 0x28, 0x75, 
        0xb4, 0xdd, 0x0c, 0x14, 0xbb, 0x9b, 0x17, 0xbc,
        0x63, 0x1c, 0xcc, 0x82, 0xa0, 0x78, 0x48, 0x15, 
        0x84, 0x04, 0x16, 0x56, 0xaf, 0x29, 0x28, 0x34,
        0xe1, 0xae, 0x6d, 0xaa, 0xb6, 0x1d, 0x28, 0x75, 
        0xb4, 0xdd, 0x0c, 0x14, 0xbb, 0x9b, 0x17, 0xbc
      };

  assert(std::equal(std::begin(data), std::end(data), std::begin(payloadPattern)) && "Bytes vector is not equal to expected pattern");
}

void test_doSign () {
   //doSign(Data, uint8_t [32], uint8_t [32])

Data data = Data {
        0x33, 0x00, 0x08, 0x34, 0x32, 0x00, 0x00, 0x00, 
        0x17, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x63, 0x1c, 0xcc, 0x82, 0xa0, 0x78, 0x48, 0x15, 
        0x84, 0x04, 0x16, 0x56, 0xaf, 0x29, 0x28, 0x34,
        0xe1, 0xae, 0x6d, 0xaa, 0xb6, 0x1d, 0x28, 0x75, 
        0xb4, 0xdd, 0x0c, 0x14, 0xbb, 0x9b, 0x17, 0xbc,
        0x63, 0x1c, 0xcc, 0x82, 0xa0, 0x78, 0x48, 0x15, 
        0x84, 0x04, 0x16, 0x56, 0xaf, 0x29, 0x28, 0x34,
        0xe1, 0xae, 0x6d, 0xaa, 0xb6, 0x1d, 0x28, 0x75, 
        0xb4, 0xdd, 0x0c, 0x14, 0xbb, 0x9b, 0x17, 0xbc
      };

   uint8_t publicKey[KEYS_SIZE];
   uint8_t privateKey[KEYS_SIZE];
   std::vector<uint8_t> vk = hex2bytes(PRIVKEY);
   std::copy(vk.begin(), vk.end(), privateKey);

   //prepare pubkey
   using namespace CryptoPP;

   ed25519::Signer signer = ed25519Signer (privateKey);
   ed25519::Verifier verifier(signer);

   const ed25519PublicKey& pubKey = dynamic_cast<const ed25519PublicKey&>(verifier.GetPublicKey());
   auto pt = pubKey.GetPublicKeyBytePtr();

   std::memcpy(publicKey, pt, KEYS_SIZE);
  
   Data signature = doSign (data, privateKey, publicKey);

   Data signaturePattern = Data {
    0x68, 0xd4, 0xd0, 0x1a, 0x5d, 0xd9, 0x8e, 0xbc,
    0xa8, 0xa7, 0x93, 0x15, 0x06, 0x93, 0x8b, 0x6f,
    0x7c, 0x79, 0xab, 0x1b, 0x6b, 0x27, 0x03, 0x60,
    0xfb, 0x28, 0x6c, 0xd4, 0x9d, 0x54, 0xce, 0x69, 
    0x1c, 0xeb, 0xf6, 0x07, 0x0f, 0x02, 0x6c, 0xcf,
    0x78, 0xd8, 0x9d, 0xfd, 0xf6, 0x01, 0xef, 0xc8,
    0xf4, 0x90, 0xce, 0xc4, 0x56, 0x0a, 0xfb, 0x9b,
    0xcf, 0x04, 0x35, 0x11, 0xa0, 0x93, 0xa6, 0x0d
  };

  assert(std::equal(std::begin(signature), std::end(signature), std::begin(signaturePattern)) && "Bytes vector is not equal to expected pattern");
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
