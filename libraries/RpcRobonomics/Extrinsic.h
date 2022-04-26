#pragma once

#include <vector>
#include <string>
#include  <Arduino_JSON.h>
#include <Ed25519.h>
#include "Encoder.h"
#include "Utils.h"

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
