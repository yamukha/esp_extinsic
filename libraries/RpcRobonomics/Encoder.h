#pragma once

#include "Data.h"

enum TWSS58AddressType {
    TWSS58AddressTypePolkadot = 0,
    TWSS58AddressTypeKusama = 2,
};

static constexpr uint8_t signedBit = 0x80;
static constexpr uint8_t extrinsicFormat = 4;
static constexpr uint8_t sigTypeEd25519 = 0x00;
static constexpr uint32_t multiAddrSpecVersion = 28;
static constexpr uint32_t multiAddrSpecVersionKsm = 2028;
static constexpr TWSS58AddressType network = TWSS58AddressTypeKusama;

static constexpr size_t kMinUint16 = (1ul << 6u);
static constexpr size_t kMinUint32 = (1ul << 14u);
static constexpr size_t kMinBigInteger = (1ul << 30u);
static constexpr uint64_t kMaxBigInteger = (1ul << 31u) * (1ul << 31u);

bool encodeRawAccount(TWSS58AddressType network, uint32_t specVersion) {
    if ((network == TWSS58AddressTypePolkadot && specVersion >= multiAddrSpecVersion) ||
        (network == TWSS58AddressTypeKusama && specVersion >= multiAddrSpecVersionKsm)) {
            return false;
        }
    return true;
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

inline Data encodeAccountId(const Data& bytes, bool raw) {
    auto data = Data{};
    if (!raw) {
        // MultiAddress::AccountId
        // https://github.com/paritytech/substrate/blob/master/primitives/runtime/src/multiaddress.rs#L28
        append(data, 0x00);
        
        //std::string id = "12D3KooWBTxFpuyLJ7MpjxNTogMTa8nSLCQV7BAhQiFSkvuuiM8E";
        //std::vector<uint8_t> vec; 
        //vec.assign(id.begin(), id.end());
        //append(data, vec);
        
       }
    append(data, bytes);
    return data;
}

inline void encodeLengthPrefix(Data& data) {
    size_t len = data.size();
    auto prefix = encodeCompact(len);
    data.insert(data.begin(), prefix.begin(), prefix.end());
}