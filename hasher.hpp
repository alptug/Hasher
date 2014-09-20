//
//  hasher.h
//  hasher
//
//  Created by Alptuğ Ulugöl on 13/09/14.
//  Copyright (c) 2014 KAL IEEE. All rights reserved.
//
// SHA-1, SHA-2 (SHA-224, SHA-256, SHA-384, and SHA-512), SHA-3, Tiger, WHIRLPOOL,
// RIPEMD-128, RIPEMD-256, RIPEMD-160, RIPEMD-320
// MD2, MD4, MD5, Panama Hash, DES, ARC4, SEAL 3.0, WAKE-OFB, DESX (DES-XEX3), RC2, SAFER, 3-WAY,
//GOST, SHARK, CAST-128, Square



#ifndef __hasher__hasher__
#define __hasher__hasher__

#include <iostream>
#include <string>
#include <array>
#include <vector>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/tiger.h>
#include <cryptopp/whrlpool.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/md2.h>
#include <cryptopp/md4.h>
#include <cryptopp/md5.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

class hasher
{
    std::string source;
    
    std::string SHA1_str, SHA224_str, SHA256_str, SHA384_str, SHA512_str, SHA3_224_str, SHA3_256_str, SHA3_384_str, SHA3_512_str, Tiger_str, WHIRLPOOL_str, RIPEMD128_str, RIPEMD256_str, RIPEMD160_str, RIPEMD320_str, MD2_str, MD4_str, MD5_str;
    
    void SHA1();
    void SHA224();
    void SHA256();
    void SHA384();
    void SHA512();
    void SHA3_224();
    void SHA3_256();
    void SHA3_384();
    void SHA3_512();
    void Tiger();
    void WHIRLPOOL();
    void RIPEMD128();
    void RIPEMD256();
    void RIPEMD160();
    void RIPEMD320();
    void MD2();
    void MD4();
    void MD5();
    
    
public:
    hasher(std::string);
    ~hasher();
    
    std::string get_SHA1();
    std::string get_SHA224();
    std::string get_SHA256();
    std::string get_SHA384();
    std::string get_SHA512();
    std::string get_SHA3_224();
    std::string get_SHA3_256();
    std::string get_SHA3_384();
    std::string get_SHA3_512();
    std::string get_Tiger();
    std::string get_WHIRLPOOL();
    std::string get_RIPEMD128();
    std::string get_RIPEMD256();
    std::string get_RIPEMD160();
    std::string get_RIPEMD320();
    std::string get_MD2();
    std::string get_MD4();
    std::string get_MD5();
    
    boost::property_tree::ptree xml_node();
};
#endif /* defined(__hasher__hasher__) */
