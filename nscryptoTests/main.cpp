//
//  main.cpp
//  nscryptoTests
//
//  Created by Andrey Belenko on 09/03/15.
//  Copyright (c) 2015 NowSecure. All rights reserved.
//

#include "nscrypto.h"

#include <memory>
#include <string>
#include <tuple>

using std::unique_ptr;
using std::string;
using std::tie;

#include <stdlib.h>

#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

static size_t length(0);

int main(int argc, char* const argv[]) {
    int result(0);
    
    auto session = Catch::Session();
    
    for (length = 1; length <= 65535; length += 15) {
        printf("length = %zu\n", length);
        
        result = session.run( argc, argv );
        
        if (result) {
            return result;
        }
    }
    
    return result;
}

static string random_string(size_t length) {
    assert(length > 0);
    
    auto bytes = unique_ptr<uint8_t[]>(new uint8_t[length]);
    arc4random_buf(bytes.get(), length);
    
    return string((const char*)bytes.get(), length);
}

static string flip_random_bit(const string& in) {
    assert(!in.empty());
    const int bits = (int)in.size() * 8;
    const int flip = arc4random_uniform(bits);
    
    string out(in);
    out.at(flip/8) ^= 0x1 << (7 - (flip % 8));
    
    return out;
}

TEST_CASE("nscrypto ecdh", "[nscrypto]") {
    
    keypair_t s(ec_keypair()), r(ec_keypair());
    
    string s_priv, s_pub;
    tie(s_priv, s_pub) = s;
    
    REQUIRE(!s_priv.empty());
    REQUIRE(!s_pub.empty());
    
    string r_priv, r_pub;
    tie(r_priv, r_pub) = r;
    
    REQUIRE(!r_priv.empty());
    REQUIRE(!r_pub.empty());


    SECTION("generated keys are not empty"){
    }
    
    SECTION("generated keys are not equal"){
        REQUIRE(s_priv != r_priv);
        REQUIRE(s_pub != r_pub);
    }
    
    SECTION("encryption and decryption works") {
        
        SECTION("client-to-server") {
            string s_id("sender"), r_id("recipient");
            string msg(random_string(length));
            
            ecdh_encrypted_t encrypted(ecdh_client_encrypt(s_priv, r_pub, s_id, r_id, msg));
            string enc, tag, eph;
            tie(enc, tag, eph) = encrypted;
            
            REQUIRE(!enc.empty());
            REQUIRE(!tag.empty());
            REQUIRE(!eph.empty());
            
            string decrypted(ecdh_server_decrypt(r_priv, s_pub, s_id, r_id, encrypted));
            REQUIRE(!decrypted.empty());
            
            REQUIRE(decrypted == msg);
            
            SECTION("decryption with wrong keys fails") {
                string x_priv, x_pub;
                tie(x_priv, x_pub) = ec_keypair();
                
                REQUIRE(!x_priv.empty());
                REQUIRE(!x_pub.empty());
                
                SECTION("recipient's key") {
                    decrypted = ecdh_server_decrypt(x_priv, s_pub, s_id, r_id, encrypted);
                    REQUIRE(decrypted.empty());
                }
                
                SECTION("sender's key") {
                    decrypted = ecdh_server_decrypt(r_priv, x_pub, s_id, r_id, encrypted);
                    REQUIRE(decrypted.empty());
                }
                
                SECTION("ephemeral key") {
                    decrypted = ecdh_server_decrypt(r_priv, s_pub, s_id, r_id, ecdh_encrypted_t(enc, tag, x_pub));
                    REQUIRE(decrypted.empty());
                }
            }
            
            SECTION("decryption with wrong s_id fails") {
                string x_id(flip_random_bit(s_id));
                decrypted = ecdh_server_decrypt(r_priv, s_pub, x_id, r_id, encrypted);
                REQUIRE(decrypted.empty());
            }
            
            SECTION("decryption with wrong r_id fails") {
                string x_id(flip_random_bit(r_id));
                decrypted = ecdh_server_decrypt(r_priv, s_pub, s_id, x_id, encrypted);
                REQUIRE(decrypted.empty());
            }
            
            SECTION("decryption with ecdh_client_decrypt fails") {
                decrypted = ecdh_client_decrypt(r_priv, s_pub, s_id, r_id, encrypted);
                REQUIRE(decrypted.empty());
            }
            
            SECTION("tampering with encrypted data break decryption") {
                enc = flip_random_bit(enc);
                decrypted = ecdh_server_decrypt(r_priv, s_pub, s_id, r_id, ecdh_encrypted_t(enc, tag, eph));
                REQUIRE(decrypted.empty());
            }
            
            SECTION("tampering with tag breaks decryption") {
                tag = flip_random_bit(tag);
                decrypted = ecdh_server_decrypt(r_priv, s_pub, s_id, r_id, ecdh_encrypted_t(enc, tag, eph));
                REQUIRE(decrypted.empty());
            }
            
            SECTION("tampering with ephemeral key breaks decryption") {
                eph = flip_random_bit(eph);
                decrypted = ecdh_server_decrypt(r_priv, s_pub, s_id, r_id, ecdh_encrypted_t(enc, tag, eph));
                REQUIRE(decrypted.empty());
            }
        }
        
        SECTION("server-to-client") {
            string s_id("sender"), r_id("recipient");
            string msg(random_string(length));
            
            ecdh_encrypted_t encrypted(ecdh_server_encrypt(s_priv, r_pub, s_id, r_id, msg));
            string enc, tag, eph;
            tie(enc, tag, eph) = encrypted;
            
            REQUIRE(!enc.empty());
            REQUIRE(!tag.empty());
            REQUIRE(!eph.empty());
            
            string decrypted(ecdh_client_decrypt(r_priv, s_pub, s_id, r_id, encrypted));
            REQUIRE(!decrypted.empty());
            
            REQUIRE(decrypted == msg);
            
            SECTION("decryption with wrong keys fails") {
                string x_priv, x_pub;
                tie(x_priv, x_pub) = ec_keypair();
                
                REQUIRE(!x_priv.empty());
                REQUIRE(!x_pub.empty());
                
                SECTION("recipient's key") {
                    decrypted = ecdh_client_decrypt(x_priv, s_pub, s_id, r_id, encrypted);
                    REQUIRE(decrypted.empty());
                }
                
                SECTION("sender's key") {
                    decrypted = ecdh_client_decrypt(r_priv, x_pub, s_id, r_id, encrypted);
                    REQUIRE(decrypted.empty());
                }
                
                SECTION("ephemeral key") {
                    decrypted = ecdh_client_decrypt(r_priv, s_pub, s_id, r_id, ecdh_encrypted_t(enc, tag, x_pub));
                    REQUIRE(decrypted.empty());
                }
            }
            
            SECTION("decryption with wrong s_id fails") {
                string x_id(flip_random_bit(s_id));
                decrypted = ecdh_client_decrypt(r_priv, s_pub, x_id, r_id, encrypted);
                REQUIRE(decrypted.empty());
            }
            
            SECTION("decryption with wrong r_id fails") {
                string x_id(flip_random_bit(r_id));
                decrypted = ecdh_client_decrypt(r_priv, s_pub, s_id, x_id, encrypted);
                REQUIRE(decrypted.empty());
            }
            
            SECTION("decryption with ecdh_server_decrypt fails") {
                decrypted = ecdh_server_decrypt(r_priv, s_pub, s_id, r_id, encrypted);
                REQUIRE(decrypted.empty());
            }
            
            SECTION("tampering with encrypted data break decryption") {
                enc = flip_random_bit(enc);
                decrypted = ecdh_client_decrypt(r_priv, s_pub, s_id, r_id, ecdh_encrypted_t(enc, tag, eph));
                REQUIRE(decrypted.empty());
            }
            
            SECTION("tampering with tag breaks decryption") {
                tag = flip_random_bit(tag);
                decrypted = ecdh_client_decrypt(r_priv, s_pub, s_id, r_id, ecdh_encrypted_t(enc, tag, eph));
                REQUIRE(decrypted.empty());
            }
            
            SECTION("tampering with ephemeral key breaks decryption") {
                eph = flip_random_bit(eph);
                decrypted = ecdh_client_decrypt(r_priv, s_pub, s_id, r_id, ecdh_encrypted_t(enc, tag, eph));
                REQUIRE(decrypted.empty());
            }
        }
    }
}

TEST_CASE("ncrypto ecdh interoperability with vp_ecdh", "[nscrypto]") {
    // TODO
}
