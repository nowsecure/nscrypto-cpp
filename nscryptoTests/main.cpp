//
//  main.cpp
//  nscryptoTests
//
//  Created by Andrey Belenko on 09/03/15.
//  Copyright (c) 2015 NowSecure. All rights reserved.
//

#include "nscrypto.h"
#ifdef __linux__
#include <bsd/stdlib.h>
#endif

#include <memory>
#include <string>
#include <tuple>

using std::unique_ptr;
using std::string;
using std::tie;

#include <stdlib.h>

#include "vp_ecdh.h"

#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

static size_t length(0);

int main(int argc, char* const argv[]) {
    int result(0);
    
    auto session = Catch::Session();
    
    for (length = 1; length <= 65535; length += 15) {
        printf("length = %zu\n", length);
        
        result = session.run(argc, argv);
        
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
    
    string s_priv, s_pub;
    tie(s_priv, s_pub) = ec_keypair();
    
    string r_priv, r_pub;
    tie(r_priv, r_pub) = ec_keypair();
    
    // CHECK: generated keys are not empty
    REQUIRE(!s_priv.empty());
    REQUIRE(!s_pub.empty());
    REQUIRE(!r_priv.empty());
    REQUIRE(!r_pub.empty());
    
    // CHECK: generated keys are not equal
    REQUIRE(s_priv != r_priv);
    REQUIRE(s_pub != r_pub);
    
    string s_id("sender"), r_id("recipient");
    string msg(random_string(length));
    
    REQUIRE(msg.size() == length);
    
    SECTION("client-to-server encryption and decryption works") {
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
    
    SECTION("server-to-client encryption and decryption works") {
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
    
    SECTION("interoperability with vp_ecdh maintained") {
        
        EC_KEY* vp_s_priv = VP_EC_KEY_import_private(s_priv);
        EC_KEY* vp_s_pub = VP_EC_KEY_import_public(s_pub);
        
        EC_KEY* vp_r_priv = VP_EC_KEY_import_private(r_priv);
        EC_KEY* vp_r_pub = VP_EC_KEY_import_public(r_pub);
        
        // CHECK: keys were imported successfully
        REQUIRE(vp_s_priv != NULL);
        REQUIRE(vp_s_pub != NULL);
        REQUIRE(vp_r_priv != NULL);
        REQUIRE(vp_r_pub != NULL);
        
        // CHECK: keys can be successfully exported
        REQUIRE(VP_EC_KEY_export_private(vp_s_priv) == s_priv);
        REQUIRE(VP_EC_KEY_export_private(vp_r_priv) == r_priv);
        REQUIRE(VP_EC_KEY_export_public(vp_s_pub) == s_pub);
        REQUIRE(VP_EC_KEY_export_public(vp_r_pub) == r_pub);
        
        SECTION("old code can decrypt data encrypted with new code") {
            SECTION("client-to-server") {
                ecdh_encrypted_t encrypted(ecdh_client_encrypt(s_priv, r_pub, s_id, r_id, msg));
                string enc, tag, eph;
                tie(enc, tag, eph) = encrypted;
                
                REQUIRE(!enc.empty());
                REQUIRE(!tag.empty());
                REQUIRE(!eph.empty());
                
                EC_KEY* vp_eph = VP_EC_KEY_import_public(eph);
                REQUIRE(vp_eph != NULL);
                REQUIRE(VP_EC_KEY_export_public(vp_eph) == eph);
                
                string decrypted(VP_ECDH_decrypt(vp_r_priv, vp_s_pub, vp_eph, s_id, r_id, string("\x00\x00\x00\x01", 4), enc, tag));
                
                REQUIRE(!decrypted.empty());
                REQUIRE(decrypted == msg);
                
                EC_KEY_free(vp_eph);
            }
            
            SECTION("server-to-client") {
                ecdh_encrypted_t encrypted(ecdh_server_encrypt(s_priv, r_pub, s_id, r_id, msg));
                string enc, tag, eph;
                tie(enc, tag, eph) = encrypted;
                
                REQUIRE(!enc.empty());
                REQUIRE(!tag.empty());
                REQUIRE(!eph.empty());
                
                EC_KEY* vp_eph = VP_EC_KEY_import_public(eph);
                REQUIRE(vp_eph != NULL);
                REQUIRE(VP_EC_KEY_export_public(vp_eph) == eph);
                
                //string decrypted(ecdh_client_decrypt(r_priv, s_pub, s_id, r_id, encrypted));
                string decrypted(VP_ECDH_decrypt(vp_r_priv, vp_s_pub, vp_eph, s_id, r_id, string("\x00\x00\x00\x02", 4), enc, tag));
                
                REQUIRE(!decrypted.empty());
                REQUIRE(decrypted == msg);
                
                EC_KEY_free(vp_eph);
            }
        }
        
        SECTION("new code can decrypt data encrypted with old code") {
            SECTION("client-to-server") {
                EC_KEY* vp_eph = NULL;
                string tag, enc(VP_ECDH_encrypt(vp_s_priv, vp_r_pub, s_id, r_id, string("\x00\x00\x00\x01", 4), msg, &vp_eph, &tag));
                
                REQUIRE(vp_eph != NULL);
                REQUIRE(!tag.empty());
                REQUIRE(!enc.empty());
                
                string eph(VP_EC_KEY_export_public(vp_eph));
                REQUIRE(!eph.empty());
                
                string decrypted(ecdh_server_decrypt(r_priv, s_pub, s_id, r_id, ecdh_encrypted_t{enc,tag,eph}));
                REQUIRE(!decrypted.empty());
                REQUIRE(decrypted == msg);
                
                EC_KEY_free(vp_eph);
            }
            
            SECTION("server-to-client") {
                EC_KEY* vp_eph = NULL;
                string tag, enc(VP_ECDH_encrypt(vp_s_priv, vp_r_pub, s_id, r_id, string("\x00\x00\x00\x02", 4), msg, &vp_eph, &tag));
                
                REQUIRE(vp_eph != NULL);
                REQUIRE(!tag.empty());
                REQUIRE(!enc.empty());
                
                string eph(VP_EC_KEY_export_public(vp_eph));
                REQUIRE(!eph.empty());
                
                string decrypted(ecdh_client_decrypt(r_priv, s_pub, s_id, r_id, ecdh_encrypted_t {enc, tag, eph}));
                REQUIRE(!decrypted.empty());
                REQUIRE(decrypted == msg);
                
                EC_KEY_free(vp_eph);
            }
        }
        
        EC_KEY_free(vp_s_priv);
        EC_KEY_free(vp_s_pub);
        EC_KEY_free(vp_r_priv);
        EC_KEY_free(vp_r_pub);
    }
}
