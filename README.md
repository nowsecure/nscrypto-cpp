# nscrypto-cpp

A C++11 library providing simple API for public-key encryption

# Description  

`nscrypto-cpp` is a C++ libary implementing a simple API for encrypting and decrypting data using [hybrid encryption](http://en.wikipedia.org/wiki/Hybrid_cryptosystem). It usese [elliptic-curve Diffie-Hellman](http://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman) for key agreement and [AES](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard)-[GCM](http://en.wikipedia.org/wiki/Galois/Counter_Mode) for data encryption and authentication.   

Library implements C(1e, 2s) scheme from [NIST SP 800-56A](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf) (see section 6.2.1). It uses NIST P-256 curve (a.k.a. secp256r1, a.k.a X9.62 prime256v1) and [SHA-256](http://en.wikipedia.org/wiki/SHA-2) for ECDH key agreement and AES-128 in GCM mode for data encryption.  

Library is currently built on top of [OpenSSL](https://www.openssl.org/) but support for additional backends is planned.

# Usage Example  

```c++
#include "nscrypto.h"

void alice_encrypt() {
    std::string bob_public;     // contains Bob's public key

    // Message Alice want to send
    std::string message("attack at dawn");

    // Generate keys
    std::string alice_private, alice_public;
    std::tie(alice_private, alice_private) = ec_keypair();

    // Encrypt
    ecdh_encrypted_t encrypted(ecdh_client_encrypt(alice_private, bob_public, "Alice", "Bob", message));

    // Send encrypted to Bob
    // . . .
}

void bob_decrypt() {
    std::string alice_public;   // contains Alice's public key
    std::string bob_private;    // contains Bob's private key

    // Receive encrypted from Alice
    // . . .
    
    std::string decrypted(ecdh_server_decrypt(bob_private, alice_public, "Alice", "Bob", encrypted));
    if (decrypted.empty()) {
        // Decryption or integrity check failed
        return;
    }

    // . . .
}

```

# API

## Key Generation

```c++
using keypair_t = std::tuple<std::string, std::string>;
keypair_t ec_keypair();
```

#### Description

Generates new EC keypair. 

#### Return Values

Returns `keypair_t` (a tuple (private_key, public_key). If there was a problem while generating keys returns a tuple with empty strings.

## Encryption and Decryption

```c++
using ecdh_encrypted_t = std::tuple<std::string, std::string, std::string>;

ecdh_encrypted_t ecdh_client_encrypt(const std::string& s_priv, const std::string& r_pub,
                                     const std::string& s_id, const std::string& r_id,
                                     const std::string& message);

ecdh_encrypted_t ecdh_server_encrypt(const std::string& s_priv, const std::string& r_pub,
                                     const std::string& s_id, const std::string& r_id,
                                     const std::string& message);

std::string ecdh_server_decrypt(const std::string& r_priv, const std::string& s_pub,
                                const std::string& s_id, const std::string& r_id,
                                const ecdh_encrypted_t& encrypted);

std::string ecdh_client_decrypt(const std::string& r_priv, const std::string& s_pub,
                                const std::string& s_id, const std::string& r_id,
                                const ecdh_encrypted_t& encrypted);
```
#### Description

`ecdh_client_encrypt` and `ecdh_server_encrypt` encrypt supplied message. Internally they generate an ephemeral EC key and use ECDH to compute encryption key that is then used to encrypt and authenticate data using AES-128 in GCM mode.  

`ecdh_server_decrypt` and `ecdh_client_decrypt` perform reverse operations and decrypt supplied message.

Messages encrypted with `ecdh_client_encrypt` can be decrypted with `ecdh_server_decrypt`. Messages encrypted with `ecdh_server_encrypt` can be decrypted with `ecdh_client_decrypt`. Using functions in other combinations will result in decryption errors. This is by design.

Parameters:  

 - `s_priv`, `s_pub`  – sender's private and public keys.  
 - `r_priv`, `r_pub` – recipient's private and public keys.  
 - `s_id`, `r_id` – sender's and recipient's identifiers. This can be any string but same values must be passed for decryption as were passed for encryption.  

#### Return Values

`ecdh_client_encrypt` and `ecdh_server_encrypt` return `ecdh_encrypted_t` (a tuple containing encrypted message (ciphertext), authentication tag (used to ensure that message was not altered in transit) and public ephemeral key that is used in ECDH key agreement. If there was a problem during encryption then tuple containing empty strings is returned.

`ecdh_server_decrypt` and `ecdh_client_decrypt` return `std::string` containing decrypted data. If there was a problem during decryption (for example because function is unable to authenticate data or sender) then empty string is returned.  


# Build

Please use supplied Xcode project to build library. Keep in mind that when linking with `libnscrypto` you also need to link with `lcrypto` (OpenSSL).  
