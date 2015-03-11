#include "nscrypto_ecdh.h"

#include <functional>
#include <vector>
#include <cassert>

#include <stdint.h>

#include <openssl/ecdh.h>
#include <openssl/evp.h>	// for NID_X9_62_prime256v1
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/asn1t.h>

#ifdef _NSCRYPTO_EXTRA_LOGGING
    #define LogMsg(frmt, ...)   fprintf(stderr, "%s: " frmt "\n", __FUNCTION__, ##__VA_ARGS__)
#else
    #define LogMsg(frmt, ...)   ((void*)0)
#endif //_NSCRYPTO_EXTRA_LOGGING

#define LogTrace()              LogMsg("")
#define LogTrace2(frmt, ...)    LogMsg(frmt, ##__VA_ARGS__)
#define LogError(frmt, ...)     LogMsg("[ERROR] " frmt, ##__VA_ARGS__)
#define LogWarn(frmt, ...)      LogMsg("[WARN] " frmt, ##__VA_ARGS__)
#define LogInfo(frmt, ...)      LogMsg("[INFO] " frmt, ##__VA_ARGS__)
#define LogVerbose(frmt, ...)   LogMsg("[VERBOSE] " frmt, ##__VA_ARGS__)

constexpr auto CurveName(NID_X9_62_prime256v1);

// Size of computed shared secret; can be calculated as follows
// int secret_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
// secret_size = (secret_size + 7) / 8;
constexpr auto ECDHResultSize(32);

// Size of derived secret
// This is how many bytes KDF is expected to produce
constexpr auto KDFResultSize(SHA256_DIGEST_LENGTH);

static auto eckey_deleter = [](EC_KEY* key) {
    if (key != nullptr) {
        EC_KEY_free(key);
    }
};

using ECKEY = std::unique_ptr<EC_KEY, std::function<void(EC_KEY*)>>;

#pragma mark - EC Key Allocation and Generation

/*!
 @functiongroup EC Key Allocation and Generation
 */

/*!
 Allocates and configures a new EC keypair.
 
 @return newly allocated ECKEY
 
 @see ECKEY
 */
static ECKEY ECKEY_new() {
    LogTrace();
    
    ECKEY key(EC_KEY_new_by_curve_name(CurveName), eckey_deleter);
    
    if (!key) {
        LogError("Unable to create EC key for %d", CurveName);
        return key;
    }
    
    EC_KEY_set_conv_form(key.get(), POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(key.get(), OPENSSL_EC_NAMED_CURVE);
    
    return key;
}

/*!
 Generates a new EC keypair.
 
 @return newly generated ECKEY
 
 @see ECKEY
 */
static ECKEY ECKEY_generate() {
    LogTrace();
    
    ECKEY key(ECKEY_new());
    
    if (!key) {
        return key;
    }
    
    if (EC_KEY_generate_key(key.get())) {
        if (EC_KEY_check_key(key.get())) {
            return key;
        } else {
            LogError("Unable to verify EC key");
        }
    } else {
        LogError("Unable to generate EC key");
    }
    
    key.reset(nullptr);
    return key;
}

#pragma mark - EC Key Import and Export
/*!
 @functiongroup EC Key Import and Export
 */

typedef struct ec_priv_key_st {
    ASN1_INTEGER      *i;
    ASN1_OCTET_STRING *x;
} EC_PRIV_KEY;

DECLARE_ASN1_FUNCTIONS(EC_PRIV_KEY)

ASN1_SEQUENCE(EC_PRIV_KEY) = {
    ASN1_SIMPLE(EC_PRIV_KEY, i, ASN1_INTEGER),
    ASN1_SIMPLE(EC_PRIV_KEY, x, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(EC_PRIV_KEY)

IMPLEMENT_ASN1_FUNCTIONS(EC_PRIV_KEY)

static auto ecprivkey_deleter = [](EC_PRIV_KEY* key) {
    if (key != nullptr) {
        EC_PRIV_KEY_free(key);
    }
};

using ECPRIVKEY = std::unique_ptr<EC_PRIV_KEY, std::function<void(EC_PRIV_KEY*)>>;

/*!
 Export private part of the EC key.
 
 @param key Key to export.
 
 @return std::string containing exported private key. In case of error returns
  empty string.
 
 @see ECKEY, ECKEY_import_private
 */
std::string ECKEY_export_private(const ECKEY& key) {
    LogTrace();
    
    if (!key) {
        LogError("key == nullptr");
        return std::string();
    }
    
    ECPRIVKEY pkey = ECPRIVKEY(EC_PRIV_KEY_new(), ecprivkey_deleter);
    
    ASN1_INTEGER_set(pkey->i, 1);
    
    const BIGNUM* x = EC_KEY_get0_private_key(key.get());
    
    auto pBytes = std::unique_ptr<uint8_t[]>(new uint8_t[BN_num_bytes(x)]);
    int cb = BN_bn2bin(x, pBytes.get());
    ASN1_STRING_set(pkey->x, pBytes.get(), cb);
    
    uint8_t* pb = NULL;
    cb = i2d_EC_PRIV_KEY(pkey.get(), &pb);
    
    std::string r((const char*)pb, cb);
    OPENSSL_free(pb);
    
    return r;
}

/*!
 Export public part of the EC key.
 
 @param key Key to export.
 
 @return std::string containing exported public key. In case of error returns
 empty string.
 
 @see ECKEY, ECKEY_import_public
 */
std::string ECKEY_export_public(const ECKEY& key) {
    LogTrace();
    
    if (!key) {
        LogError("key == nullptr");
        return std::string();
    }
    
    uint8_t* pb = NULL;
    int cb = i2o_ECPublicKey(key.get(), &pb);
    
    std::string r((const char*)pb, cb);
    OPENSSL_free(pb);
    
    return r;
}

/*!
 Import private key.
 
 @param data std::string containing exported key
 
 @return ECKEY. If there was an error, (bool)key will evaluate to false.
 
 @see ECKEY, ECKEY_import_private
 */
ECKEY ECKEY_import_private(const std::string& data) {
    LogTrace();
    
    ECKEY key(ECKEY_new());
    if (!key) {
        return key;
    }
    
    if (data.empty()) {
        LogError("Empty input");
        key.reset(nullptr);
        return key;
    }
    
    uint8_t* pb = (uint8_t*)data.data();
    ECPRIVKEY pkey(d2i_EC_PRIV_KEY(NULL, (const uint8_t**) &pb, (int)data.size()), ecprivkey_deleter);
    if (!pkey) {
        LogError("Malformed key, unable to decode");
        key.reset(nullptr);
        return key;
    }
    
    BIGNUM* x = BN_bin2bn(ASN1_STRING_data(pkey->x), ASN1_STRING_length(pkey->x), NULL);
    if (!x) {
        LogError("Malformed key, unable to convert to BIGNUM");
        key.reset(nullptr);
        return key;
    }
    
    // Compute public key
    EC_POINT* pub = EC_POINT_new(EC_KEY_get0_group(key.get()));
    EC_POINT_mul(EC_KEY_get0_group(key.get()), pub, x, NULL, NULL, NULL);
    
    EC_KEY_set_private_key(key.get(), x);
    EC_KEY_set_public_key(key.get(), pub);
    
    BN_free(x);
    EC_POINT_free(pub);
    
    if (!EC_KEY_check_key(key.get())) {
        LogError("Unable to verify imported private key");
        key.reset(nullptr);
        return key;
    }
    
    return key;
};

/*!
 Import public key.
 
 @param data std::string containing exported key
 
 @return ECKEY. If there was an error, (bool)key will evaluate to false.
 
 @see ECKEY, ECKEY_import_private
 */
ECKEY ECKEY_import_public(const std::string& data) {
    LogTrace();
    
    ECKEY key(ECKEY_new());
    if (!key) {
        return key;
    }
    
    if (data.empty()) {
        LogError("Empty input");
        key.reset(nullptr);
        return key;
    }
    
    uint8_t* p = (uint8_t*)data.data();
    EC_KEY* pKey = key.get();
    pKey = o2i_ECPublicKey(&pKey, (const uint8_t**)&p, (int)data.size());
    
    if (!EC_KEY_check_key(key.get())) {
        LogError("Unable to verify imported public key");
        key.reset(nullptr);
        return key;
    }
    
    return key;
};

#pragma mark - ECDH Computations
/*!
 @functiongroup ECDH Computations
 */

static std::string ECDH_compute_secret(const ECKEY& priv, const ECKEY& pub) {
    LogTrace();
    
    uint8_t Z[ECDHResultSize] = { 0 };
    int cb = ECDH_compute_key(Z, ECDHResultSize, EC_KEY_get0_public_key(pub.get()), priv.get(), NULL);
    
    if (cb != ECDHResultSize) {
        return std::string();
    }
    
    return std::string((const char*)Z, ECDHResultSize);
}

static std::string ECDH_derive_key(const std::string& Zs, const std::string& Ze,
                                   const std::vector<std::string>& otherInfo)
{
    LogTrace();
    
    assert(SHA256_DIGEST_LENGTH == KDFResultSize);
    
    if (Zs.empty() || Ze.empty()) {
        return std::string();
    }
    
    SHA256_CTX sha256;
    uint8_t out[SHA256_DIGEST_LENGTH] = { 0 };
    
    unsigned char Counter[4] = { 0x00, 0x00, 0x00, 0x01 };
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, Counter, sizeof(Counter));
    SHA256_Update(&sha256, Zs.data(), Zs.size());
    SHA256_Update(&sha256, Ze.data(), Zs.size());
    
    for (const auto& s : otherInfo) {
        assert(!s.empty());
        SHA256_Update(&sha256, s.data(), s.size());
    }
    
    SHA256_Final(out, &sha256);
    SHA256_Init(&sha256);
    
    return std::string((const char*)out, KDFResultSize);
}

static std::string ECDH_compute_key(const ECKEY& s_priv, const ECKEY& s_pub,            // static keys
                                    const ECKEY& e_priv, const ECKEY& e_pub,            // ephemeral keys
                                    const std::string& sndr_id, const ECKEY& sndr_pub,  // sender id and public key
                                    const std::string& rcpt_id, const ECKEY& rcpt_pub,  // recipient id and public key
                                    const std::string& dv)
{
    LogTrace();
    
    if (!s_priv || !s_pub || !e_priv || !e_pub || !sndr_pub || !rcpt_pub) {
        LogError("nullptr key(s)");
        return std::string();
    }
    
    if (sndr_id.empty() || rcpt_id.empty() || dv.empty()) {
        LogError("empty parameter(s)");
        return std::string();
    }
    
    // 2. Compute static secret, Zs = ECDH_compute_key(s_priv, r_pub)
    std::string Zs(ECDH_compute_secret(s_priv, s_pub));
    
    if(Zs.size() != ECDHResultSize) {
        LogError("Unexpected len of static secret: %d bytes", Zs.size());
        return std::string();
    }
    
    // 3. Compute ephemeral secret, Ze = ECDH_compute_key(e_priv, r_pub)
    std::string Ze(ECDH_compute_secret(e_priv, e_pub));
    
    if(Ze.size() != ECDHResultSize) {
        LogError("Unexpected len of ephemeral secret: %d bytes", Ze.size());
        return std::string();
    }
    
    // 4. Z = Zs || Ze
    // 5. S = KDF (Z, DV || s_id || eph_pub || r_id || r_pub)
    
    const std::vector<std::string> otherInfo {
        dv,
        sndr_id,
        ECKEY_export_public(sndr_pub),
        rcpt_id,
        ECKEY_export_public(rcpt_pub),
    };
    
    for (const auto& s : otherInfo) {
        if (s.empty()) {
            LogError("empty KDF input(s)");
            return std::string();
        }
    }
    
    std::string S(ECDH_derive_key(Zs, Ze, otherInfo));
    
    if (S.size() != KDFResultSize) {
        LogError("Unexpected len of computed secret: %d bytes", S.size());
        return std::string();
    }
    
    return S;
}

#pragma mark - ECDH Key Agreement
/*!
 @functiongroup ECDH Key Agreement
 */

///////////////////////////////////////////////////////////////////////////////
//
// This complies with "viaProtect: Data Protection" specification
// Implements steps 1-5 of Encryption process desribed in
// Data Authentication with Optional Encryption Primitive
//
// Resulting S can be split into key and IV and used for encryption
//
static std::tuple<std::string, ECKEY>
ECDH_sender_new_key(const ECKEY& s_priv, const ECKEY& r_pub,
                    const std::string& s_id, const std::string& r_id,
                    const std::string& dv)
{
    LogTrace();
    
    auto empty = std::tuple<std::string, ECKEY>(std::string(), ECKEY());
    
    if (!s_priv || !r_pub) {
        LogError("nullptr key(s)");
        return empty;
    }
    
    if (s_id.empty() || r_id.empty() || dv.empty()) {
        LogError("empty parameter(s)");
        return empty;
    }
    
    // Generate ephemeral keypair
    ECKEY eph = ECKEY_generate();
    
    if (!eph) {
        LogError("Unable to generate ephemeral keypair");
        return empty;
    }
    
    std::string S(ECDH_compute_key(s_priv, r_pub, eph, r_pub, s_id, eph, r_id, r_pub, dv));
    // Destroy ephemeral private key
    EC_KEY_set_private_key(eph.get(), NULL);
    
    if (S.size() != KDFResultSize) {
        LogError("Unexpected len of computed secret: %d bytes", S.size());
        return empty;
    }
    
    return std::make_tuple(S, std::move(eph));
}

///////////////////////////////////////////////////////////////////////////////
//
// This complies with "viaProtect: Data Protection" specification
// Implements steps 1-5 of Decryption process desribed in
// Data Authentication with Optional Encryption Primitive
//
// Resulting S can be split into key and IV and used for decryption
//
static std::string
ECDH_recipient_get_key(const ECKEY& r_priv, const ECKEY& s_pub, const ECKEY& e_pub,
                       const std::string& s_id, const std::string& r_id,
                       const std::string& dv)
{
    LogTrace();
    
    if (!r_priv || !s_pub || !e_pub) {
        LogError("nullptr key(s)");
        return std::string();
    }
    
    if (s_id.empty() || r_id.empty() || dv.empty()) {
        LogError("empty parameter(s)");
        return std::string();
    }
    
    std::string S(ECDH_compute_key(r_priv, s_pub, r_priv, e_pub, s_id, e_pub, r_id, r_priv, dv));
    if (S.size() != KDFResultSize) {
        LogError("Unexpected len of computed secret: %d bytes", S.size());
        return std::string();
    }
    
    return S;
}

#pragma mark - AES-GCM encryption/decryption
/*!
 @functiongroup AES-GCM encryption/decryption
 */

static std::string _AAD(const std::string& dv, const std::string& s_id, const ECKEY& s_pub, const std::string& r_id, const ECKEY& r_pub) {
    LogTrace();
    
    if (!s_pub || !r_pub) {
        LogError("nullptr key(s)");
        return std::string();
    }
    
    if (dv.empty() || s_id.empty() || r_id.empty()) {
        LogError("empty parameter(s)");
        return std::string();
    }
    
    std::string s_key(ECKEY_export_public(s_pub)), r_key(ECKEY_export_public(r_pub));
    
    if (s_key.empty() || r_key.empty()) {
        LogError("error exporting public keys");
        return std::string();
    }
    
    return dv + s_id + s_key + r_id + r_key;
}


enum class Operation { Encrypt, Decrypt };

template<Operation Op>
static std::tuple<std::string, std::string>
encrypt_aes_gcm(const std::string& data, const std::string& aad, const std::string& tag,
                const std::string& iv, const std::string& key)
{
    LogTrace();
    
    auto r = std::make_tuple(std::string(), std::string());
    
    const EVP_CIPHER* ciph = EVP_aes_128_gcm();
    
    auto ossl_evp_ciph_ctx_deleter = [](EVP_CIPHER_CTX* key) {
        if (key != nullptr) {
            EVP_CIPHER_CTX_cleanup(key);
            EVP_CIPHER_CTX_free(key);
        }
    };
    
    using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(ossl_evp_ciph_ctx_deleter)>;
    CipherCtxPtr evp(EVP_CIPHER_CTX_new(), ossl_evp_ciph_ctx_deleter);
    
    int encrypt = Op == Operation::Encrypt ? 1 : 0;
    
    if (!EVP_CipherInit(evp.get(), ciph, (const uint8_t*)key.data(), (const uint8_t*)iv.data(), encrypt)) {
        LogError("EVP_CipherInit()");
        return r;
    }
    
    if (!EVP_CIPHER_CTX_ctrl(evp.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), NULL)) {
        LogError("EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_IVLEN)");
        return r;
    }
    
    if (Op == Operation::Decrypt) {
        if (!EVP_CIPHER_CTX_ctrl(evp.get(), EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void*)tag.data())) {
            LogError("EVP_CIPHER_CTX_ctrl()");
            return r;
        }
    }
    
    int outl = 0;
    if (!aad.empty()) {
        if (!EVP_CipherUpdate(evp.get(), NULL, &outl, (const uint8_t*)aad.data(), (int)aad.size())) {
            LogError("EVP_CipherUpdate() - 1");
            return r;
        }
    }
    
    outl = 0;
    
    std::unique_ptr<uint8_t[]> pbOut(new uint8_t[data.size()]);
    
    if (!EVP_CipherUpdate(evp.get(), pbOut.get(), &outl, (const uint8_t*)data.data(), (int)data.size())) {
        LogError("EVP_CipherUpdate() - 2");
        return r;
    }
    
    int cbOut = outl;
    
    if (!EVP_CipherFinal(evp.get(), pbOut.get() + outl, &outl)) {
        LogError("EVP_CipherFinal()");
        return r;
    }
    
    cbOut += outl;
    
    std::string output((const char*)pbOut.get(), cbOut);
    
    if (Op == Operation::Encrypt) {
        uint8_t bTag[AES_BLOCK_SIZE] = { 0 };
        
        if (!EVP_CIPHER_CTX_ctrl(evp.get(), EVP_CTRL_GCM_GET_TAG, sizeof(bTag), bTag)) {
            LogError("EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG)");
            return r;
        }
        
        return std::make_tuple(output, std::string((const char*)bTag, sizeof(bTag)));
    }
    
    return std::make_tuple(output, std::string());
}

static std::tuple<std::string, std::string>
_encrypt(const std::string& aad, const std::string& data,
         const std::string& iv, const std::string& key)
{
    LogTrace();
    return encrypt_aes_gcm<Operation::Encrypt>(data, aad, std::string(), iv, key);
}

static std::string
_decrypt(const std::string& aad, const std::string& data, const std::string& tag,
         const std::string& iv, const std::string& key)
{
    LogTrace();
    std::string r;
    std::tie(r, std::ignore) = encrypt_aes_gcm<Operation::Decrypt>(data, aad, tag, iv, key);
    return r;
}

#pragma mark - ECDH Hybrid Encryption
/*!
 @functiongroup ECDH Hybrid Encryption
 */

ecdh_encrypted_t ECDH_encrypt(const std::string& s_priv, const std::string& r_pub,
                              const std::string& s_id, const std::string& r_id,
                              const std::string& dv, const std::string& data)
{
    LogTrace();
    
    const ecdh_encrypted_t empty = ecdh_encrypted_t(std::string(),std::string(),std::string());
    
    if (s_priv.empty() || r_pub.empty()) {
        LogError("empty key(s)");
        return empty;
    }
    
    ECKEY sndr_priv(ECKEY_import_private(s_priv));
    ECKEY rcpt_pub(ECKEY_import_public(r_pub));
    
    if(!sndr_priv || !rcpt_pub) {
        LogError("nullptr key(s)");
        return empty;
    }
    
    std::string s;
    ECKEY eph;
    
    std::tie(s, eph) = ECDH_sender_new_key(sndr_priv, rcpt_pub, s_id, r_id, dv);
    if (s.empty() || s.size() < 24 || !eph) {
        LogError("Cannot create encryption key");
        return empty;
    }
    
    std::string aad(_AAD(dv, s_id, eph, r_id, rcpt_pub));
    if (aad.empty()) {
        LogError("add is empty");
        return empty;
    }
    
    std::string key(s.substr(0, 16)), iv(s.substr(16, 12));
    std::string pub(ECKEY_export_public(eph));
    std::string enc, tag;
    
    std::tie(enc, tag) = _encrypt(aad, data, iv, key);
    if (enc.empty() || tag.empty() || pub.empty()) {
        return empty;
    }
    
    return ecdh_encrypted_t(enc, tag, pub);
}

std::string ECDH_decrypt(const std::string& r_priv, const std::string& s_pub, const std::string& e_pub,
                         const std::string& s_id, const std::string& r_id, const std::string& dv,
                         const std::string& data, const std::string& tag)
{
    LogTrace();
    
    if (r_priv.empty() || s_pub.empty() || e_pub.empty()) {
        LogError("empty key(s)");
        return std::string();
    }
    
    ECKEY rcpt_priv(ECKEY_import_private(r_priv));
    ECKEY sndr_pub(ECKEY_import_public(s_pub));
    ECKEY ephm_pub(ECKEY_import_public(e_pub));
    
    if(!rcpt_priv || !sndr_pub || !ephm_pub) {
        LogError("nullptr key(s)");
        return std::string();
    }
    
    std::string s(ECDH_recipient_get_key(rcpt_priv, sndr_pub, ephm_pub, s_id, r_id, dv));
    if (s.empty() || s.size() < 24) {
        LogError("Cannot compute decryption key");
        return std::string();
    }
    
    std::string aad(_AAD(dv, s_id, ephm_pub, r_id, rcpt_priv));
    if (aad.empty()) {
        LogError("add is empty");
        return std::string();
    }
    
    std::string key(s.substr(0, 16)), iv(s.substr(16, 12));
    return _decrypt(aad, data, tag, iv, key);
}

#pragma mark - Public API
/*!
 @functiongroup Public API
 */

keypair_t ec_keypair() {
    LogTrace();
    
    ECKEY key(ECKEY_generate());
    if (!key) {
        return keypair_t(std::string(), std::string());
    }
    
    std::string priv(ECKEY_export_private(key)), pub(ECKEY_export_public(key));
    
    if (priv.empty() || pub.empty()) {
        return keypair_t(std::string(), std::string());
    }
    
    return keypair_t(priv, pub);
}

ecdh_encrypted_t ecdh_client_encrypt(const std::string& s_priv, const std::string& r_pub,
                                     const std::string& s_id, const std::string& r_id,
                                     const std::string& message)
{
    LogTrace();
    
    (void)s_priv; (void)r_pub;
    (void)s_id; (void)r_id;
    (void)message;
    
    return ECDH_encrypt(s_priv, r_pub, s_id, r_id, std::string("\x00\x00\x00\x01", 4), message);
}

ecdh_encrypted_t ecdh_server_encrypt(const std::string& s_priv, const std::string& r_pub,
                                     const std::string& s_id, const std::string& r_id,
                                     const std::string& message)
{
    LogTrace();
    
    (void)s_priv; (void)r_pub;
    (void)s_id; (void)r_id;
    (void)message;
    
    return ECDH_encrypt(s_priv, r_pub, s_id, r_id, std::string("\x00\x00\x00\x02", 4), message);
}

std::string ecdh_server_decrypt(const std::string& r_priv, const std::string& s_pub,
                                 const std::string& s_id, const std::string& r_id,
                                const ecdh_encrypted_t& encrypted)
{
    LogTrace();
    
    return ECDH_decrypt(r_priv, s_pub,
                        std::get<2>(encrypted),
                        s_id, r_id,
                        std::string("\x00\x00\x00\x01", 4),
                        std::get<0>(encrypted),
                        std::get<1>(encrypted));
    
}

std::string ecdh_client_decrypt(const std::string& r_priv, const std::string& s_pub,
                                 const std::string& s_id, const std::string& r_id,
                                 const ecdh_encrypted_t& encrypted)
{
    LogTrace();
    
    return ECDH_decrypt(r_priv, s_pub,
                        std::get<2>(encrypted),
                        s_id, r_id,
                        std::string("\x00\x00\x00\x02", 4),
                        std::get<0>(encrypted),
                        std::get<1>(encrypted));
}
