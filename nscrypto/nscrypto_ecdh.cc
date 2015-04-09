#include "nscrypto_ecdh.h"

#include <cassert>
#include <functional>
#include <memory>
#include <vector>

#include <stdint.h>

#if defined(USE_LIBCRYPTO)
    #include <openssl/ecdh.h>
    #include <openssl/evp.h>	// for NID_X9_62_prime256v1
    #include <openssl/sha.h>
    #include <openssl/aes.h>
    #include <openssl/asn1t.h>
#elif defined(USE_MBEDTLS)
    #include <algorithm>
    #include <mutex>
    #include <polarssl/entropy.h>
    #include <polarssl/ecdh.h>
    #include <polarssl/sha256.h>
    #include <polarssl/gcm.h>
    #include <polarssl/asn1.h>
    #include <polarssl/asn1write.h>
    #include <polarssl/bignum.h>
#else
    #error Underlying library not specified
    #error Please define USE_LIBCRYPTO for OpenSSL or USE_MBEDTLS for mbed TLS
#endif

#if defined(USE_LIBCRYPTO)
    constexpr auto CurveName(NID_X9_62_prime256v1);
#elif defined(USE_MBEDTLS)
    constexpr auto CurveName(POLARSSL_ECP_DP_SECP256R1);
#endif

// Size of computed shared secret; can be calculated as follows
// int secret_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
// secret_size = (secret_size + 7) / 8;
constexpr auto ECDHResultSize(32);

// Size of AES block
constexpr auto AesBlockSize(16);

// Size of SHA-256 digest
constexpr auto Sha256DigestSize(32);

// Size of derived secret
// This is how many bytes KDF is expected to produce
constexpr auto KDFResultSize(Sha256DigestSize);

#ifdef _NSCRYPTO_LOGGING
    #define LogMsg(frmt, ...)   fprintf(stderr, "%s: " frmt "\n", __FUNCTION__, ##__VA_ARGS__)
#else
    #define LogMsg(frmt, ...)
#endif //_NSCRYPTO_EXTRA_LOGGING

#ifdef _NSCRYPTO_TRACE
    #define LogTrace()              LogMsg("")
    #define LogTrace2(frmt, ...)    LogMsg(frmt, ##__VA_ARGS__)
#else
    #define LogTrace()
    #define LogTrace2(frmt, ...)
#endif //_NSCRYPTO_TRACE

#define LogError(frmt, ...)     LogMsg("[ERROR] " frmt, ##__VA_ARGS__)
#define LogWarn(frmt, ...)      LogMsg("[WARN] " frmt, ##__VA_ARGS__)
#define LogInfo(frmt, ...)      LogMsg("[INFO] " frmt, ##__VA_ARGS__)
#define LogVerbose(frmt, ...)   LogMsg("[VERBOSE] " frmt, ##__VA_ARGS__)

#if defined(USE_LIBCRYPTO)
    using ECKEY = std::unique_ptr<EC_KEY, std::function<void(EC_KEY*)>>;
#elif defined(USE_MBEDTLS)
    using ECKEY = std::unique_ptr<ecp_keypair, std::function<void(ecp_keypair*)>>;
#endif

#pragma mark - Auxiliary backend-specific functions

#if defined(USE_MBEDTLS)

/*
 Random Number Generator
 */
#if defined(__APPLE__)
#include <Security/Security.h>
static int f_rng(__unused void* p_rng, unsigned char* bytes, size_t count) {
    if (0 == SecRandomCopyBytes(kSecRandomDefault, count, bytes)) {
        return 0;
    }
    
    return POLARSSL_ERR_ENTROPY_SOURCE_FAILED;
}
#elif defined(__linux__)
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
static int f_rng(void* p_rng, unsigned char* bytes, size_t count) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t cb = read(fd, bytes, count);
        close(fd);
        return ((ssize_t)count == cb) ? 0 : POLARSSL_ERR_ENTROPY_SOURCE_FAILED;
    }

    return POLARSSL_ERR_ENTROPY_SOURCE_FAILED;
}
#else
#error No RNG function defined for current platform
#endif // __APPLE__

/*
 Bignum -> std::string serialization
 */
static std::string mpi_get_string(const mpi *X, size_t size = 0) {
    LogTrace();
    
    if (!X) {
        LogError("X == nullptr");
        return std::string();
    }
    
    auto len = std::max(mpi_size(X), size);
    auto bytes = std::unique_ptr<uint8_t[]>(new uint8_t[len]);
    
    if (0 == mpi_write_binary(X, bytes.get(), len)) {
        return std::string((const char*)bytes.get(), len);
    }
    
    return std::string();
}

/*
 Helper type to manage mpi creation and cleaning on scope exit
 */

struct scoped_mpi : public mpi {
    scoped_mpi() {
        mpi_init(this);
    }
    
    scoped_mpi(const scoped_mpi&) = delete;
    
    ~scoped_mpi() {
        mpi_free(this);
    }
};

static ECKEY ECKEY_new();

/*
 NIST P-256 modular square root
 Return X such that A = X^2 mod P
 Special case for NIST P-256 curve, for which P mod 4 == 3
 */

static int mpi_mod_sqrt_p256(mpi* X, const mpi* A) {
    LogTrace();
    
    int ret(0);
    
    if (0 == mpi_cmp_int(A, 0)) {
        return POLARSSL_ERR_MPI_NOT_ACCEPTABLE;
    }
    
    if (0 == mpi_cmp_int(A, 1)) {
        return POLARSSL_ERR_MPI_NOT_ACCEPTABLE;
    }
    
    static scoped_mpi r, P;
    static std::once_flag _once;
    
    // Pre-compute exponent (r) for computing square roots
    std::call_once(_once, [&](void){
        ECKEY key(ECKEY_new());
        
        do {
            if ((ret = mpi_copy(&P, &key->grp.P)) != 0) {
                break;
            }
            
            if ((ret = mpi_copy(&r, &key->grp.P)) != 0) {
                break;
            }
            
            if ((ret = mpi_shift_r(&r, 2)) != 0) {
                break;
            }
            
            if ((ret = mpi_add_int(&r, &r, 1)) != 0) {
                break;
            }
        } while(0);
    });
    
    if (ret != 0) {
        LogError("Unable to pre-compute r");
        return ret;
    }
    
    if ((ret = mpi_exp_mod(X, A, &r, &P, nullptr)) != 0) {
        LogError("Unable to compute modexp");
        return ret;
    }
    
    // Verify
    do {
        scoped_mpi t;
        
        if ((ret = mpi_mul_mpi(&t, X, X)) != 0) {
            break;
        }
        
        if ((ret = mpi_mod_mpi(&t, &t, &P)) != 0) {
            break;
        }
        
        const bool _1 = mpi_cmp_mpi(&t, A) == 0;
        
        if ((ret = mpi_sub_mpi(&t, &P, &t)) != 0) {
            break;
        }
        
        const bool _2 = mpi_cmp_mpi(&t, A) == 0;
        
        if (!_1 && !_2) {
            return POLARSSL_ERR_MPI_NOT_ACCEPTABLE;
        }
    } while(0);
    
    return ret;
}

/*
 NIST P-256 point decompression
 Routine 2.2.4 from https://www.nsa.gov/ia/_files/nist-routines.pdf
 */

static int ecp_point_read_binary_ex(const ecp_group *grp, ecp_point *pt, const unsigned char *buf, size_t ilen) {
    LogTrace();
    
    if (buf[0] != 0x02 && buf[0] != 0x03) {
        return ecp_point_read_binary(grp, pt, buf, ilen);
    }
    
    auto plen = mpi_size(&grp->P);
    if (ilen != 1 + plen) {
        return POLARSSL_ERR_ECP_BAD_INPUT_DATA;
    }
    
    int ret(0);
    if ((ret = mpi_read_binary(&pt->X, buf + 1, plen)) != 0) {
        LogError("Unable to read mpi");
        return ret;
    }
    
    const int y_bit = buf[0] & 0x1;
    
    do {
        scoped_mpi t0, t1, t2;
        
        // t0 <- x^3 - 3x + b
        // t1 <- sqrt(t0)
    
        if ((ret = mpi_mul_mpi(&t0, &pt->X, &pt->X)) != 0) {
            break;
        }
        
        // t1 <- x^2 mod p
        if ((ret = mpi_mod_mpi(&t1, &t0, &grp->P)) != 0) {
            break;
        }
        
        if ((ret = mpi_mul_mpi(&t0, &t1, &pt->X)) != 0) {
            break;
        }
        
        // t1 <- x^3 mod p
        if ((ret = mpi_mod_mpi(&t1, &t0, &grp->P)) != 0) {
            break;
        }
        
        // t0 <- 2*x
        if ((ret = mpi_add_mpi(&t0, &pt->X, &pt->X)) != 0) {
            break;
        }
        
        // t0 <- 3*x
        if ((ret = mpi_add_mpi(&t0, &t0, &pt->X)) != 0) {
            break;
        }
        
        // t1 <- x^3 - 3*x
        if ((ret = mpi_sub_mpi(&t1, &t1, &t0)) != 0) {
            break;
        }
        
        // t0 <- x^3 - 3*x + b
        if ((ret = mpi_add_mpi(&t0, &t1, &grp->B)) != 0) {
            break;
        }
        
        if ((ret = mpi_mod_mpi(&t0, &t0, &grp->P)) != 0) {
            break;
        }
        
        // Y <- sqrt(t0)
        if ((ret = mpi_mod_sqrt_p256(&pt->Y, &t0)) != 0) {
            break;
        }
        
        if ((ret = mpi_lset(&pt->Z, 1)) != 0) {
            break;
        }
    } while(0);
    
    if (ret != 0) {
        LogError("Unable compute sqrt");
        return ret;
    }
    
    if (mpi_get_bit(&pt->Y, 0) != y_bit) {
        mpi_sub_mpi(&pt->Y, &grp->P, &pt->Y);
    }
    
    return 0;
}

#endif // USE_MBEDTLS

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

#if defined(USE_LIBCRYPTO)
    static auto eckey_deleter = [](EC_KEY* key) {
        if (key != nullptr) {
            EC_KEY_free(key);
        }
    };
    
    ECKEY key(EC_KEY_new_by_curve_name(CurveName), eckey_deleter);
    
    if (!key) {
        LogError("Unable to create EC key for %d", CurveName);
        return key;
    }
    
    EC_KEY_set_conv_form(key.get(), POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(key.get(), OPENSSL_EC_NAMED_CURVE);
#elif defined(USE_MBEDTLS)
    static auto ecp_keypair_deleter = [](ecp_keypair* key) {
        if (key != nullptr) {
            ecp_keypair_free(key);
            delete key;
        }
    };
    
    ECKEY key(new ecp_keypair, ecp_keypair_deleter);
    ecp_keypair_init(key.get());
    if (0 != ecp_use_known_dp(&key->grp, CurveName)) {
        LogError("Unable to set well-known group %d for EC key", CurveName);
        key.reset(nullptr);
    }
#endif
    
    return key;
}

/*!
 Generates a new EC keypair.
 
 @return newly generated ECKEY
 
 @see ECKEY
 */
static ECKEY ECKEY_generate() {
    LogTrace();
    
#if defined(USE_LIBCRYPTO)
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
#elif defined(USE_MBEDTLS)
    ECKEY key(ECKEY_new());
    
    if (0 == ecp_gen_keypair(&key->grp, &key->d, &key->Q, f_rng, nullptr)) {
        if (0 == ecp_check_pubkey(&key->grp, &key->Q) && 0 == ecp_check_privkey(&key->grp, &key->d)) {
            return key;
        } else {
            LogError("Unable to verify EC key");
        }
    } else {
        LogError("Unable to generate EC key");
    }
#endif

    return key;
}

#pragma mark - EC Key Import and Export

/*!
 @functiongroup EC Key Import and Export
 */

#if defined(USE_LIBCRYPTO)
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

using ECPRIVKEY = std::unique_ptr<EC_PRIV_KEY, std::function<void(EC_PRIV_KEY*)>>;

static auto ecprivkey_deleter = [](EC_PRIV_KEY* key) {
    if (key != nullptr) {
        EC_PRIV_KEY_free(key);
    }
};
#endif

/*!
 Export private part of the EC key.
 
 @param key Key to export.
 
 @return std::string containing exported private key. In case of error returns
 empty string.
 
 @see ECKEY, ECKEY_import_private
 */

std::string ECKEY_export_private(const ECKEY& key) {
    LogTrace();

#if defined(USE_LIBCRYPTO)
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
#elif defined(USE_MBEDTLS)
    auto d = mpi_get_string(&key->d);
    constexpr int buffer_size = 64;
    auto start = std::unique_ptr<uint8_t[]>(new uint8_t[buffer_size]);
    auto p = start.get() + buffer_size;
    
    size_t len(0);
    int ret;
    
    do {
        ret = asn1_write_octet_string(&p, start.get(), (const uint8_t*)d.data(), d.size());
        if (ret < 0) break;
        len += ret;
        
        ret = asn1_write_int(&p, start.get(), 1);
        if (ret < 0) break;
        len += ret;
        
        ret = asn1_write_len(&p, start.get(), len);
        if (ret < 0) break;
        len += ret;
        
        ret = asn1_write_tag(&p, start.get(), ASN1_CONSTRUCTED | ASN1_SEQUENCE);
        if (ret < 0) break;
        len += ret;
    } while(0);
    
    if (ret < 0) {
        LogError("Error serializing private key as ASN.1");
        return std::string();
    }
    
    std::string r((const char*)p, len);
#endif

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

#if defined(USE_LIBCRYPTO)
    if (!key) {
        LogError("key == nullptr");
        return std::string();
    }
    
    uint8_t* pb = NULL;
    int cb = i2o_ECPublicKey(key.get(), &pb);
    
    std::string r((const char*)pb, cb);
    OPENSSL_free(pb);
#elif defined(USE_MBEDTLS)
    constexpr int buffer_size = 64;
    auto buffer = std::unique_ptr<uint8_t[]>(new uint8_t[buffer_size]);
    size_t len(0);
    
    int ret = ecp_point_write_binary(&key->grp, &key->Q, POLARSSL_ECP_PF_COMPRESSED, &len, buffer.get(), buffer_size);
    if (ret != 0) {
        LogError("Cannot serialize point");
        return std::string();
    }
    
    std::string r((const char*)buffer.get(), len);
#endif

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

#if defined(USE_LIBCRYPTO)
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
#elif defined(USE_MBEDTLS)
    ECKEY key(ECKEY_new());
    uint8_t *p = (uint8_t*)data.data();
    const uint8_t* end = (const uint8_t*)data.data() + data.size();
    
    size_t len(0);
    int ret(0);
    int i = 0;
    
    do {
        if ((ret = asn1_get_tag(&p, end, &len, ASN1_CONSTRUCTED | ASN1_SEQUENCE)) != 0) {
            break;
        }
        
        if ((ret = asn1_get_int(&p, end, &i)) != 0) {
            break;
        }
        
        if ((ret = asn1_get_tag(&p, end, &len, ASN1_OCTET_STRING)) != 0) {
            break;
        }
        
        if ((ret = mpi_read_binary(&key->d, p, len)) != 0) {
            break;
        }
        
        // Compute public key from private
        if ((ret = ecp_mul(&key->grp, &key->Q, &key->d, &key->grp.G, f_rng, nullptr)) != 0) {
            break;
        }
        
        if ((ret = ecp_check_privkey(&key->grp, &key->d)) != 0) {
            LogError("Unable to verify imported private key (private part)");
            break;
        }
        
        if ((ret = ecp_check_pubkey(&key->grp, &key->Q)) != 0) {
            LogError("Unable to verify imported private key (public part)");
            break;
        }
    } while(0);
    
    if (0 != ret) {
        LogError("Malformed key, unable to decode");
        key.reset(nullptr);
        return key;
    }
#endif
    
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
    
#if defined(USE_LIBCRYPTO)
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
#elif defined(USE_MBEDTLS)
    ECKEY key(ECKEY_new());
    
    int ret = ecp_point_read_binary_ex(&key->grp, &key->Q, (const uint8_t*)data.data(), data.size());
    if (0 != ret) {
        LogError("Unable to import key");
        key.reset(nullptr);
        return key;
    }
    
    ret = ecp_check_pubkey(&key->grp, &key->Q);
    if (0 != ret) {
        LogError("Unable to verify imported public key");
        key.reset(nullptr);
        return key;
    }
#endif
    
    return key;
};

#pragma mark - ECDH Computations

/*!
 @functiongroup ECDH Computations
 */

static std::string ECDH_compute_secret(const ECKEY& priv, const ECKEY& pub) {
    LogTrace();
    
#if defined(USE_LIBCRYPTO)
    uint8_t Z[ECDHResultSize] = { 0 };
    int cb = ECDH_compute_key(Z, ECDHResultSize, EC_KEY_get0_public_key(pub.get()), priv.get(), NULL);
    if (cb != ECDHResultSize) {
        return std::string();
    }
    
    return std::string((const char*)Z, ECDHResultSize);
#elif defined(USE_MBEDTLS)
   scoped_mpi z;
    
    int ret = ecdh_compute_shared(&priv->grp, &z, &pub->Q, &priv->d, f_rng, nullptr);
    if (0 != ret) {
        return std::string();
    }
    
    std::string Z(mpi_get_string(&z, ECDHResultSize));
    
    if (Z.size() != ECDHResultSize) {
        return std::string();
    }
    
    return Z;
#endif
}

static std::string ECDH_derive_key(const std::string& Zs, const std::string& Ze,
                                   const std::vector<std::string>& otherInfo)
{
    LogTrace();
    
    if (Zs.empty() || Ze.empty()) {
        return std::string();
    }
    
#if defined(USE_LIBCRYPTO)
    SHA256_CTX sha256;
#elif defined(USE_MBEDTLS)
    sha256_context sha256;
    sha256_init(&sha256);
#endif
    
    uint8_t out[Sha256DigestSize] = { 0 };
    
    unsigned char Counter[4] = { 0x00, 0x00, 0x00, 0x01 };
    
#if defined(USE_LIBCRYPTO)
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, Counter, sizeof(Counter));
    SHA256_Update(&sha256, Zs.data(), Zs.size());
    SHA256_Update(&sha256, Ze.data(), Zs.size());
#elif defined(USE_MBEDTLS)
    sha256_starts(&sha256, false);
    sha256_update(&sha256, Counter, sizeof(Counter));
    sha256_update(&sha256, (const uint8_t*)Zs.data(), Zs.size());
    sha256_update(&sha256, (const uint8_t*)Ze.data(), Zs.size());
#endif
    
    for (const auto& s : otherInfo) {
#if defined(USE_LIBCRYPTO)
        SHA256_Update(&sha256, s.data(), s.size());
#elif defined(USE_MBEDTLS)
        sha256_update(&sha256, (const uint8_t*)s.data(), s.size());
#endif
    }

#if defined(USE_LIBCRYPTO)
    SHA256_Final(out, &sha256);
    SHA256_Init(&sha256);
#elif defined(USE_MBEDTLS)
    sha256_finish(&sha256, out);
    sha256_free(&sha256);
#endif
    
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
        LogError("Unexpected len of static secret: %lu bytes", Zs.size());
        return std::string();
    }
    
    // 3. Compute ephemeral secret, Ze = ECDH_compute_key(e_priv, r_pub)
    std::string Ze(ECDH_compute_secret(e_priv, e_pub));
    
    if(Ze.size() != ECDHResultSize) {
        LogError("Unexpected len of ephemeral secret: %lu bytes", Ze.size());
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
        LogError("Unexpected len of computed secret: %lu bytes", S.size());
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
#if defined(USE_LIBCRYPTO)
    EC_KEY_set_private_key(eph.get(), NULL);
#elif defined(USE_MBEDTLS)
    mpi_free(&eph->d);
#endif
    
    if (S.size() != KDFResultSize) {
        LogError("Unexpected len of computed secret: %lu bytes", S.size());
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
        LogError("Unexpected len of computed secret: %lu bytes", S.size());
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
    
#if defined(USE_LIBCRYPTO)
    const EVP_CIPHER* ciph = EVP_aes_128_gcm();
    
    auto ossl_evp_ciph_ctx_deleter = [](EVP_CIPHER_CTX* key) {
        if (key != nullptr) {
            EVP_CIPHER_CTX_cleanup(key);
            EVP_CIPHER_CTX_free(key);
        }
    };
    
    using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(ossl_evp_ciph_ctx_deleter)>;
    CipherCtxPtr evp(EVP_CIPHER_CTX_new(), ossl_evp_ciph_ctx_deleter);
    
    constexpr int encrypt = Op == Operation::Encrypt ? 1 : 0;
    
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
        uint8_t bTag[AesBlockSize] = { 0 };
        
        if (!EVP_CIPHER_CTX_ctrl(evp.get(), EVP_CTRL_GCM_GET_TAG, sizeof(bTag), bTag)) {
            LogError("EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG)");
            return r;
        }
        
        return std::make_tuple(output, std::string((const char*)bTag, sizeof(bTag)));
    }
    
    return std::make_tuple(output, std::string());
    
#elif defined(USE_MBEDTLS)
    gcm_context gcm;
    int ret = gcm_init(&gcm, POLARSSL_CIPHER_ID_AES, (const uint8_t*)key.data(), 128);
    if (0 != ret) {
        return r;
    }
    
    size_t len(data.size());
    std::unique_ptr<uint8_t[]> output(new uint8_t[len]);
    
    if (Op == Operation::Encrypt) {
        uint8_t bTag[AesBlockSize] = { 0 };
        
        ret = gcm_crypt_and_tag(&gcm, GCM_ENCRYPT, len,
                                (const uint8_t*)iv.data(), iv.size(),
                                (const uint8_t*)aad.data(), aad.size(),
                                (const uint8_t*)data.data(),
                                output.get(),
                                sizeof(bTag), bTag);
        
        if (ret == 0) {
            gcm_free(&gcm);
            return std::make_tuple(std::string((const char*)output.get(), len),
                                   std::string((const char*)bTag, sizeof(bTag)));
        }
        
    } else {
        ret = gcm_auth_decrypt(&gcm, len,
                               (const uint8_t*)iv.data(), iv.size(),
                               (const uint8_t*)aad.data(), aad.size(),
                               (const uint8_t*)tag.data(), tag.size(),
                               (const uint8_t*)data.data(),
                               output.get());
        if (ret == 0) {
            gcm_free(&gcm);
            return std::make_tuple(std::string((const char*)output.get(), len),
                                   std::string());
        }
    }
    
    gcm_free(&gcm);
    
    return r;
#endif
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

#pragma mark - Testing Routines

/*!
 @functiongroup Testing Routines
 */
#ifdef _NSCRYPTO_TESTS
int test_export_import() {
    ECKEY key(ECKEY_generate());
    
    std::string priv(ECKEY_export_private(key)), pub(ECKEY_export_public(key));
    ECKEY k_priv(ECKEY_import_private(priv)), k_pub(ECKEY_import_public(pub));
    
    int r = 0;
    
#if defined(USE_LIBCRYPTO)
    // Check private key
    if (BN_cmp(EC_KEY_get0_private_key(key.get()), EC_KEY_get0_private_key(k_priv.get()))) {
        LogError("key vs k_priv mismatch (private)");
        r++;
    }
    
    // Check group
    const EC_GROUP* g1 = EC_KEY_get0_group(key.get());
    const EC_GROUP* g2 = EC_KEY_get0_group(k_priv.get());
    const EC_GROUP* g3 = EC_KEY_get0_group(k_pub.get());
    
    if (EC_GROUP_cmp(g1, g2, nullptr)) {
        LogError("key vs k_priv mismatch (group)");
        r++;
    }
    
    if (EC_GROUP_cmp(g2, g3, nullptr)) {
        LogError("k_priv vs k_pub mismatch (group)");
        r++;
    }
    
    if (EC_GROUP_cmp(g1, g3, nullptr)) {
        LogError("key vs k_pub mismatch (group)");
        r++;
    }
    
    // Check public
    const EC_POINT* pt1(EC_KEY_get0_public_key(key.get()));
    const EC_POINT* pt2(EC_KEY_get0_public_key(k_priv.get()));
    const EC_POINT* pt3(EC_KEY_get0_public_key(k_pub.get()));
    
    if (EC_POINT_cmp(g1, pt1, pt2, nullptr)) {
        LogError("key vs k_priv mismatch (public)");
        r++;
    }
    
    if (EC_POINT_cmp(g1, pt2, pt3, nullptr)) {
        LogError("k_priv vs k_pub mismatch (public)");
        r++;
    }
    
    if (EC_POINT_cmp(g1, pt1, pt3, nullptr)) {
        LogError("key vs k_pub mismatch (public)");
        r++;
    }
    
#elif defined(USE_MBEDTLS)
    // Check private key
    if (mpi_cmp_mpi(&key->d, &k_priv->d)) {
        LogError("key->d vs k_priv->d mismatch");
        r++;
    }
    
    // Check public point
    if (mpi_cmp_mpi(&key->Q.X, &k_priv->Q.X)) {
        LogError("key->Q.X vs k_priv->Q.X mismatch");
        r++;
    }
    
    if (mpi_cmp_mpi(&key->Q.Y, &k_priv->Q.Y)) {
        LogError("key->Q.Y vs k_priv->Q.Y mismatch");
        r++;
    }
    
    if (mpi_cmp_mpi(&key->Q.Z, &k_priv->Q.Z)) {
        LogError("key->Q.Z vs k_priv->Q.Z mismatch");
        r++;
    }
    
    // Check public point
    if (mpi_cmp_mpi(&key->Q.X, &k_pub->Q.X)) {
        LogError("key->Q.X vs k_pub->Q.X mismatch");
        r++;
    }
    
    if (mpi_cmp_mpi(&key->Q.Y, &k_pub->Q.Y)) {
        LogError("key->Q.Y vs k_pub->Q.Y mismatch");
        r++;
    }
    
    if (mpi_cmp_mpi(&key->Q.Z, &k_pub->Q.Z)) {
        LogError("key->Q.Z vs k_pub->Q.Z mismatch");
        r++;
    }
    
#else
    #error Underlying library not specified
#endif

    return r;
}
#endif
