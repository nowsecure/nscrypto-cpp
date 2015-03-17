#include "vp_ecdh.h"

#include <openssl/evp.h>	// for NID_X9_62_prime256v1
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/asn1t.h>

#ifdef _EXTRA_LOGGING
    #define LogMsg(frmt, ...)       fprintf(stderr, "%s: " frmt "\n", __FUNCTION__, ##__VA_ARGS__)
#else
    #define LogMsg(frmt, ...)
#endif //_EXTRA_LOGGING

#define LogTrace()              LogMsg("")
#define LogTrace2(frmt, ...)    LogMsg(frmt, ##__VA_ARGS__)
#define LogError(frmt, ...)     LogMsg("[ERROR] " frmt, ##__VA_ARGS__)
#define LogWarn(frmt, ...)      LogMsg("[WARN] " frmt, ##__VA_ARGS__)
#define LogInfo(frmt, ...)      LogMsg("[INFO] " frmt, ##__VA_ARGS__)
#define LogVerbose(frmt, ...)   LogMsg("[VERBOSE] " frmt, ##__VA_ARGS__)

#include <stdint.h>

#define CURVE_NAME		NID_X9_62_prime256v1

typedef struct {
	unsigned char* pb;
	size_t         cb;
} Blob;

// Allocate new EC key
static EC_KEY* VP_EC_KEY_new();

// Compute shared secret Z given public and private keys
int VP_ECDH_compute_secret(EC_KEY* priv, const EC_KEY* pub, uint8_t* Z);

// Derive key
static int VP_ECDH_derive_key(unsigned char* Zs, unsigned char* Ze, Blob* OtherInfo, int count, unsigned char* out);

// Compute shared secret key given two pairs of keys:
// - static keys s_priv and s_pub
// - ephemeral keys e_priv, e_pub
static int VP_ECDH_compute_key(EC_KEY* s_priv, const EC_KEY* s_pub, EC_KEY* e_priv, const EC_KEY* e_pub, const char* sndr_id, const EC_KEY* sndr_pub, const char* rcpt_id, const EC_KEY* rcpt_pub, const unsigned char* dv, size_t dv_len, unsigned char* S);

///////////////////////////////////////////////////////////////////////////////
//
EC_KEY* VP_EC_KEY_generate() {
    LogTrace();
    
	EC_KEY* key = VP_EC_KEY_new();
    
	if (!EC_KEY_generate_key (key)) {
		LogError("Unable to generate EC key");
		EC_KEY_free(key);
		return NULL;
	}
    
	if (!EC_KEY_check_key(key)) {
		LogError("Unable to verify EC key");
		EC_KEY_free(key);
		return NULL;
	}
    
	return key;
}

///////////////////////////////////////////////////////////////////////////////
//
static EC_KEY* VP_EC_KEY_new() {
    LogTrace();
    
	EC_KEY* key = EC_KEY_new_by_curve_name(CURVE_NAME);
	if (key == NULL) {
		LogError("Unable to create EC key for %d", CURVE_NAME);
		return NULL;
	}
    
	EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
	EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
    
	return key;
}

///////////////////////////////////////////////////////////////////////////////
//
typedef struct ec_priv_key_st {
	ASN1_INTEGER      *i;
	ASN1_OCTET_STRING *x;
} VP_EC_PRIV_KEY;

DECLARE_ASN1_FUNCTIONS(VP_EC_PRIV_KEY)

ASN1_SEQUENCE(VP_EC_PRIV_KEY) = {
	ASN1_SIMPLE(VP_EC_PRIV_KEY, i, ASN1_INTEGER),
	ASN1_SIMPLE(VP_EC_PRIV_KEY, x, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(VP_EC_PRIV_KEY)

IMPLEMENT_ASN1_FUNCTIONS(VP_EC_PRIV_KEY)

///////////////////////////////////////////////////////////////////////////////
//
std::string VP_EC_KEY_export_private(const EC_KEY* key) {
    LogTrace();
    
    std::string r;
    
    if (!key) {
        LogError("NULL pointer");
        return r;
    }
    
    VP_EC_PRIV_KEY* pkey = VP_EC_PRIV_KEY_new();
	ASN1_INTEGER_set(pkey->i, 1);
    
	const BIGNUM* x = EC_KEY_get0_private_key(key);
	uint8_t* pb = new uint8_t[BN_num_bytes(x)];
	int cb = BN_bn2bin(x, pb);
    
	ASN1_STRING_set(pkey->x, pb, cb);
	delete[] pb;
    
	pb = NULL;
	cb = i2d_VP_EC_PRIV_KEY(pkey, &pb);
    
	VP_EC_PRIV_KEY_free(pkey);
    
    r = std::string((const char*) pb, cb);
	OPENSSL_free(pb);
    
	return r;
}

///////////////////////////////////////////////////////////////////////////////
//
std::string VP_EC_KEY_export_public(const EC_KEY* key) {
    LogTrace();
    
    std::string r;
    
    if (!key) {
        LogError("NULL pointer");
        return r;
    }
    
    uint8_t* pb = NULL;
	int cb = i2o_ECPublicKey((EC_KEY*)key, &pb);
    
    r = std::string((const char*)pb, cb);
	OPENSSL_free(pb);
    
	return r;
}

///////////////////////////////////////////////////////////////////////////////
//
EC_KEY* VP_EC_KEY_import_private(const std::string& data) {
    LogTrace();
    
    if (data.empty()) {
        LogError("Empty input");
        return NULL;
    }
    
    uint8_t* pb = (uint8_t*) data.data();
	VP_EC_PRIV_KEY* pkey = d2i_VP_EC_PRIV_KEY(NULL, (const uint8_t**) &pb, (int)data.size());
    
	if (!pkey) {
		LogError("Malformed key, unable to decode");
		return NULL;
	}
    
	BIGNUM* priv = BN_bin2bn(ASN1_STRING_data(pkey->x), ASN1_STRING_length(pkey->x), NULL);
	VP_EC_PRIV_KEY_free(pkey);
    
	if (!priv) {
		LogError("Malformed key, unable to convert to BIGNUM");
		return NULL;
	}
    
	EC_KEY* key = VP_EC_KEY_new();
	
	// Compute public key
	EC_POINT* pub = EC_POINT_new(EC_KEY_get0_group(key));
	EC_POINT_mul(EC_KEY_get0_group(key), pub, priv, NULL, NULL, NULL);
    
	EC_KEY_set_private_key(key, priv);
	EC_KEY_set_public_key(key, pub);
    
	BN_free(priv);
	EC_POINT_free(pub);
    
	if (!EC_KEY_check_key (key)) {
		LogError("Unable to verify imported private key");
		EC_KEY_free (key);
		return NULL;
	}
    
	return key;
};

///////////////////////////////////////////////////////////////////////////////
//
EC_KEY* VP_EC_KEY_import_public (const std::string& data) {
    LogTrace();
    
    if (data.empty()) {
        LogError("Empty input");
        return NULL;
    }
    
    uint8_t* p = (uint8_t*) data.data();
    EC_KEY* key = VP_EC_KEY_new();

    key = o2i_ECPublicKey(&key, (const uint8_t**) &p, (int)data.size());
    
	if (!EC_KEY_check_key (key)) {
		LogError("Unable to verify imported public key");
		EC_KEY_free (key);
		return NULL;
	}
    
	return key;
};

///////////////////////////////////////////////////////////////////////////////
//
std::string VP_encrypt_data(int encrypt, const std::string& aad, const std::string& data, const std::string& iv, const std::string& key, std::string* tag) {
    LogTrace();
    
	std::string r;
	if (!tag) {
		LogError("NULL pointer");
		return r;
	}

	const EVP_CIPHER* ciph = EVP_aes_128_gcm();
	EVP_CIPHER_CTX* evp = EVP_CIPHER_CTX_new();

	if (!EVP_CipherInit(evp, ciph, (const uint8_t*)key.data(), (const uint8_t*)iv.data(), encrypt)) {
		LogError("EVP_CipherInit()");
		EVP_CIPHER_CTX_cleanup(evp);
		EVP_CIPHER_CTX_free(evp);
		return r;
	}

	if (!EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), NULL)) {
		LogError("EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_IVLEN)");
		EVP_CIPHER_CTX_cleanup(evp);
		EVP_CIPHER_CTX_free(evp);
		return r;
	}

	if (!encrypt) {
		if (!EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, (int)tag->size(), (void*)tag->data())) {
			LogError("EVP_CIPHER_CTX_ctrl()");
			EVP_CIPHER_CTX_cleanup(evp);
			EVP_CIPHER_CTX_free(evp);
			return r;
		}
	}

	int outl = 0;
	if (!aad.empty()) {
		if (!EVP_CipherUpdate(evp, NULL, &outl, (const uint8_t*)aad.data(), (int)aad.size())) {
			LogError("EVP_CipherUpdate() - 1");
			EVP_CIPHER_CTX_cleanup(evp);
			EVP_CIPHER_CTX_free(evp);
			return r;
		}
	}

	outl = 0;
	uint8_t* pbOut = new uint8_t[data.size()];

	if (!EVP_CipherUpdate(evp, pbOut, &outl, (const uint8_t*)data.data(), (int)data.size())) {
		LogError("EVP_CipherUpdate() - 2");
		EVP_CIPHER_CTX_cleanup(evp);
		EVP_CIPHER_CTX_free(evp);
		return r;
	}

	int rr = outl;

	if (!EVP_CipherFinal(evp, pbOut + outl, &outl)) {
		LogError("EVP_CipherFinal()");
		EVP_CIPHER_CTX_cleanup(evp);
		EVP_CIPHER_CTX_free(evp);
		return r;
	}

	rr += outl;

	if (encrypt) {
		uint8_t bTag[AES_BLOCK_SIZE] = { 0 };

		if (!EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, sizeof(bTag), bTag)) {
			LogError("EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG)");
			delete[] pbOut;
			EVP_CIPHER_CTX_cleanup(evp);
			EVP_CIPHER_CTX_free(evp);
			return r;
		}

		*tag = std::string((const char*)bTag, sizeof(bTag));
	}

	r = std::string((const char*)pbOut, rr);
	delete[] pbOut;

	EVP_CIPHER_CTX_cleanup(evp);
	EVP_CIPHER_CTX_free(evp);

	return r;
}

///////////////////////////////////////////////////////////////////////////////
//
// This complies with "viaProtect: Data Protection" specification
// Implements steps 1-5 of Encryption process desribed in
// Data Authentication with Optional Encryption Primitive
//
// Resulting S can be split into key and IV and used for encryption
//
std::string VP_ECDH_generate_enc_key (EC_KEY* S_priv, const EC_KEY* R_pub, const std::string& S_id, const std::string& R_id, const std::string& DV, EC_KEY** SE_pub) {
    LogTrace();
    
	std::string r;
	if (S_priv == NULL || R_pub == NULL || SE_pub == NULL) {
		LogError("NULL argument");
		return r;
	}

	// Generate ephemeral keypair
	EC_KEY* SE = VP_EC_KEY_generate();

	if (!SE) {
		LogError("Unable to generate ephemeral keypair");
		return r;
	}

	uint8_t S[DERIVED_SECRET_SIZE + 1] = { 0 };
	int cb = VP_ECDH_compute_key(S_priv, R_pub, SE, R_pub, S_id.c_str(), SE, R_id.c_str(), R_pub, (const uint8_t*)DV.data(), DV.size(), S);

	// Destroy ephemeral private key
	//EC_KEY_set_private_key (eph, NULL);

	if (cb == DERIVED_SECRET_SIZE) {
		*SE_pub = SE;
		return std::string((const char*) S, DERIVED_SECRET_SIZE);
	}

	memset(S, 0, sizeof(S));
	EC_KEY_free(SE);

	return r;
}

///////////////////////////////////////////////////////////////////////////////
//
// This complies with "viaProtect: Data Protection" specification
// Implements steps 1-5 of Decryption process desribed in
// Data Authentication with Optional Encryption Primitive
//
// Resulting S can be split into key and IV and used for decryption
//
std::string VP_ECDH_compute_dec_key(EC_KEY* R_priv, const EC_KEY* S_pub, const EC_KEY* SE_pub, const std::string& S_id, const std::string& R_id, const std::string& DV) {
    LogTrace();
    
	std::string r;
	if (R_priv == NULL || S_pub == NULL || SE_pub == NULL) {
		LogError("NULL argument");
		return r;
	}

	uint8_t S[DERIVED_SECRET_SIZE + 1] = { 0 };
	int cb = VP_ECDH_compute_key(R_priv, S_pub, R_priv, SE_pub, S_id.c_str(), SE_pub, R_id.c_str(), R_priv, (const uint8_t*)DV.data(), DV.size(), S);
	if (cb == DERIVED_SECRET_SIZE) {
		return std::string((const char*)S, DERIVED_SECRET_SIZE);
	}

	memset(S, 0, DERIVED_SECRET_SIZE);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
static std::string _AAD(const std::string& DV, const std::string& S_id, const EC_KEY* S_pub, const std::string& R_id, const EC_KEY* R_pub) {
    LogTrace();
    
	std::string r;
	if (!S_pub || !R_pub) {
		LogError("NULL argument");
		return r;
	}

	uint8_t* S_pub_buf = NULL;
	size_t S_pub_len = i2o_ECPublicKey((EC_KEY*)S_pub, &S_pub_buf);

	uint8_t* R_pub_buf = NULL;
	size_t R_pub_len = i2o_ECPublicKey((EC_KEY*)R_pub, &R_pub_buf);

	r = DV + S_id + std::string((const char*)S_pub_buf, S_pub_len) + R_id + std::string((const char*)R_pub_buf, R_pub_len);

	if (S_pub_buf)
		free(S_pub_buf);

	if (R_pub_buf)
		free(R_pub_buf);

	return r;
}

///////////////////////////////////////////////////////////////////////////////
//
std::string VP_ECDH_encrypt(EC_KEY* S_priv, const EC_KEY* R_pub, const std::string& S_id, const std::string& R_id, const std::string& DV, const std::string& data, EC_KEY** SE_pub, std::string* tag) {
    LogTrace();
    
	std::string r;

	if (S_priv == NULL || R_pub == NULL || SE_pub == NULL || tag == NULL) {
		LogError("NULL argument");
		return r;
	}

	EC_KEY* SE = NULL;
	r = VP_ECDH_generate_enc_key(S_priv, R_pub, S_id, R_id, DV, &SE);
	if (r.empty() || r.size() < 24) {
		LogError("Cannot create encryption key");
		return std::string();
	}

	*SE_pub = SE;

	std::string aad = _AAD(DV, S_id, SE, R_id, R_pub);

	std::string key = r.substr(0, 16);
	std::string iv = r.substr(16, 12);

	return VP_encrypt_data(1, aad, data, iv, key, tag);
}

///////////////////////////////////////////////////////////////////////////////
//
std::string VP_ECDH_decrypt(EC_KEY* R_priv, const EC_KEY* S_pub, const EC_KEY* SE_pub, const std::string& S_id, const std::string& R_id, const std::string& DV, const std::string& data, const std::string& tag) {
    LogTrace();
    
	std::string r;
	if (R_priv == NULL || S_pub == NULL || SE_pub == NULL) {
		LogError("NULL argument");
		return r;
	}

	r = VP_ECDH_compute_dec_key(R_priv, S_pub, SE_pub, S_id, R_id, DV);
	if (r.empty() || r.size() < 24) {
		LogError("Cannot compute decryption key");
		return std::string();
	}

	std::string aad = _AAD(DV, S_id, SE_pub, R_id, R_priv);

	std::string key = r.substr(0, 16);
	std::string iv = r.substr(16, 12);

	std::string tt(tag);
	return VP_encrypt_data(0, aad, data, iv, key, &tt);
}

///////////////////////////////////////////////////////////////////////////////
//
static int VP_ECDH_compute_key (EC_KEY* s_priv, const EC_KEY* s_pub, EC_KEY* e_priv, const EC_KEY* e_pub, const char* sndr_id, const EC_KEY* sndr_pub, const char* rcpt_id, const EC_KEY* rcpt_pub, const unsigned char* dv, size_t dv_len, unsigned char* S) {
    LogTrace();
    
	if (s_priv == NULL || s_pub == NULL || e_priv == NULL || e_pub == NULL || sndr_id == NULL || sndr_pub == NULL || rcpt_id == NULL || rcpt_pub == NULL || S == NULL) {
		return (-1);
	}

	// Static secret, Zs = ECDH_compute_key (s_priv, r_pub)
	unsigned char Zs[COMPUTED_SECRET_SIZE];

	// Ephemeral secret, Ze = ECDH_compute_key (e_priv, r_pub)
	unsigned char Ze[COMPUTED_SECRET_SIZE];

	int cb;
	// 2. Compute shared secret Zs
	cb = VP_ECDH_compute_secret (s_priv, s_pub, Zs);
	if (cb != COMPUTED_SECRET_SIZE) {
		LogError("Computed secret (static) is too short: %d bytes", cb);

		memset (Zs, 0, sizeof(Zs));
		return 0;
	}
    
	// 3. Compute ephemeral secret Ze
	cb = VP_ECDH_compute_secret (e_priv, e_pub, Ze);
	if (cb != COMPUTED_SECRET_SIZE) {
		LogError("Computed secret (ephemral) is too short: %d bytes", cb);

		memset (Zs, 0, sizeof(Zs));
		memset (Ze, 0, sizeof(Ze));
		return 0;
	}

	// 4. Z = Zs || Ze -- this will be done implicitly in the next step
	// 5. S = KDF (Z, DV || s_id || eph_pub || r_id || r_pub)

	unsigned char* sndr_pub_buf = NULL;
	size_t sndr_pub_len = i2o_ECPublicKey ((EC_KEY*) sndr_pub, &sndr_pub_buf);

	unsigned char* rcpt_pub_buf = NULL;
	size_t rcpt_pub_len = i2o_ECPublicKey ((EC_KEY*) rcpt_pub, &rcpt_pub_buf);
	
	Blob OtherInfo[5] = { {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0} };
	
	OtherInfo[0].pb = (unsigned char*) dv;
	OtherInfo[0].cb = dv_len;

	OtherInfo[1].pb = (unsigned char*) sndr_id;
	OtherInfo[1].cb = strlen (sndr_id);

	OtherInfo[2].pb = sndr_pub_buf;
	OtherInfo[2].cb = sndr_pub_len;

	OtherInfo[3].pb = (unsigned char*) rcpt_id;
	OtherInfo[3].cb = strlen (rcpt_id);

	OtherInfo[4].pb = rcpt_pub_buf;
	OtherInfo[4].cb = rcpt_pub_len;
	
	int cbKey = VP_ECDH_derive_key (Zs, Ze, OtherInfo, 5, S);

	// Destroy Zs and Ze
	memset (Zs, 0, COMPUTED_SECRET_SIZE);
	memset (Ze, 0, COMPUTED_SECRET_SIZE);

	// Free allocated buffers
	free (sndr_pub_buf);
	free (rcpt_pub_buf);

	if (cbKey == DERIVED_SECRET_SIZE) {
		return DERIVED_SECRET_SIZE;
	}

	memset (S, 0, DERIVED_SECRET_SIZE);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
static int VP_ECDH_derive_key (unsigned char* Zs, unsigned char* Ze, Blob* OtherInfo, int count, unsigned char* out) {
    LogTrace();
    
	SHA256_CTX sha256;

	unsigned char Counter[4] = { 0x00, 0x00, 0x00, 0x01 };

	SHA256_Init (&sha256);
	SHA256_Update (&sha256, Counter, sizeof(Counter));
	SHA256_Update (&sha256, Zs, COMPUTED_SECRET_SIZE);
	SHA256_Update (&sha256, Ze, COMPUTED_SECRET_SIZE);

	for (int i = 0; i < count; i++) {
		SHA256_Update (&sha256, OtherInfo[i].pb, OtherInfo[i].cb);
	}

	SHA256_Final (out, &sha256);
	SHA256_Init (&sha256);

	return DERIVED_SECRET_SIZE;
}

///////////////////////////////////////////////////////////////////////////////
//
int VP_ECDH_compute_secret(EC_KEY* priv, const EC_KEY* pub, uint8_t* Z) {
    LogTrace();
	return ECDH_compute_key(Z, COMPUTED_SECRET_SIZE, EC_KEY_get0_public_key(pub), priv, NULL);
}
