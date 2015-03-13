
#include <cstring>
#include <string>

#include <openssl/ecdh.h>

// Size of computed shared secret; can calculated as follows
// int secret_size = EC_GROUP_get_degree (EC_KEY_get0_group (key));
// secret_size = (secret_size + 7) / 8;
#define COMPUTED_SECRET_SIZE	32

// Size of derived secret
// This is how many bytes KDF is expected to produce
#define DERIVED_SECRET_SIZE		32

// Generates new EC keypair
EC_KEY* VP_EC_KEY_generate ();

// Export public/private key to opaque std::string
std::string VP_EC_KEY_export_private(const EC_KEY* key);
std::string VP_EC_KEY_export_public (const EC_KEY* key);

// Import opaque std::string and return public/private key
EC_KEY* VP_EC_KEY_import_private(const std::string& data);
EC_KEY* VP_EC_KEY_import_public (const std::string& data);

// Generate shared secret S, suitable for use as key material
std::string VP_ECDH_generate_enc_key(EC_KEY* S_priv, const EC_KEY* R_pub, const std::string& S_id, const std::string& R_id, const std::string& DV, EC_KEY** SE_pub);
std::string VP_ECDH_encrypt(EC_KEY* S_priv, const EC_KEY* R_pub, const std::string& S_id, const std::string& R_id, const std::string& DV, const std::string& data, EC_KEY** SE_pub, std::string* tag);

std::string VP_ECDH_compute_dec_key(EC_KEY* R_priv, const EC_KEY* S_pub, const EC_KEY* SE_pub, const std::string& S_id, const std::string& R_id, const std::string& DV);
std::string VP_ECDH_decrypt(EC_KEY* R_priv, const EC_KEY* S_pub, const EC_KEY* SE_pub, const std::string& S_id, const std::string& R_id, const std::string& DV, const std::string& data, const std::string& tag);
