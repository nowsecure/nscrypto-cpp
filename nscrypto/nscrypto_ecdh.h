/*!
 @header NSCRYPTO ECDH API
 
 Simple and user-friendly API to encrypt and decrypt data using
 Elliptic-Curve Diffie-Hellman (ECDH) key agreement in a way consistent
 with NIST 800-56A C(1e, 2s) scheme.
 This scheme is suitable for "store-and-forward" scenarios and provides 
 perfect forward secresy for sender (but not for recipient).
 
 @compilerflag -lcrypto
 
 @author NowSecure (Andrey Belenko)
 
 @version 0.1
 
 @updated 2015-03-11
 */

#ifndef __NSCRYPTO_ECDH_H__
#define __NSCRYPTO_ECDH_H__

#include <string>
#include <tuple>

/*!
 @typedef keypair_t
 
 @abstract A tuple holding a keypair. Contains following elements:
 
 @field private key (std::string)
 
 @field public key (std::string)
 */
typedef std::tuple<std::string, std::string> keypair_t;

/*!
 @typedef ecdh_encrypted_t
 
 @abstract A tuple holding an encrypted message. Contains following elements:
 
 @field ciphertext of the message (std::string)
 
 @field authentication tag (std::string)
 
 @field ephemeral public key (std::string)
 */
typedef std::tuple<std::string, std::string, std::string> ecdh_encrypted_t;

/*!
 @functiongroup Key Generation
 */

/*!
 Generates new EC keypair.
 
 @return keypair_t containing generated private key and corresponding public
  key. In case of error returns keypair_t containing empty std::strings.
 
 @see keypair_t
 */
keypair_t ec_keypair();

/*!
 @functiongroup Encryption and Decryption
 */

/*!
 Encrypts message. This function is meant to be used by clients and on data that
 is being sent from client to server. Recipient can decrypt data by calling 
 ecdh_server_decrypt function.
 
 @param s_priv  Sender's private key
 @param r_pub   Recipient's public key
 @param s_id    Sender's unique identifier
 @param r_id    Recipient's identifier (typically shared among all clients)
 @param message Data to encrypt
 
 @return ecdh_encrypted_t containing ciphertext, tag, and ephemeral public key.
  In case of error returns ecdh_encrypted_t containing empty std::strings.
 
 @see ecdh_encrypted_t, ecdh_server_decrypt
 */
ecdh_encrypted_t ecdh_client_encrypt(const std::string& s_priv, const std::string& r_pub,
                                     const std::string& s_id, const std::string& r_id,
                                     const std::string& message);

/*!
 Encrypts message. This function is meant to be used by server and on data that
 is being sent from server to client. Recipient can decrypt data by calling
 ecdh_client_decrypt function.
 
 @param s_priv  Sender's private key
 @param r_pub   Recipient's public key
 @param s_id    Sender's unique identifier
 @param r_id    Recipient's identifier (typically shared among all clients)
 @param message Data to encrypt
 
 @return ecdh_encrypted_t containing ciphertext, tag, and ephemeral public key.
 In case of error returns ecdh_encrypted_t containing empty std::strings.
 
 @see ecdh_encrypted_t, ecdh_client_decrypt
 */
ecdh_encrypted_t ecdh_server_encrypt(const std::string& s_priv, const std::string& r_pub,
                                     const std::string& s_id, const std::string& r_id,
                                     const std::string& message);

/*!
 Decrypts message encrypted by ecdh_client_encrypt. This function is meant to be
 used by servers and on data that is sent from client to server.
 
 @param r_priv    Recipient's private key
 @param s_pub     Sender's public key
 @param s_id      Sender's unique identifier
 @param r_id      Recipient's identifier (typically shared among all clients)
 @param encrypted ecdh_encrypted_t holding ciphertext, authentication tag, and
  ephemeral public key
 
 @return std::string containing decrypted data. In case of error returns empty
  string.
 
 @see ecdh_encrypted_t, ecdh_client_encrypt
 */
std::string ecdh_server_decrypt(const std::string& r_priv, const std::string& s_pub,
                                const std::string& s_id, const std::string& r_id,
                                const ecdh_encrypted_t& encrypted);

/*!
 Decrypts message encrypted by ecdh_server_encrypt. This function is meant to be
 used by clients and on data that is sent from server to client.
 
 @param r_priv    Recipient's private key
 @param s_pub     Sender's public key
 @param s_id      Sender's unique identifier
 @param r_id      Recipient's identifier (typically shared among all clients)
 @param encrypted ecdh_encrypted_t holding ciphertext, authentication tag, and
 ephemeral public key
 
 @return std::string containing decrypted data. In case of error returns empty
 string.
 
 @see ecdh_encrypted_t, ecdh_server_encrypt
 */
std::string ecdh_client_decrypt(const std::string& r_priv, const std::string& s_pub,
                                const std::string& s_id, const std::string& r_id,
                                const ecdh_encrypted_t& encrypted);

#endif //__NSCRYPTO_ECDH_H__
