#pragma once
#include <string>
#include <vector>
#include <memory>

// Forward declare OpenSSL types
typedef struct evp_pkey_st EVP_PKEY;

namespace pki487 {

struct KeyPair {
    std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> pkey{nullptr, nullptr};
};

// Generate RSA key pair with given bits.
KeyPair generate_rsa_key(int bits = 2048);

// Save keys to PEM files.
void save_private_key_pem(const KeyPair& kp, const std::string& path, const std::string& pass = "");
void save_public_key_pem(const KeyPair& kp, const std::string& path);

// Load keys from PEM files.
std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> load_private_key_pem(const std::string& path, const std::string& pass = "");
std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> load_public_key_pem(const std::string& path);

// Sign data using SHA256 with RSA (PKCS#1 v1.5). Returns signature bytes.
std::vector<unsigned char> sign_sha256_rsa(EVP_PKEY* priv, const std::string& data);

// Verify signature using SHA256 with RSA (PKCS#1 v1.5). Returns true if valid.
bool verify_sha256_rsa(EVP_PKEY* pub, const std::string& data, const std::vector<unsigned char>& sig);

// Base64 helpers (no newlines).
std::string base64_encode(const std::vector<unsigned char>& data);
std::vector<unsigned char> base64_decode(const std::string& b64);

// Extract public key PEM string from EVP_PKEY.
std::string public_key_to_pem(EVP_PKEY* pkey);

} // namespace pki487
