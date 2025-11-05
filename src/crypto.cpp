#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdexcept>
#include <vector>
#include <memory>

namespace pki487 {

static void pkey_free(EVP_PKEY* p) { if (p) EVP_PKEY_free(p); }

KeyPair generate_rsa_key(int bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); throw std::runtime_error("keygen_init failed"); }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) { EVP_PKEY_CTX_free(ctx); throw std::runtime_error("set bits failed"); }
    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey_raw) <= 0) { EVP_PKEY_CTX_free(ctx); throw std::runtime_error("keygen failed"); }
    EVP_PKEY_CTX_free(ctx);
    KeyPair kp;
    kp.pkey = std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)>(pkey_raw, pkey_free);
    return kp;
}

void save_private_key_pem(const KeyPair& kp, const std::string& path, const std::string& pass) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) throw std::runtime_error("Cannot open file for private key");
    if (pass.empty()) {
        if (!PEM_write_PrivateKey(f, kp.pkey.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
            fclose(f); throw std::runtime_error("PEM_write_PrivateKey failed");
        }
    } else {
        if (!PEM_write_PrivateKey(f, kp.pkey.get(), EVP_aes_256_cbc(), (unsigned char*)pass.data(), (int)pass.size(), nullptr, nullptr)) {
            fclose(f); throw std::runtime_error("PEM_write_PrivateKey (enc) failed");
        }
    }
    fclose(f);
}

void save_public_key_pem(const KeyPair& kp, const std::string& path) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) throw std::runtime_error("Cannot open file for public key");
    if (!PEM_write_PUBKEY(f, kp.pkey.get())) { fclose(f); throw std::runtime_error("PEM_write_PUBKEY failed"); }
    fclose(f);
}

std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> load_private_key_pem(const std::string& path, const std::string& pass) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) throw std::runtime_error("Cannot open private key file");
    EVP_PKEY* p = PEM_read_PrivateKey(f, nullptr, nullptr, pass.empty() ? nullptr : (void*)pass.c_str());
    fclose(f);
    if (!p) throw std::runtime_error("PEM_read_PrivateKey failed");
    return {p, pkey_free};
}

std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> load_public_key_pem(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) throw std::runtime_error("Cannot open public key file");
    EVP_PKEY* p = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!p) throw std::runtime_error("PEM_read_PUBKEY failed");
    return {p, pkey_free};
}

std::vector<unsigned char> sign_sha256_rsa(EVP_PKEY* priv, const std::string& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    std::vector<unsigned char> sig;
    size_t siglen = 0;
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, priv) <= 0) { EVP_MD_CTX_free(ctx); throw std::runtime_error("DigestSignInit failed"); }
    if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) <= 0) { EVP_MD_CTX_free(ctx); throw std::runtime_error("DigestSignUpdate failed"); }
    if (EVP_DigestSignFinal(ctx, nullptr, &siglen) <= 0) { EVP_MD_CTX_free(ctx); throw std::runtime_error("DigestSignFinal(size) failed"); }
    sig.resize(siglen);
    if (EVP_DigestSignFinal(ctx, sig.data(), &siglen) <= 0) { EVP_MD_CTX_free(ctx); throw std::runtime_error("DigestSignFinal failed"); }
    sig.resize(siglen);
    EVP_MD_CTX_free(ctx);
    return sig;
}

bool verify_sha256_rsa(EVP_PKEY* pub, const std::string& data, const std::vector<unsigned char>& sig) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    do {
        if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pub) <= 0) break;
        if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) <= 0) break;
        if (EVP_DigestVerifyFinal(ctx, sig.data(), sig.size()) != 1) break;
        ok = true;
    } while(false);
    EVP_MD_CTX_free(ctx);
    return ok;
}

std::string base64_encode(const std::vector<unsigned char>& data) {
    BIO* bio = BIO_new(BIO_f_base64());
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new(BIO_s_mem());
    bio = BIO_push(bio, mem);
    BIO_write(bio, data.data(), (int)data.size());
    BIO_flush(bio);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free_all(bio);
    return out;
}

std::vector<unsigned char> base64_decode(const std::string& b64) {
    BIO* bio = BIO_new(BIO_f_base64());
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new_mem_buf(b64.data(), (int)b64.size());
    bio = BIO_push(bio, mem);
    std::vector<unsigned char> out(b64.size());
    int len = BIO_read(bio, out.data(), (int)out.size());
    if (len < 0) len = 0;
    out.resize((size_t)len);
    BIO_free_all(bio);
    return out;
}

std::string public_key_to_pem(EVP_PKEY* pkey) {
    BIO* mem = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(mem, pkey)) { BIO_free(mem); throw std::runtime_error("PEM_write_bio_PUBKEY failed"); }
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(mem, &bptr);
    std::string pem(bptr->data, bptr->length);
    BIO_free(mem);
    return pem;
}

} // namespace pki487
