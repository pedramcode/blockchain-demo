#include "blockchain/wallet.h"

// Generate private key and return as string
std::string generatePrivateKey();

// Generate public key from private key string and return as string
std::string generatePublicKey(const std::string &privateKeyStr);

// Sign data using private key and return signature as string
std::string signData(const std::string &dataStr, const std::string &privateKeyStr);

// Verify signature using public key and return true if valid, false otherwise
bool verifySignature(const std::string &dataStr, const std::string &signatureStr, const std::string &publicKeyStr);

bchain::Wallet::Wallet() {
    _prv = generatePrivateKey();
    _pub = generatePublicKey(_prv);
}

bchain::Wallet::Wallet(const std::string &private_key) {
    _prv = private_key;
    _pub = generatePublicKey(_prv);
}

bchain::Wallet bchain::Wallet::generate() {
    return {};
}

bchain::Wallet bchain::Wallet::from_prv(const std::string &private_key) {
    return bchain::Wallet(private_key);
}

std::string bchain::Wallet::sign_message(const std::string &data) {
    return signData(data, _prv);
}

bool bchain::Wallet::verify_message(const std::string &data, const std::string &sign) {
    return verifySignature(data, sign, _pub);
}

std::string generatePrivateKey() {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, NULL);

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    char *privKey;
    long length = BIO_get_mem_data(bio, &privKey);
    std::string privateKey(privKey, length);

    BIO_free_all(bio);
    RSA_free(rsa);
    BN_free(bn);

    // Base64 encode the private key
    return bchain::utils::base64_encode(reinterpret_cast<const unsigned char *>(privateKey.c_str()), privateKey.length());
}

std::string generatePublicKey(const std::string &privateKeyStr) {
    // Decode the base64 encoded private key
    std::string decodedPrivateKey = bchain::utils::base64_decode(privateKeyStr);

    RSA *rsa = NULL;
    BIO *bio = BIO_new_mem_buf(decodedPrivateKey.c_str(), -1);
    rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);

    RSA *pubKey = RSAPublicKey_dup(rsa);
    BIO *pubBio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pubBio, pubKey);

    char *pubKeyData;
    long length = BIO_get_mem_data(pubBio, &pubKeyData);
    std::string publicKey(pubKeyData, length);

    BIO_free_all(bio);
    BIO_free_all(pubBio);
    RSA_free(rsa);
    RSA_free(pubKey);

    // Base58 encode the public key
    return bchain::utils::base58_encode(reinterpret_cast<const unsigned char *>(publicKey.c_str()), publicKey.length());
}

std::string signData(const std::string &dataStr, const std::string &privateKeyStr) {
    // Decode the base58 encoded private key
    std::string decodedPrivateKey = bchain::utils::base58_decode(privateKeyStr);

    RSA *rsa = NULL;
    BIO *bio = BIO_new_mem_buf(decodedPrivateKey.c_str(), -1);
    rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);

    const unsigned char *data = reinterpret_cast<const unsigned char *>(dataStr.data()); // Use data() instead of c_str()
    unsigned char signature[RSA_size(rsa)];
    unsigned int signatureLength;

    int result = RSA_sign(NID_sha256, data, dataStr.size(), signature, &signatureLength, rsa);
    if (result != 1) {
        // Handle error
    }

    BIO_free_all(bio);
    RSA_free(rsa);

    // Base64 encode the signature
    return bchain::utils::base64_encode(signature, signatureLength);
}

bool verifySignature(const std::string &dataStr, const std::string &signatureStr, const std::string &publicKeyStr) {
    // Decode the base58 encoded public key
    std::string decodedPublicKey = bchain::utils::base58_decode(publicKeyStr);

    RSA *rsa = NULL;
    BIO *bio = BIO_new_mem_buf(decodedPublicKey.c_str(), -1);
    rsa = PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, NULL);

    const unsigned char *data = reinterpret_cast<const unsigned char *>(dataStr.c_str());
    const unsigned char *signature = reinterpret_cast<const unsigned char *>(signatureStr.c_str());

    int result = RSA_verify(NID_sha256, data, dataStr.size(), signature, signatureStr.size(), rsa);

    BIO_free_all(bio);
    RSA_free(rsa);

    return result == 1;
}