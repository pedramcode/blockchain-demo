#pragma once

#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <iterator>
#include <openssl/bio.h>
#include <openssl/evp.h>

namespace bchain::utils{
    static const std::string base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    std::string base58_encode(const unsigned char *input, size_t length);
    std::string base58_decode(const std::string &input);

    std::string base64_encode(const unsigned char *input, size_t length);
    std::string base64_decode(const std::string &input);
}