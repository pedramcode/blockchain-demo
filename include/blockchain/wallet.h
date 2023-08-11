#pragma once

#include <string>
#include <stdexcept>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "utils"

namespace bchain {
    class Wallet{
    private:
        std::string _pub;
        std::string _prv;
        Wallet();
        explicit Wallet(const std::string& private_key);
    public:
        static Wallet generate();
        static Wallet from_prv(const std::string& private_key);
        std::string sign_message(const std::string &data);
        bool verify_message(const std::string &data, const std::string &sign);
    };
}