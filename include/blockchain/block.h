#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <sstream>

#include <picosha2.h>

#include "transaction.h"
#include "utils"

namespace bchain {
    class Block {
    private:
        std::string _prev_hash;
        time_t _time;
        unsigned long long _nonce;
        std::vector<Transaction> _trxs;
    public:
        Block();
        std::string operator()();
    };
}