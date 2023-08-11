#include "blockchain/block.h"

bchain::Block::Block(){
    this->_nonce = 0;
    this->_time = utils::getCurrentUTCTimestamp();
}

std::string bchain::Block::operator()() {
    std::stringstream string_stream;
    string_stream << _nonce << _time << _prev_hash;
    std::string src_str = string_stream.str();

    std::vector<unsigned char> hash(picosha2::k_digest_size);
    picosha2::hash256(src_str.begin(), src_str.end(), hash.begin(), hash.end());

    std::string hex_str = picosha2::bytes_to_hex_string(hash.begin(), hash.end());
    return hex_str;
}
