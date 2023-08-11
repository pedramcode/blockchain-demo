#include "blockchain/transaction.h"

bchain::Transaction::Transaction(const std::string &from, const std::string &to, double amount,
                                 const std::string &sig) {
    _time = utils::getCurrentUTCTimestamp();
    _from = from;
    _to = to;
    _amount = amount;
    _sig = sig;
}

std::string bchain::Transaction::get_from() const {
    return _from;
}

std::string bchain::Transaction::get_to() const {
    return _to;
}

double bchain::Transaction::get_amount() const {
    return _amount;
}

time_t bchain::Transaction::get_time() const {
    return _time;
}

std::string bchain::Transaction::get_sig() const {
    return _sig;
}
