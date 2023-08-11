#pragma once

#include <string>

#include "utils"

namespace bchain {
    class Transaction{
    private:
        std::string _from;
        std::string _to;
        double _amount;
        time_t _time;
        std::string _sig;
    public:
        Transaction(const std::string& from, const std::string& to, double amount, const std::string& sig);

        [[nodiscard]] std::string get_from() const;
        [[nodiscard]] std::string get_to() const;
        [[nodiscard]] double get_amount() const;
        [[nodiscard]] time_t get_time() const;
        [[nodiscard]] std::string get_sig() const;
    };
}