#include "blockchain/utils"

time_t bchain::utils::getCurrentUTCTimestamp() {
    auto currentTime = std::chrono::system_clock::now();
    return std::chrono::system_clock::to_time_t(currentTime);
}