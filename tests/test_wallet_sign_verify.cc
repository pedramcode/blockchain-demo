#include "blockchain/wallet.h"
#include <iostream>
#include <string>

int main(){
    bchain::Wallet wallet = bchain::Wallet::generate();
    std::string message = "Hello World!";
    std::string signature = wallet.sign_message(message);
    std::cout << "SIGNATURE : " << signature << std::endl;
    bool is_valid = wallet.verify_message(message, signature);
    if(!is_valid) return 1;
    is_valid = wallet.verify_message("Hello Pedram!", signature);
    if(is_valid) return 1;
    return 0;
}