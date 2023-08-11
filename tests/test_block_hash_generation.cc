#include "blockchain/block.h"

int main(){
    bchain::Block block1;
    block1.add_trx({"pedram", "ali", 1.2312, "123"});
    block1.add_trx({"pedram", "john", 34.12, "345"});

    bchain::Block block2;
    block1.add_trx({"pedram", "ali", 1.2312, "123"});
    block1.add_trx({"pedram", "john", 34.12, "345"});

    if(block1() == block2()) return 1;
    return 0;
}