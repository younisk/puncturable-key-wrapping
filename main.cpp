#include <iostream>
#include <pkw/pprf_aead_pkw.h>

int main() {
    std::cout << "Hello, World!" << std::endl;
    PPRF_AEAD_PKW pkw(128, 128);
    std::string mystr = "mykey";
    std::vector<unsigned char> header(0);
    std::vector<unsigned char> key(mystr.begin(), mystr.end());
    pkw.wrap(10, header, key);
    return 0;
}