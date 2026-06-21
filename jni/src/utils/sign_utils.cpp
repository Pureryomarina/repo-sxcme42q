#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include "md5.h"

std::string md5(const std::string& input) {
    unsigned char digest[16];
    MD5_CTX md5c;
    MD5Init(&md5c);
    MD5Update(&md5c, reinterpret_cast<unsigned char*>(const_cast<char*>(input.c_str())), input.length());
    MD5Final(&md5c, digest);

    std::ostringstream oss;
    for (int i = 0; i < 16; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    }
    return oss.str();
}