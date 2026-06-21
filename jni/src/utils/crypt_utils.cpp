#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <sstream>
#include <iomanip>

// RC4 密钥调度算法 (KSA)
void rc4_ksa(const std::string& key, std::vector<unsigned char>& S) {
    int key_length = key.size();
    for (int i = 0; i < 256; ++i) {
        S[i] = i;
    }

    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + S[i] + key[i % key_length]) % 256;
        std::swap(S[i], S[j]);
    }
}

// RC4 伪随机生成算法 (PRGA)
void rc4_prga(std::vector<unsigned char>& S, const std::string& data, std::string& output) {
    int i = 0, j = 0;
    for (size_t n = 0; n < data.size(); ++n) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        unsigned char K = S[(S[i] + S[j]) % 256];
        output.push_back(data[n] ^ K);
    }
}

// 将二进制数据转换为十六进制字符串
std::string to_hex_string(const std::string& data) {
    std::ostringstream oss;
    for (unsigned char c : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return oss.str();
}

// 将十六进制字符串转换为二进制数据
std::string from_hex_string(const std::string& hex) {
    std::string output;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
        output.push_back(byte);
    }
    return output;
}

// RC4 加密/解密
std::string rc4(const std::string& data, const std::string& key) {
    std::vector<unsigned char> S(256);
    rc4_ksa(key, S);

    std::string output;
    rc4_prga(S, data, output);

    return output;
} 