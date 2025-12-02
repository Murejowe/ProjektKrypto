//#define STB_IMAGE_IMPLEMENTATION
//#include "stb_image.h"
//#include <openssl/evp.h>
//#include <openssl/sha.h>
//#include <openssl/rand.h>
//#include <iostream>
//#include <windows.h>
//#include <vector>
//#include <string>
//#include <iomanip>
//#include <sstream>
//
//std::string sha256(const std::string& input) {
//    unsigned char hash[SHA256_DIGEST_LENGTH];
//    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
//
//    std::stringstream ss;
//    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
//        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
//    return ss.str();
//}
//
//std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
//    std::vector<unsigned char> bytes;
//    bytes.reserve(hex.size() / 2);
//    for (size_t i = 0; i < hex.size(); i += 2) {
//        std::string byteString = hex.substr(i, 2);
//        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
//        bytes.push_back(byte);
//    }
//    return bytes;
//}
//
//std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
//    std::stringstream ss;
//    for (unsigned char b : bytes)
//        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
//    return ss.str();
//}
//
//std::string hex_to_string(const std::string& hex) {
//    std::string result;
//    result.reserve(hex.size() / 2);
//
//    for (size_t i = 0; i < hex.size(); i += 2) {
//        // wycinek 2 znaków hex
//        std::string byteString = hex.substr(i, 2);
//        // konwersja hex -> unsigned char
//        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
//        result.push_back(static_cast<char>(byte));
//    }
//
//    return result;
//} 
//
//std::vector<unsigned char> aes_decrypt(
//    const std::vector<unsigned char>& ciphertext_with_iv,
//    const std::vector<unsigned char>& key)
//{
//    const int iv_size = 16;
//    if (ciphertext_with_iv.size() <= iv_size) return {}; // za krótki szyfrogram
//
//    std::vector<unsigned char> iv(ciphertext_with_iv.begin(), ciphertext_with_iv.begin() + iv_size);
//
//    const unsigned char* ciphertext = ciphertext_with_iv.data() + iv_size;
//    int ciphertext_len = static_cast<int>(ciphertext_with_iv.size() - iv_size);
//
//    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
//    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
//
//    std::vector<unsigned char> plaintext(ciphertext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
//    int len = 0;
//    int plaintext_len = 0;
//
//    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len);
//    plaintext_len = len;
//
//    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
//    plaintext_len += len;
//
//    EVP_CIPHER_CTX_free(ctx);
//
//    plaintext.resize(plaintext_len);
//    return plaintext;
//}
//
//
//int main()
//{
//    SetConsoleOutputCP(CP_UTF8);
//    SetConsoleCP(CP_UTF8);
//    std::string input = "eb31f0e454867b683021a8dbefd8e4d2690af2bc771e1fe25ba252bd381f8c35c605c96cc1d9684fb1f90af35cc8e18c9fc574253155efde8c5b1866d3bca7c0ac72bd66a9f003a77d05675013f6ad707674ffe73c30c72be488eac4c2801f40ac4a9ad426a7622764e0e2e76d4149c6a550383006c0386601149acb0b97d545753ca226f11c37c3833d26a076e8d79e8de264f6992771ac24b24e5fe5de2f88169399544905f7eefb91ea6a5ee9f160514105ad703bfd5f9f6b42ab10ae7919a0d6b9e5afae8c09e4e33b6af471b57f3d3d4a44896532d9fa16c605f7b5d80a196462a41167f0342d448828efe127c6a54b2e5f2a2f53d53c4383274c32a5a5b9410ce6f81ab209b0100904ac4a5bff4bb696f6fc1a06489ad9d00c77c3910be501abaa1d108cbe1b53035d8d7d1fd96efa3099260ea164a7d0735d8970b7d9";
//    std::vector<unsigned char> encrypt_me(input.begin(), input.end());
//    int width, height, channels;
//    unsigned char* data = stbi_load("Example1.png", &width, &height, &channels, 3);
//    std::vector<std::vector<int>> bity;
//    if (!data) {
//        std::cout << "B³¹d wczytywania obrazu!\n";
//        return -1;
//    }
//    for (int y = 0; y < height; y++) {
//        for (int x = 0; x < width; x++) {
//
//            // Obliczamy indeks bazowy piksela
//            int index = (y * width + x) * channels;
//            std::vector<int> bit_kanal;
//            bit_kanal.push_back(data[index]);
//            bit_kanal.push_back(data[index+1]);
//            bit_kanal.push_back(data[index+2]);
//            bity.push_back(bit_kanal);
//        }
//    }
//    int index = 0;
//    int wiersz = 0;
//    std::string pre_seed = "";
//    for (int wektor = bity.size() - 1; wektor >= 0; --wektor) {
//        index++;
//        if (index == width) {
//            index = 0;
//            wiersz++;
//            std::string key_str = sha256(pre_seed);
//            //std::cout << "wartoœci wiersza: \n" << pre_seed << "\n" << "wartoœci hasza: " << key_str << "\n";
//            std::vector<unsigned char> key = hex_to_bytes(key_str);
//            encrypt_me = aes_decrypt(encrypt_me, key);
//            //std::cout << "szyfrogram: ";
//            std::cout << bytes_to_hex(encrypt_me) << "\n\n";
//            pre_seed = "";
//        }
//        for (auto& piksel : bity[wektor]) {
//            pre_seed += std::to_string(piksel);
//        }
//    }
//    stbi_image_free(data);
//    return 0;
//}
//
