#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iostream>
#include <windows.h>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    for (unsigned char b : bytes)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}

std::string hex_to_string(const std::string& hex) {
    std::string result;
    result.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        // wycinek 2 znaków hex
        std::string byteString = hex.substr(i, 2);
        // konwersja hex -> unsigned char
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        result.push_back(static_cast<char>(byte));
    }

    return result;
} 

std::vector<unsigned char> aes_decrypt(
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv)
{
    // IV musi mieæ 16 bajtów w AES-CBC
    if (iv.size() != 16) return {};

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0;
    int plaintext_len = 0;

    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), (int)ciphertext.size());
    plaintext_len = len;

    // Final + padding
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        // BAD PADDING albo z³y klucz/iv
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);
    return plaintext;
}


int main()
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::string decrypt_me = "b2c47b08e424e5d630d9a1a8c877c148af8a28f42c16245c5abb520960762afe9b0b42a514246037661d875718053c29b6112ed4ecded3c8b35018a7f016839dabd4102f06fc8459fca568394f740f80947343a9061c71e20991697d65be329e12a02e89a7ab1df48dd87630ad61587b2841ab59079bcbb703b20aa2cfc0bd291146af44da0c5854ef6bad3b6bc7c76cf845916652336dcf0969e765a3f42d0eca13c3414d695d955a6348354ec86de96712cb1d0dc80760fb1ea3a1348b0068b322737226d09315f05bdc8531aec67b0b4b20b18709e51a0e11d7f9deb078e2656bce176da9c9290150c9c6bc8b6b951109dd8804a2ba2467a622bb9b2e06735c1e432864c753f66b54d9710f2e6a9f229231c7376d24f7467b590c9d1cd540543c9f1c87f98de1c435a5e360db28c5a3d74b7b6a490f5285a1ebde477261af";
    int width, height, channels;
    unsigned char* data = stbi_load("Example1.png", &width, &height, &channels, 3);
    std::vector<std::vector<int>> bity;
    if (!data) {
        std::cout << "B³¹d wczytywania obrazu!\n";
        return -1;
    }
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {

            // Obliczamy indeks bazowy piksela
            int index = (y * width + x) * channels;
            std::vector<int> bit_kanal;
            bit_kanal.push_back(data[index]);
            bit_kanal.push_back(data[index+1]);
            bit_kanal.push_back(data[index+2]);
            bity.push_back(bit_kanal);
        }
    }
    int index = 0;
    std::string pre_seed = "";
    for (int wektor = bity.size() - 1; wektor >= 0; --wektor) {
        index++;
        if (index == width) {
            std::string iv_string = decrypt_me.substr(0, 32);
            std::string decrypt_string = decrypt_me.substr(32);
            std::vector<unsigned char> iv = hex_to_bytes(iv_string);
            std::vector<unsigned char> decrypt = hex_to_bytes(decrypt_string);
            index = 0;
            std::string key_str = sha256(pre_seed);
            //std::cout << "wartoœci wiersza: \n" << pre_seed << "\n" << "wartoœci hasza: " << key_str << "\n";
            std::vector<unsigned char> key = hex_to_bytes(key_str);
            decrypt_me = bytes_to_hex(aes_decrypt(decrypt, key, iv));
            //std::cout << "szyfrogram: ";
            pre_seed = "";
        }
        for (auto& piksel : bity[wektor]) {
            pre_seed += std::to_string(piksel);
        }
    }
    std::cout << decrypt_me;
    stbi_image_free(data);
    return 0;
}

