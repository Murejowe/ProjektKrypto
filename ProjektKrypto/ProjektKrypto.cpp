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

std::vector<unsigned char> iv(){
    std::vector<unsigned char> iv(16);
    // Generowanie losowego IV
    RAND_bytes(iv.data(), 16);
    return iv;
}

std::vector<unsigned char> aes_encrypt(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

    // miejsce: IV + ciphertext + padding
    std::vector<unsigned char> ciphertext(
        iv.size() + plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc())
    );

    // wpisujemy IV na początek
    std::copy(iv.begin(), iv.end(), ciphertext.begin());

    int len = 0;
    int ciphertext_len = 0;

    // szyfrowanie danych RAW (bez stringa!)
    EVP_EncryptUpdate(
        ctx,
        ciphertext.data() + iv.size(),   // pomiń IV
        &len,
        plaintext.data(),
        plaintext.size()
    );
    ciphertext_len = len;

    // padding
    EVP_EncryptFinal_ex(
        ctx,
        ciphertext.data() + iv.size() + ciphertext_len,
        &len
    );
    ciphertext_len += len;

    // docięcie rzeczywistego rozmiaru
    ciphertext.resize(iv.size() + ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}


int main()
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::string input = "kochamdisa";
    std::vector<unsigned char> encrypt_me(input.begin(), input.end());
    int width, height, channels;
    unsigned char* data = stbi_load("Example1.png", &width, &height, &channels, 3);
    std::vector<std::vector<int>> bity;
    if (!data) {
        std::cout << "Błąd wczytywania obrazu!\n";
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
    int wiersz = 0;
    std::string pre_seed = "";
    for (auto& wektor : bity) {
        index++;
        if (index == width) {
            index = 0;
            wiersz++;
            std::string key_str = sha256(pre_seed);
            //std::cout << "wartości wiersza: \n" << pre_seed << "\n" << "wartości hasza: " << key_str << "\n";
            std::vector<unsigned char> key = hex_to_bytes(key_str);
            encrypt_me = aes_encrypt(encrypt_me, key, iv());
            //std::cout << "szyfrogram: ";
            std::cout << bytes_to_hex(encrypt_me) << "\n\n";
            pre_seed = "";
        }
        for (auto& piksel : wektor) {
            pre_seed += std::to_string(piksel);
        }
    }
    std::cout << bytes_to_hex(encrypt_me);
    stbi_image_free(data);
    return 0;
}

