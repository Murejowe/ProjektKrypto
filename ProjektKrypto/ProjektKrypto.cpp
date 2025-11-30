#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#include <iostream>
#include <windows.h>
#include <vector>

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
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
    for (auto& wektor : bity) {
        for (auto& piksel : wektor) {
            std::cout << piksel << " ";
        }
        std::cout << "\n";
    }
    stbi_image_free(data);
    return 0;
}

