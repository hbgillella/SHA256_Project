#include "sha256.h"
#include <iostream>
#include <fstream>
#include <sstream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
        return 1;
    }

    // Open the file specified by the command line argument
    std::ifstream file(argv[1]);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << argv[1] << std::endl;
        return 1;
    }

    // Read the file content into a string
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string text = buffer.str();

    // Compute the SHA-256 hash of the text
    std::string hash = sha256(text);
    std::cout << "SHA-256 Hash of the Book of Mark: " << hash << std::endl;

    return 0;
}