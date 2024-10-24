//
// Created by davidlee on 10/23/24.
//

#include "HashFactory.h"

std::string HashFactory::GenerateHash(const std::string& password, const std::string& salt, const std::string& algo) {
    // The crypt method generates a hashed password using a salt
    struct crypt_data data;
    data.initialized = 0;

    // Concatenate "$6$" for SHA-512 algorithm identifier before the salt
    std::string saltPrefix = algo + salt;

    // Generate the hash
    char* hash = crypt_r(password.c_str(), saltPrefix.c_str(), &data);
    if (hash == nullptr) {
        std::cerr << "Error generating hash" << std::endl;
        exit(1);
    }

    return std::string(hash);
}