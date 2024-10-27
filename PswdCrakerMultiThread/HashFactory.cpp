//
// Created by davidlee on 10/23/24.
//

#include "HashFactory.h"

#include <fstream>
#include <sstream>

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

    std::string result = split(std::string(hash), '$')[3];

    return result;
}

std::unordered_map<std::string, std::unordered_map<std::string, std::string>> HashFactory::ReadShadowFile(const std::string &fileLocation) {
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> data;
std::string filePath = fileLocation;
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "File at " << filePath << " doesn't exist or could not be opened." << std::endl;
        return data;  // Return empty data if the file doesn't exist
    }

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream lineStream(line);
        std::string userName1, passwordHash1;
        std::string userName, passwordHash;

        // Read username and password hash from line, splitting by ':'
        if (std::getline(lineStream, userName1, ':') && std::getline(lineStream, passwordHash1, ':')) {
            userName = userName1;
            passwordHash = passwordHash1;

            // Store the password hash in the map
            data[userName]["password_hash"] = passwordHash;
        }
    }

    if (file.bad()) {
        std::cerr << "Error reading file at " << filePath << std::endl;
        data.clear();  // Clear data in case of reading error
    }

    file.close();
    return data;
}

std::string HashFactory::ReturnPasswordFromSha512Hash(const std::vector<std::string> &passwordHash) {

    if (passwordHash.size() < 4) {
        std::cerr << "Invalid hash format" << std::endl;
        return "";
    }

    std::string algorithm = passwordHash[1];
    algorithm = "$" + algorithm + "$";
    std::string salt = passwordHash[2];
    std::string true_hash = passwordHash[3];

    // Character set to use for brute-forcing
    std::string char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    std::string foundPassword;

    // Generate all possible combinations of characters up to length 4
    for (int length = 1; length <= 4; ++length) {
        std::vector<int> indexes(length, 0);

        // Loop through all combinations of the specified length
        while (true) {
            std::string passwordTemp;
            for (int idx : indexes) {
                passwordTemp += char_set[idx];
            }

            std::string test_hash = GenerateHash(passwordTemp, salt, algorithm);
            std::cout << "Trying password: " << passwordTemp << std::endl;

            // Check if hash matches
            if (test_hash == true_hash) {
                std::cout << "Password found: " << passwordTemp << std::endl;
                return passwordTemp;
            }

            // Generate the next combination
            int pos = length - 1;
            while (pos >= 0 && ++indexes[pos] == char_set.size()) {
                indexes[pos] = 0;
                --pos;
            }

            // Break if all combinations are exhausted
            if (pos < 0) break;
        }
    }

    return "Password crack failed";
}

std::string HashFactory::ReturnPasswordFromYesCryptHash(const std::vector<std::string> &passwordHash) {

}

std::vector<std::string> HashFactory::split(const std::string &str, char delimiter) {
    std::vector<std::string> tokens;
    std::istringstream stream(str);
    std::string token;

    while (std::getline(stream, token, delimiter)) {
        tokens.push_back(token);
    }

    return tokens;
}