//
// Created by davidlee on 10/23/24.
//

#include "HashFactory.h"

#include <fstream>
#include <sstream>
#include <thread>

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

std::vector<std::string> HashFactory::split(const std::string &str, char delimiter) {
    std::vector<std::string> tokens;
    std::istringstream stream(str);
    std::string token;

    while (std::getline(stream, token, delimiter)) {
        tokens.push_back(token);
    }

    return tokens;
}

std::string HashFactory::PasswordFinder(const std::vector<std::string> passwordHash, const std::string &firstCharSet, int id) {

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

                // Generate all possible combinations of characters up to length 4
            for (int length = 1; length <= 4; ++length) {
                // Initialize indexes, with the first index for `firstCharSet`
                std::vector<int> indexes(length, 0);

                // Loop through all combinations of the specified length
                while (true) {
                    std::string passwordTemp;

                    // Set the first character from `firstCharSet`
                    passwordTemp += firstCharSet[indexes[0]];

                    // Set the rest of the characters from `char_set`
                    for (int i = 1; i < length; ++i) {
                        passwordTemp += char_set[indexes[i]];
                    }
                    std::lock_guard<std::mutex> guard(mtx);
                    //std::cout << "Thread " << id << ": Trying password: " << passwordTemp << std::endl;

                    if (found) {
                        return "";
                    }
                    std::string test_hash = GenerateHash(passwordTemp, salt, algorithm);
                    if (test_hash == true_hash) {
                        found = true;
                        result = "Password found at Thread " + std::to_string(id) + " : " + passwordTemp + "\n";
                        return passwordTemp;
                    }

                    // Generate the next combination
                    int pos = length - 1;
                    while (pos >= 0) {
                        if (pos == 0 && ++indexes[pos] == firstCharSet.size()) {
                            indexes[pos] = 0;
                            --pos;
                        } else if (pos > 0 && ++indexes[pos] == char_set.size()) {
                            indexes[pos] = 0;
                            --pos;
                        } else {
                            break;
                        }
                    }

                    // Break if all combinations are exhausted
                    if (pos < 0) break;
                }
            }

            return "Password not found at Thread " + std::to_string(id);
}

std::string HashFactory::PasswordCrack1Threaded(std::vector<std::string> passwordHash1) {
    found = false;
    // Create multiple threads
    std::vector<std::thread> threads;
    threads.push_back(std::thread([this, &passwordHash1]() { this->PasswordFinder(passwordHash1, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*", 1); }));

    // Join threads to main thread
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    if (found) {
        std::cout << result << std::endl;
        return result;
    } else {
        return "Password crack failed";
    }
}

std::string HashFactory::PasswordCrack2Threaded(std::vector<std::string> passwordHash1) {
    found = false;
    // Create multiple threads
    std::vector<std::thread> threads;
    threads.push_back(std::thread([this, &passwordHash1]() { this->PasswordFinder(passwordHash1, "abcdefghijklmnopqrstuvwxyzABCDEFGHI", 1); }));
    threads.push_back(std::thread([this, &passwordHash1]() { this->PasswordFinder(passwordHash1, "JKLMNOPQRSTUVWXYZ0123456789!@#$%^&*", 2); }));

    // Join threads to main thread
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    if (found) {
        std::cout << result << std::endl;
        return result;
    } else {
        return "Password crack failed";
    }
}

std::string HashFactory::PasswordCrack3Threaded(std::vector<std::string> passwordHash1) {
    found = false;
    // Create multiple threads
    std::vector<std::thread> threads;
    threads.push_back(std::thread([this, &passwordHash1]() { this->PasswordFinder(passwordHash1, "abcdefghijklmnopqrstuv", 3); }));
    threads.push_back(std::thread([this, &passwordHash1]() { this->PasswordFinder(passwordHash1, "wxyzABCDEFGHIJKLMNOPQRST", 2); }));
    threads.push_back(std::thread([this, &passwordHash1]() { this->PasswordFinder(passwordHash1, "UVWXYZ0123456789!@#$%^&*", 1); }));

    // Join threads to main thread
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    if (found) {
        std::cout << result << std::endl;
        return result;
    } else {
        return "Password crack failed";
    }
}

std::string HashFactory::PasswordCrack4Threaded(std::vector<std::string> passwordHash1) {
    found = false;
    // Create multiple threads
    std::vector<std::thread> threads;
    threads.push_back(std::thread([this, &passwordHash1]() { this->PasswordFinder(passwordHash1, "abcdefghijklmnop", 1); }));
    threads.push_back(std::thread([this, &passwordHash1]() { this->PasswordFinder(passwordHash1, "qrstuvwxyzABCDEFGH", 2); }));
    threads.push_back(std::thread([this, &passwordHash1]() { this->PasswordFinder(passwordHash1, "IJKLMNOPQRSTUVWXYZ0", 3); }));
    threads.push_back(std::thread([this, &passwordHash1]() { this->PasswordFinder(passwordHash1, "123456789!@#$%^&*", 4); }));

    // Join threads to main thread
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    if (found) {
        std::cout << result << std::endl;
        return result;
    } else {
        return "Password crack failed";
    }
}