#include <iostream>
#include <string>
#include <chrono>
#include <ranges>

#include "HashFactory.h"

//Sample file password: "b", "bc", "abb", "abba"

int main() {
    std::cout << "Password Hash Crack" << std::endl;

    std::string username = "sha512length1user";
    std::cout << "Enter UserName:\n";
    std::getline(std::cin, username);

    std::string filePath1;
    std::cout << "Enter shadow file location:\n";
    std::getline(std::cin, filePath1);

    HashFactory hash_factory;
    // Start time
    auto start_time = std::chrono::high_resolution_clock::now();

    std::string fileLocation = (filePath1.empty()) ? "../etc.shadow.sample.txt" : filePath1;
    auto shadowFile = hash_factory.ReadShadowFile(fileLocation);

    auto userInterest = shadowFile[username];
    std::string passwordHashStr = userInterest["password_hash"];
    std::vector<std::string> passwordHash = hash_factory.split(passwordHashStr, '$');

    std::string crackedPassword;

    if (passwordHash.size() == 4) {
        if (passwordHash[1] == "1") {
            crackedPassword = hash_factory.ReturnPasswordFromSha512Hash(passwordHash);
            std::cout << "MD5 Password Crack Result: " << crackedPassword << std::endl;
        }
        else if (passwordHash[1] == "2b" || passwordHash[1] == "2y") {
            crackedPassword = hash_factory.ReturnPasswordFromSha512Hash(passwordHash);
            std::cout << "Blowfish Password Crack Result: " << crackedPassword << std::endl;
        }
        else if (passwordHash[1] == "5") {
            crackedPassword = hash_factory.ReturnPasswordFromSha512Hash(passwordHash);
            std::cout << "SHA-256 Password Crack Result: " << crackedPassword << std::endl;
        }
        else if (passwordHash[1] == "6") {
            crackedPassword = hash_factory.ReturnPasswordFromSha512Hash(passwordHash);
            std::cout << "SHA-512 Password Crack Result: " << crackedPassword << std::endl;
        }
    } else if (passwordHash.size() == 5) {
        if (passwordHash[1] == "y") {
            crackedPassword = hash_factory.ReturnPasswordFromYesCryptHash(passwordHash);
            std::cout << "Yescrypt Password Crack Result: " << crackedPassword << std::endl;
        }
    }

    // End time
    auto end_time = std::chrono::high_resolution_clock::now();
    auto execution_time = std::chrono::duration<double>(end_time - start_time).count();
    std::cout << "Execution Time: " << execution_time << " seconds" << std::endl;

    return 0;
}

