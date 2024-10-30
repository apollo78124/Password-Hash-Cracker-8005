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

    std::string fileLocation = (filePath1.empty()) ? "../etc.shadow.sample.txt" : filePath1;
    auto shadowFile = hash_factory.ReadShadowFile(fileLocation);

    auto userInterest = shadowFile[username];
    std::string passwordHashStr = userInterest["password_hash"];
    std::vector<std::string> passwordHash = hash_factory.split(passwordHashStr, '$');

    std::string crackedPassword;

    std::string hashingAlgorithm;

    if (passwordHash.size() == 4) {
        if (passwordHash[1] == "1") {
            hashingAlgorithm = "MD5";
        }
        else if (passwordHash[1] == "2b" || passwordHash[1] == "2y") {
            hashingAlgorithm = "Blowfish";
        }
        else if (passwordHash[1] == "5") {
            hashingAlgorithm = "SHA-256";
        }
        else if (passwordHash[1] == "6") {
            hashingAlgorithm = "SHA-512";
        }

            // Start time
            auto start_time = std::chrono::high_resolution_clock::now();
            crackedPassword = hash_factory.PasswordCrack1Threaded(passwordHash);
            std::cout << hashingAlgorithm + " 1 Threaded Password Crack Result: " << crackedPassword << std::endl;
            // End time
            auto end_time = std::chrono::high_resolution_clock::now();
            auto execution_time1 = std::chrono::duration<double>(end_time - start_time).count();

            // Start time
            start_time = std::chrono::high_resolution_clock::now();
            crackedPassword = hash_factory.PasswordCrack2Threaded(passwordHash);
            std::cout << hashingAlgorithm + " 2 Threaded Password Crack Result: " << crackedPassword << std::endl;
            // End time
            end_time = std::chrono::high_resolution_clock::now();
            auto execution_time2 = std::chrono::duration<double>(end_time - start_time).count();

            // Start time
            start_time = std::chrono::high_resolution_clock::now();
            crackedPassword = hash_factory.PasswordCrack3Threaded(passwordHash);
            std::cout << hashingAlgorithm + " 3 Threaded Password Crack Result: " << crackedPassword << std::endl;
            // End time
            end_time = std::chrono::high_resolution_clock::now();
            auto execution_time3 = std::chrono::duration<double>(end_time - start_time).count();

            // Start time
            start_time = std::chrono::high_resolution_clock::now();
            crackedPassword = hash_factory.PasswordCrack4Threaded(passwordHash);
            std::cout << hashingAlgorithm + " 4 Threaded Password Crack Result: " << crackedPassword << std::endl;
            // End time
            end_time = std::chrono::high_resolution_clock::now();
            auto execution_time4 = std::chrono::duration<double>(end_time - start_time).count();

            std::cout << "1 Threaded Execution Time: " << execution_time1 << " seconds" << std::endl;
            std::cout << "2 Threaded Execution Time: " << execution_time2 << " seconds" << std::endl;
            std::cout << "3 Threaded Execution Time: " << execution_time3 << " seconds" << std::endl;
            std::cout << "4 Threaded Execution Time: " << execution_time4 << " seconds" << std::endl;
    } else if (passwordHash.size() == 5) {
        if (passwordHash[1] == "y") {
            crackedPassword = hash_factory.ReturnPasswordFromYesCryptHash(passwordHash);
            std::cout << "Yescrypt Password Crack Result: " << crackedPassword << std::endl;
        }
    }

    return 0;
}

