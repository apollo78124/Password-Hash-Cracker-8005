//
// Created by davidlee on 10/23/24.
//

#ifndef HASHFACTORY_H
#define HASHFACTORY_H
#include <atomic>
#include <string>
#include <crypt.h>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <unordered_map>
#include <vector>

class HashFactory {
public:
    std::mutex mtx;
    std::atomic<bool> found;
    std::string result;
    std::string GenerateHash(const std::string& password, const std::string& salt, const std::string& algo);
    // Function placeholders for reading shadow files and returning passwords from hash
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> ReadShadowFile(const std::string &fileLocation);
    std::string ReturnPasswordFromSha512Hash(const std::vector<std::string> &passwordHash);
    std::string ReturnPasswordFromYesCryptHash(const std::vector<std::string> &passwordHash);
    std::vector<std::string> split(const std::string &str, char delimiter);
    std::string PasswordFinder(std::vector<std::string> passwordHash, const std::string &firstCharSet, int id);
    std::string PasswordCrack1Threaded(std::vector<std::string> passwordHash);
    std::string PasswordCrack2Threaded(std::vector<std::string> passwordHash);
    std::string PasswordCrack3Threaded(std::vector<std::string> passwordHash);
    std::string PasswordCrack4Threaded(std::vector<std::string> passwordHash);
};



#endif //HASHFACTORY_H
