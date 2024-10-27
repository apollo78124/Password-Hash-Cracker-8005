//
// Created by davidlee on 10/23/24.
//

#ifndef HASHFACTORY_H
#define HASHFACTORY_H
#include <string>
#include <crypt.h>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <unordered_map>
#include <vector>

class HashFactory {
public:
    std::string GenerateHash(const std::string& password, const std::string& salt, const std::string& algo);
    // Function placeholders for reading shadow files and returning passwords from hash
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> ReadShadowFile(const std::string &fileLocation);
    std::string ReturnPasswordFromSha512Hash(const std::vector<std::string> &passwordHash);
    std::string ReturnPasswordFromYesCryptHash(const std::vector<std::string> &passwordHash);
    std::vector<std::string> split(const std::string &str, char delimiter);
};



#endif //HASHFACTORY_H
