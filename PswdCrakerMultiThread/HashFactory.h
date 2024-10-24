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

class HashFactory {
public:
    std::string GenerateHash(const std::string& password, const std::string& salt, const std::string& algo);
};



#endif //HASHFACTORY_H
