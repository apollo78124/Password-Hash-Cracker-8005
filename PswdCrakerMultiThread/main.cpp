#include <iostream>
#include <string>

#include "HashFactory.h"

//Sample file password: "b", "bc", "abb", "abba"
int main() {

    HashFactory factory1;

    // algorithm selection
    std::string algo;
    algo = "$1$";
    std::string salt = "eU2IX.qV";
    std::string password = "b";
    // Generate a random salt for hashing

    // Generate and display the hash
    std::string hashedPassword = factory1.GenerateHash(password, salt, algo);
    std::cout << "Generated hash: " << hashedPassword << std::endl;

    return 0;
}