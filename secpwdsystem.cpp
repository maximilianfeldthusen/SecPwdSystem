
#include <iostream>
#include <string>
#include <argon2.h>
#include <cstring> // for memset
#include <stdexcept>
#include <iomanip> // for std::hex
#include <sstream> // for std::ostringstream
#include <openssl/rand.h> // Include OpenSSL for RAND_bytes

class SecurePasswordManager {
public:
    SecurePasswordManager() = default;

    // Hash a password using Argon2
    std::string hashPassword(const std::string& password) {
        const int HASH_LENGTH = 32; // Length of the hash in bytes
        const int SALT_LENGTH = 16; // Length of the salt in bytes
        uint8_t salt[SALT_LENGTH];
        uint8_t hash[HASH_LENGTH];

        // Generate random salt
        if (RAND_bytes(salt, SALT_LENGTH) != 1) {
            throw std::runtime_error("Failed to generate random salt");
        }

        // Hash the password
        int result = argon2i_hash_raw(2, 1 << 16, 1,
                                       reinterpret_cast<const uint8_t*>(password.data()), password.size(),
                                       salt, SALT_LENGTH,
                                       hash, HASH_LENGTH);

        if (result != ARGON2_OK) {
            throw std::runtime_error("Hashing failed");
        }

        // Convert the salt and hash to a hex string for storage
        std::string saltHex = bytesToHex(salt, SALT_LENGTH);
        std::string hashHex = bytesToHex(hash, HASH_LENGTH);
        
        return saltHex + "$" + hashHex; // Store salt and hash together
    }

    // Validate a password against a stored hash
    bool validatePassword(const std::string& password, const std::string& storedHash) {
        // Split the stored hash into salt and hash parts
        size_t separatorPos = storedHash.find('$');
        if (separatorPos == std::string::npos) {
            throw std::invalid_argument("Invalid stored hash format");
        }

        std::string saltHex = storedHash.substr(0, separatorPos);
        std::string hashHex = storedHash.substr(separatorPos + 1);

        const int HASH_LENGTH = 32;
        const int SALT_LENGTH = 16;
        uint8_t salt[SALT_LENGTH];
        uint8_t hash[HASH_LENGTH];
        
        // Convert hex to bytes
        hexToBytes(saltHex, salt, SALT_LENGTH);
        hexToBytes(hashHex, hash, HASH_LENGTH);

        // Validate the password
        int result = argon2i_verify(hash, HASH_LENGTH,
                                    reinterpret_cast<const uint8_t*>(password.data()), password.size(),
                                    salt, SALT_LENGTH);

        return result == ARGON2_OK;
    }

private:
    // Convert bytes to hex string
    std::string bytesToHex(const uint8_t* bytes, size_t length) {
        std::ostringstream oss;
        for (size_t i = 0; i < length; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
        }
        return oss.str();
    }

    // Convert hex string to bytes
    void hexToBytes(const std::string& hex, uint8_t* bytes, size_t length) {
        for (size_t i = 0; i < length; ++i) {
            bytes[i] = (hexCharToByte(hex[i * 2]) << 4) | hexCharToByte(hex[i * 2 + 1]);
        }
    }

    uint8_t hexCharToByte(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::invalid_argument("Invalid hex character");
    }
};

int main() {
    SecurePasswordManager spm;

    std::string password;
    std::cout << "Enter password to hash: ";
    std::getline(std::cin, password);

    try {
        // Hash the password
        std::string hashedPassword = spm.hashPassword(password);
        std::cout << "Hashed password: " << hashedPassword << std::endl;

        // Validate the password
        std::string passwordToCheck;
        std::cout << "Enter password to validate: ";
        std::getline(std::cin, passwordToCheck);

        if (spm.validatePassword(passwordToCheck, hashedPassword)) {
            std::cout << "Password is valid!" << std::endl;
        } else {
            std::cout << "Invalid password." << std::endl;
        }
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    } catch (const std::invalid_argument& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
