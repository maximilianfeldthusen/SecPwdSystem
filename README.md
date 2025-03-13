## Documentation

### SecPwdSystem

This C++ code implements a secure password management system using the Argon2 hashing algorithm. Let's break down the code step by step:

### Includes and Libraries

1. **`<iostream>`**: For input and output operations.
2. **`<string>`**: To use the string class.
3. **`<argon2.h>`**: The Argon2 library for password hashing.
4. **`<cstring>`**: For functions like `memset`.
5. **`<stdexcept>`**: For throwing exceptions.
6. **`<iomanip>`**: For manipulating output formats.
7. **`<sstream>`**: For converting bytes to hex.
8. **`<openssl/rand.h>`**: For generating secure random numbers.

### SecurePasswordManager Class

The `SecurePasswordManager` class is responsible for hashing passwords and validating them.

#### Constructor

- **`SecurePasswordManager()`**: Default constructor.

#### Public Methods

1. **`hashPassword(const std::string& password)`**:
   - Takes a plaintext password, generates a random salt, and hashes the password using Argon2.
   - Salt and hash are converted into hexadecimal strings and stored together, separated by a `$` symbol.
   - Handles errors by throwing exceptions if salt generation or hashing fails.

2. **`validatePassword(const std::string& password, const std::string& storedHash)`**:
   - Takes a plaintext password and a stored hash (which includes the salt).
   - Splits the stored hash into the salt and hash components.
   - Converts these hex strings back into byte arrays.
   - Validates the password by hashing it with the extracted salt and comparing it to the stored hash.
   - Returns `true` if the password is valid, otherwise `false`.

#### Private Methods

1. **`bytesToHex(const uint8_t* bytes, size_t length)`**:
   - Converts a byte array into a hexadecimal string.
   - Uses a string stream to format the output.

2. **`hexToBytes(const std::string& hex, uint8_t* bytes, size_t length)`**:
   - Converts a hexadecimal string back into a byte array.
   - Calls `hexCharToByte` to convert each character pair in the hex string to a byte.

3. **`hexCharToByte(char c)`**:
   - Converts a single hexadecimal character to its byte value.
   - Throws an exception if the character is invalid.

### Main Function

1. **Input Handling**:
   - The user is prompted to enter a password to hash.
   - The entered password is hashed using `hashPassword`.

2. **Password Validation**:
   - The user is prompted to enter a password for validation.
   - The entered password is validated against the previously hashed password using `validatePassword`.

3. **Error Handling**:
   - Catches and prints errors related to hashing and validation.

### Summary

This program securely manages passwords by:
- Using Argon2, a strong hashing algorithm designed for password hashing.
- Generating random salts to ensure that the same password results in different hashes.
- Storing hashes in a format that allows for easy retrieval and comparison.
- Providing a user-friendly command-line interface for interacting with the password manager.

![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white)
