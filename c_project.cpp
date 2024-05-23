#include <iostream>
#include <string>
#include <cctype>

// Function to encrypt a message using the Caesar cipher
std::string encryptCaesarCipher(const std::string& message, int shift) {
    std::string encryptedMessage = "";
    for (char c : message) {
        if (isalpha(c)) {
            char shiftedChar = (isupper(c)) ? 'A' + ((c - 'A' + shift) % 26) : 'a' + ((c - 'a' + shift) % 26);
            encryptedMessage += shiftedChar;
        } else {
            encryptedMessage += c;
        }
    }
    return encryptedMessage;
}

// Function to decrypt a message using the Caesar cipher
std::string decryptCaesarCipher(const std::string& encryptedMessage, int shift) {
    return encryptCaesarCipher(encryptedMessage, 26 - shift); // Decryption is essentially shifting backwards
}

// Function to encrypt a message using the Vigenère cipher
std::string encryptVigenereCipher(const std::string& message, const std::string& key) {
    std::string encryptedMessage = "";
    int keyIndex = 0;
    for (char c : message) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            encryptedMessage += ((c - base + key[keyIndex] - 'A') % 26) + base;
            keyIndex = (keyIndex + 1) % key.length();
        } else {
            encryptedMessage += c;
        }
    }
    return encryptedMessage;
}

// Function to decrypt a message using the Vigenère cipher
std::string decryptVigenereCipher(const std::string& encryptedMessage, const std::string& key) {
    std::string decryptedMessage = "";
    int keyIndex = 0;
    for (char c : encryptedMessage) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            decryptedMessage += ((c - key[keyIndex] + 26) % 26) + base;
            keyIndex = (keyIndex + 1) % key.length();
        } else {
            decryptedMessage += c;
        }
    }
    return decryptedMessage;
}

// Function to encrypt a message using the Atbash cipher
std::string encryptAtbashCipher(const std::string& message) {
    std::string encryptedMessage = "";
    for (char c : message) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            encryptedMessage += ('Z' - (c - base)) + base;
        } else {
            encryptedMessage += c;
        }
    }
    return encryptedMessage;
}

// Function to decrypt a message using the Atbash cipher (same as encryption)
std::string decryptAtbashCipher(const std::string& encryptedMessage) {
    return encryptAtbashCipher(encryptedMessage);
}

int main() {
    std::string message, key;
    int shift;

    std::cout << "Enter a message: ";
    std::getline(std::cin, message);

    std::cout << "Enter the shift value for the Caesar cipher: ";
    std::cin >> shift;
    std::cin.ignore(); // Ignore the newline character left in the input buffer

    std::cout << "Enter the key for the Vigenère cipher: ";
    std::getline(std::cin, key);

    // Encrypt using Caesar cipher
    std::string encryptedCaesar = encryptCaesarCipher(message, shift);
    std::cout << "Encrypted message (Caesar cipher): " << encryptedCaesar << std::endl;

    // Decrypt using Caesar cipher
    std::string decryptedCaesar = decryptCaesarCipher(encryptedCaesar, shift);
    std::cout << "Decrypted message (Caesar cipher): " << decryptedCaesar << std::endl;

    // Encrypt using Vigenère cipher
    std::string encryptedVigenere = encryptVigenereCipher(message, key);
    std::cout << "Encrypted message (Vigenère cipher): " << encryptedVigenere << std::endl;

    // Decrypt using Vigenère cipher
    std::string decryptedVigenere = decryptVigenereCipher(encryptedVigenere, key);
    std::cout << "Decrypted message (Vigenère cipher): " << decryptedVigenere << std::endl;

    // Encrypt using Atbash cipher
    std::string encryptedAtbash = encryptAtbashCipher(message);
    std::cout << "Encrypted message (Atbash cipher): " << encryptedAtbash << std::endl;

    // Decrypt using Atbash cipher
    std::string decryptedAtbash = decryptAtbashCipher(encryptedAtbash);
    std::cout << "Decrypted message (Atbash cipher): " << decryptedAtbash << std::endl;

    return 0;
}

