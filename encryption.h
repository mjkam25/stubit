#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdexcept>  // Ajoutez cette ligne en haut du fichier
#include <vector>
#include <array>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sodium.h>
#pragma once
#include <vector>
#include <string>

std::vector<uint8_t> AES_GCM_Decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);


// Clé de chiffrement dérivée d'un mot de passe (PBKDF2 + Salt)
std::vector<uint8_t> DeriveKey(const std::string& password, const std::vector<uint8_t>& salt) {
    std::vector<uint8_t> key(32); // AES-256
    PKCS5_PBKDF2_HMAC(
        password.c_str(), password.size(),
        salt.data(), salt.size(),
        100000,  // Itérations (augmenter pour renforcer)
        EVP_sha3_256(),
        key.size(), key.data()
    );
    return key;
}

// Chiffrement AES-256-GCM (authentifié)
std::vector<uint8_t> AES_GCM_Encrypt(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& key,
    std::vector<uint8_t>& iv
) {
    if (key.size() != 32 || iv.size() != 12) {
        throw std::runtime_error("AES-GCM nécessite une clé de 32 octets et un IV de 12 octets.");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> ciphertext(data.size() + 16); // +16 pour le tag
    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), data.size());
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);

    // Ajouter le tag d'authentification
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext.data() + data.size());
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

// Chiffrement ChaCha20-Poly1305 (alternatif, résistant aux attaques par cache)
std::vector<uint8_t> ChaCha20_Encrypt(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce
) {
    if (key.size() != 32 || nonce.size() != 12) {
        throw std::runtime_error("ChaCha20 nécessite une clé de 32 octets et un nonce de 12 octets.");
    }

    std::vector<uint8_t> ciphertext(data.size() + 16); // +16 pour le tag
    crypto_aead_chacha20poly1305_encrypt(
        ciphertext.data(), NULL,
        data.data(), data.size(),
        NULL, 0,  // Données supplémentaires (AAD)
        NULL, nonce.data(), key.data()
    );
    return ciphertext;
}

// Obfuscation polymorphique (XOR dynamique + permutations)
void PolymorphicObfuscate(std::vector<uint8_t>& data) {
    uint8_t xorKey = rand() % 256;
    for (auto& byte : data) {
        byte ^= xorKey;
        xorKey = (xorKey * 0x1F + 0x3D) % 256;  // Mutation aléatoire
    }
}

#endif // ENCRYPTION_H
