//
//  KeyStore.swift
//
//  Created by Supakonoha on 31/01/2020.
//
//  Copyright (c) 2020 Supakonoha
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import LocalAuthentication
import Security
import CryptoKit

/// Keychain errors
internal enum KeyStoreError: Error {
    /// Unexpected Error Accessing Data (Device with no secure enclave or error creating access control)
    case unexpectedAccessData
    case noKey
    case unhandledError(status: OSStatus)
}

/// Tools to create CryptoKit keys in device secure enclave
/// Requires Secure Enclave on device: iPhone 5s (or later), iPad Air (or later),
/// Mac computers that contain the T1 chip or the Apple T2 Security Chip,
/// Apple TV 4th generation (or later), Apple Watch Series 1 (or later),
/// HomePod
/// Minimum requirements: iOS 13.0, OSX 10.15, watchOS 6.0 or tvOS 13.0
public struct KeyStore {
    /// Tag used to identify the key on keychain
    private let tag = "securecommunications.keystore.p256.keyagreement.privatekey"

    /// Access Control for Secure Enclave
    private let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage],
        nil
    )

    /**
     Returns the Public CryptoKit key to be shared with Recipient

     - Throws: KeychainError or CryptoKitError errors

     - Returns: Data with raw representation of the public key.
     */
    public func getPublicKey() throws -> Data {
        try getKey().publicKey.rawRepresentation
    }

    /**
     Returns a symmetric key using CryptoKit key on keychain

     - Parameters:
        - recipientPublicKey: Raw Representation of Recipient P-256 puiblic key.
        - salt: The salt to use for key derivation.

     - Throws: An error of type KeychainError or an error occured while computing the shared secret

     - Returns: Symmetric key.
     */
    internal func getSymmetricKey(
        recipientPublicKey: Data,
        salt:Data) throws -> SymmetricKey {
        let publicKey = try P256
            .KeyAgreement
            .PublicKey(rawRepresentation: recipientPublicKey)

        return try getKey()
            .sharedSecretFromKeyAgreement(with: publicKey)
            .hkdfDerivedSymmetricKey(
                using: SHA512.self,
                salt: salt,
                sharedInfo: Data(),
                outputByteCount: 32)
    }

    /**
     Returns an existing CryptoKit key from keychain or creates a new one and stores it on keychain

     - Throws: KeychainError or CryptoKitError errors

     - Returns: CryptoKit key.
     */
    private func getKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard let key = try loadKey() else {
            guard SecureEnclave.isAvailable else {
                throw KeyStoreError.unexpectedAccessData
            }

            guard let accessControl = accessControl else {
                throw KeyStoreError.unexpectedAccessData
            };

            let authContext = LAContext()

            let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                accessControl: accessControl,
                authenticationContext: authContext)

            try saveKey(key: privateKey)

            return privateKey
        }

        return key
    }

    /**
     Stores a CryptoKit key in the keychain as a generic password.

     - Parameter key: CryptoKit key to store on keychaint.

     - Throws: KeychainError or CryptoKitError errors
     */
    private func saveKey(key: SecureEnclave.P256.KeyAgreement.PrivateKey) throws {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: tag,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked,
            kSecUseDataProtectionKeychain: true,
            kSecValueData: key.dataRepresentation] as [String: Any]

        SecItemDelete(query as CFDictionary)

        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            throw KeyStoreError.unhandledError(status: status)
        }
    }

    /**
     Reads a CryptoKit key from the keychain as a generic password.

     - Throws: KeychainError or CryptoKitError errors

     - Returns: CryptoKit key.
     */
    private func loadKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
        guard SecureEnclave.isAvailable else {
            throw KeyStoreError.unexpectedAccessData
        }

        let authContext = LAContext()

        let query = [kSecClass: kSecClassGenericPassword,
                     kSecAttrAccount: tag,
                     kSecUseDataProtectionKeychain: true,
                     kSecReturnData: true] as [String: Any]

        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
            case errSecItemNotFound:
                return nil
            case errSecSuccess:
                guard let data = item as? Data else {
                    return nil
                }

                return try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: data,
                    authenticationContext: authContext)
            case let status:
                throw KeyStoreError.unhandledError(status: status)
        }
    }
}
