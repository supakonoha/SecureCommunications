//
//  Data+AESTests.swift
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

import XCTest
import CryptoKit
@testable import SecureCommunications

/// These tests must be run on device, not in simulator. Secure Enclave is not supported on simulator.
/// To run these tests on MacOS you need keychain sharing entitlement
final class DataAESTests: XCTestCase {
    private var message = "This is top secret".data(using: .utf8)!
    private var salt = "Here's some salt data to use for testing".data(using: .utf8)!
    private var privateKey = try! SecureEnclave.P256.KeyAgreement.PrivateKey()
    private var publicKey: Data!

    override func setUp() {
        deleteKey()
        publicKey = privateKey.publicKey.rawRepresentation
    }

    override func tearDown() {
        deleteKey()
    }

    func test_Given_Data_When_EncryptWithNoValidKey_Then_Nil() {
        XCTAssertNil(message.sealAES(publicKey: Data(), salt: salt))
    }

    func test_Given_Data_When_Encrypt_Then_EncryptedValue() {
        let encryptedMessage = message.sealAES(
            publicKey: publicKey,
            salt: salt)

        XCTAssertNotNil(encryptedMessage)
        XCTAssertNotEqual(message, encryptedMessage)
    }

    func test_Given_Data_When_EncryptAndDecrypt_Then_OriginalValue() throws {
        guard let encryptedMessage = message.sealAES(
            publicKey: publicKey,
            salt: salt) else {
                XCTFail("Encrypted message cannot be nil")
                return
        }

        guard let decryptedMessage = encryptedMessage.openAES(
            publicKey: publicKey,
            salt: salt) else {
                XCTFail("Decrypted message cannot be nil")
                return
        }

        XCTAssertEqual(message, decryptedMessage)
    }

    func test_Given_Data_When_EncryptAndDecryptOnRecipient_Then_OriginalValue() throws {
        guard let encryptedMessage = message.sealAES(
            publicKey: publicKey,
            salt: salt) else {
                XCTFail("Encrypted message cannot be nil")
                return
        }

        let decryptedMessage = try decrypt(data: encryptedMessage)

        XCTAssertEqual(message, decryptedMessage)
    }

    func test_Given_String_When_EncryptBySenderAndDecrypted_Then_OriginalValue() throws {
        guard let encryptedMessage = try encryptedMessage() else {
            XCTFail("Encrypted message cannot be nil")
            return
        }

        guard let decryptedMessage = encryptedMessage.openAES(
            publicKey: publicKey,
            salt: salt) else {
                XCTFail("Decrypted message cannot be nil")
                return
        }

        XCTAssertEqual(message, decryptedMessage)
    }

    func test_Given_WrongSizeMessage_When_DecryptOnRecipient_Then_Nil() throws {
        let decryptedMessage = Data().openAES(
            publicKey: publicKey,
            salt: salt)

        XCTAssertNil(decryptedMessage)
    }

    func test_Given_Data_When_EncryptBySenderAndDecryptWithWrongKeyOnRecipient_Then_Nil() throws {
        guard let encryptedMessage = try encryptedMessage() else {
            XCTFail("Encrypted message cannot be nil")
            return
        }

        let newPrivateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()

        let decryptedMessage = encryptedMessage.openAES(
            publicKey: newPrivateKey.publicKey.rawRepresentation,
            salt: salt)

        XCTAssertNil(decryptedMessage)
    }

    private func getSymmetricKey() throws -> SymmetricKey {
        let publicKey = try P256
            .KeyAgreement
            .PublicKey(rawRepresentation: KeyStore().getPublicKey())

        return try privateKey
            .sharedSecretFromKeyAgreement(with: publicKey)
            .hkdfDerivedSymmetricKey(
                using: SHA512.self,
                salt: salt,
                sharedInfo: Data(),
                outputByteCount: 32)
    }

    private func encryptedMessage() throws -> Data? {
        let symmetricKey = try getSymmetricKey()

        return try AES.GCM.seal(message, using: symmetricKey).combined
    }

    private func decrypt(data: Data) throws -> Data {
        let symmetricKey = try getSymmetricKey()

        let sealedBox = try AES.GCM.SealedBox(combined: data)

        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }

    private func deleteKey() {
        // Delete key in case it exits
        let tag = "securecommunications.keystore.p256.keyagreement.privatekey"

        let query = [kSecClass: kSecClassGenericPassword,
                     kSecUseDataProtectionKeychain: true,
                     kSecAttrAccount: tag] as [String: Any]

        SecItemDelete(query as CFDictionary)
    }
}
