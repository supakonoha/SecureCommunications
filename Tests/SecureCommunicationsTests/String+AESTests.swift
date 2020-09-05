//
//  String+AESTests.swift
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
final class StringAESTests: XCTestCase {
    private var message = "This is top secret"
    private var salt = "Here's some salt data to use for testing"
    private var privateKey = try! SecureEnclave.P256.KeyAgreement.PrivateKey()
    private var publicKey: P256.KeyAgreement.PublicKey!

    override func setUp() {
        deleteKey()
        publicKey = privateKey.publicKey
    }

    override func tearDown() {
        deleteKey()
    }

    func test_Given_String_When_Encrypt_Then_EncryptedValue() {
        let encryptedMessage = message.sealAES(
            recipientPublicKey: publicKey,
            salt: salt)

        XCTAssertNotNil(encryptedMessage)
        XCTAssertNotEqual(message, encryptedMessage)
    }

    func test_Given_String_When_EncryptAndDecryptOnRecipient_Then_OriginalValue() throws {
        guard let encryptedMessage = message.sealAES(
                recipientPublicKey: publicKey,
                salt: salt) else {
            XCTFail("Encrypted message cannot be nil")
            return
        }

        let decryptedMessage = try decrypt(string: encryptedMessage)

        XCTAssertEqual(message, decryptedMessage)
    }

    func test_Given_String_When_EncryptBySenderAndDecrypted_Then_OriginalValue() throws {
        guard let encryptedMessage = try encryptedMessage() else {
            XCTFail("Encrypted message cannot be nil")
            return
        }

        guard let decryptedMessage = encryptedMessage.openAES(
                senderPublicKey: publicKey,
                salt: salt) else {
            XCTFail("Decrypted message cannot be nil")
            return
        }

        XCTAssertEqual(message, decryptedMessage)
    }

    func test_Given_WrongSizeMessage_When_DecryptOnRecipient_Then_Nil() {
        let decryptedMessage = "".openAES(
            senderPublicKey: publicKey,
            salt: salt)

        XCTAssertNil(decryptedMessage)
    }

    func test_Given_String_When_EncryptBySenderAndDecryptWithWrongKeyOnRecipient_Then_Nil() throws {
        guard let encryptedMessage = try encryptedMessage() else {
            XCTFail("Encrypted message cannot be nil")
            return
        }

        let newPrivateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()

        let decryptedMessage = encryptedMessage.openAES(
            senderPublicKey: newPrivateKey.publicKey,
            salt: salt)

        XCTAssertNil(decryptedMessage)
    }

    private func getSymmetricKey() throws -> SymmetricKey {
        return try privateKey
            .sharedSecretFromKeyAgreement(with: try KeyStore().publicKey())
            .hkdfDerivedSymmetricKey(
                using: SHA512.self,
                salt: salt.data(using: .utf8)!,
                sharedInfo: Data(),
                outputByteCount: 32)
    }

    private func encryptedMessage() throws -> String? {
        let symmetricKey = try getSymmetricKey()

        guard let data = message.data(using: .utf8) else {
            return nil
        }

        return try AES.GCM.seal(data, using: symmetricKey).combined?.base64EncodedString()
    }

    private func decrypt(string: String) throws -> String? {
        let symmetricKey = try getSymmetricKey()

        guard let data = Data(base64Encoded: string) else {
            return nil
        }

        let sealedBox = try AES.GCM.SealedBox(combined: data)

        return try String(data: AES.GCM.open(sealedBox, using: symmetricKey), encoding: .utf8)
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
