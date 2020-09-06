//
//  String+HMACTests.swift
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
@available(iOS 13.2, macOS 10.15, watchOS 6.1, tvOS 13.2, *)
final class StringHMACTests: XCTestCase {
    private var message = "This is a message"
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

    func test_Given_Data_When_ComputesAMessageAuthenticationCode_Then_MessageAuthenticationCode() {
        let messageAuthenticationCode = message.authenticationCodeHMAC(
            recipientPublicKey: publicKey,
            salt: salt)

        XCTAssertNotNil(messageAuthenticationCode)
    }

    func test_Given_Data_When_ComputesAMessageAuthenticationCodeAndValidatesOnRecipient_Then_True() throws {
        guard let messageAuthenticationCode = message.authenticationCodeHMAC(
                recipientPublicKey: publicKey,
                salt: salt) else {
            XCTFail("Message Authentication Code cannot be nil")
            return
        }

        let validation = try validate(string: messageAuthenticationCode)

        XCTAssertTrue(validation)
    }

    func test_Given_String_When_ComputesAMessageAuthenticationCodeBySenderAndValidates_Then_True() throws {
        guard let messageAuthenticationCode = try computes() else {
            XCTFail("Message Authentication Code cannot be nil")
            return
        }

        let validation = message.isValidAuthenticationCodeHMAC(
            authenticationCode: messageAuthenticationCode,
            senderPublicKey: publicKey,
            salt: salt)

        XCTAssertTrue(validation)
    }

    func test_Given_WrongSizeMessageAuthenticationCode_When_ValidatesOnRecipient_Then_False() throws {
        let validation = message.isValidAuthenticationCodeHMAC(
            authenticationCode: "",
            senderPublicKey: publicKey,
            salt: salt)

        XCTAssertFalse(validation)
    }

    func test_Given_Data_When_ComputesAMessageAuthenticationCodeBySenderAndValidatesWithWrongKeyOnRecipient_Then_False() throws {
        guard let messageAuthenticationCode = try computes() else {
            XCTFail("Message Authentication Code cannot be nil")
            return
        }

        let newPrivateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()

        let validation = message.isValidAuthenticationCodeHMAC(
            authenticationCode: messageAuthenticationCode,
            senderPublicKey: newPrivateKey.publicKey,
            salt: salt)

        XCTAssertFalse(validation)
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

    private func computes() throws -> String? {
        let symmetricKey = try getSymmetricKey()

        guard let data = message.data(using: .utf8) else {
            return nil
        }

        return Data(HMAC<SHA512>.authenticationCode(for:data, using: symmetricKey)).base64EncodedString()
    }

    private func validate(string: String) throws -> Bool {
        let symmetricKey = try getSymmetricKey()

        guard let dataMessage = message.data(using: .utf8) else {
            return false
        }

        guard let data = Data(base64Encoded: string) else {
            return false
        }

        return HMAC<SHA512>.isValidAuthenticationCode(data, authenticating: dataMessage, using: symmetricKey)
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
