//
//  KeyStoreTests.swift
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
final class KeyStoreTests: XCTestCase {
    private var salt = "Here's some salt data to use for testing".data(using: .utf8)!
    private var privateKey = try! SecureEnclave.P256.KeyAgreement.PrivateKey()

    override func setUp() {
        deleteKey()
    }

    override func tearDown() {
        deleteKey()
    }

    func test_Given_FirstLaunch_When_GenerateSymmetricKey_Then_SymmetricKeyNotNull() {
        XCTAssertNotNil(try KeyStore().getSymmetricKey(recipientPublicKey: privateKey.publicKey.rawRepresentation, salt: salt))
    }

    func test_Given_FirstLaunch_When_GenerateSymmetricKey_Then_SymmetricKeyNotNilAndDoesntChangeOnSecondCall() throws {
        let key = try KeyStore().getSymmetricKey(recipientPublicKey: privateKey.publicKey.rawRepresentation, salt: salt)

        XCTAssertNotNil(key)

        let newKey = try KeyStore().getSymmetricKey(recipientPublicKey: privateKey.publicKey.rawRepresentation, salt: salt)

        XCTAssertNotNil(newKey)
        XCTAssertEqual(key, newKey)
    }

    func test_Given_FirstLaunch_When_GenerateSymmetricKeyAndRemoveFromKeyChain_Then_SymmetricKeyNotNilAndChangesOnSecondCall() throws {
        let key = try KeyStore().getSymmetricKey(recipientPublicKey: privateKey.publicKey.rawRepresentation, salt: salt)

        XCTAssertNotNil(key)

        deleteKey()

        let newKey = try KeyStore().getSymmetricKey(recipientPublicKey: privateKey.publicKey.rawRepresentation, salt: salt)

        XCTAssertNotNil(newKey)
        XCTAssertNotEqual(key, newKey)
    }

    func test_Given_FirstLaunch_When_GeneratePublicKey_Then_PublicKeyNotNull() {
        XCTAssertNotNil(try KeyStore().getPublicKey())
    }

    func test_Given_FirstLaunch_When_GeneratePublicKey_Then_PublicKeyNotNilAndDoesntChangeOnSecondCall() throws {
        let key = try KeyStore().getPublicKey()

        XCTAssertNotNil(key)
        XCTAssertEqual(key, try KeyStore().getPublicKey())
    }

    func test_Given_FirstLaunch_When_GeneratePublicKeyAndRemoveFromKeyChain_Then_PublicKeyNotNilAndChangesOnSecondCall() throws {
        let key = try KeyStore().getPublicKey()

        XCTAssertNotNil(key)

        deleteKey()

        let newKey = try KeyStore().getPublicKey()

        XCTAssertNotNil(newKey)
        XCTAssertNotEqual(key, newKey)
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
