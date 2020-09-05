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
    private let salt = "Here's some salt data to use for testing".data(using: .utf8)!
    private let privateKey = try! SecureEnclave.P256.KeyAgreement.PrivateKey()

    private let publicKeyX963 = Data(base64Encoded: "BEBZeDGX55fQ/DOqk4bcX8IoZ96zBOfHOWtAxJdhrMIGIBRfSiLDoDJYNYSthnli+37gEDZqbYFO9qlkBSSS9Ws=")!
    private let publicKeyRaw = Data(base64Encoded: "QFl4MZfnl9D8M6qThtxfwihn3rME58c5a0DEl2GswgYgFF9KIsOgMlg1hK2GeWL7fuAQNmptgU72qWQFJJL1aw==")!
    private let publicKeyDer = Data(base64Encoded: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQFl4MZfnl9D8M6qThtxfwihn3rME58c5a0DEl2GswgYgFF9KIsOgMlg1hK2GeWL7fuAQNmptgU72qWQFJJL1aw==")!
    private let publicKeyPem = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQFl4MZfnl9D8M6qThtxfwihn3rME
58c5a0DEl2GswgYgFF9KIsOgMlg1hK2GeWL7fuAQNmptgU72qWQFJJL1aw==
-----END PUBLIC KEY-----
"""

    override func setUp() {
        deleteKey()
    }

    override func tearDown() {
        deleteKey()
    }

    func test_Given_WrongPublicKeyinX963Representation_When_GetPublicKey_Then_Exception() throws {
        XCTAssertThrowsError(try KeyStore.publicKey(x963Representation: Data()))
        XCTAssertThrowsError(try KeyStore.publicKey(x963Representation: "WrongData".data(using: .utf8)!))
    }

    func test_Given_WrongPublicKeyinRawRepresentation_When_GetPublicKey_Then_Exception() throws {
        XCTAssertThrowsError(try KeyStore.publicKey(rawRepresentation: Data()))
        XCTAssertThrowsError(try KeyStore.publicKey(rawRepresentation: "WrongData".data(using: .utf8)!))
    }

    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    func test_Given_WrongPublicKeyinPemRepresentation_When_GetPublicKey_Then_Exception() throws {
        XCTAssertThrowsError(try KeyStore.publicKey(pemRepresentation: ""))
        XCTAssertThrowsError(try KeyStore.publicKey(pemRepresentation: "WrongData"))
    }

    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    func test_Given_WrongPublicKeyinDerRepresentation_When_GetPublicKey_Then_Exception() throws {
        XCTAssertThrowsError(try KeyStore.publicKey(derRepresentation: Data()))
        XCTAssertThrowsError(try KeyStore.publicKey(derRepresentation: "WrongData".data(using: .utf8)!))
    }

    func test_Given_PublicKeyinX963Representation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let publicKey = try KeyStore.publicKey(x963Representation: publicKeyX963)

        XCTAssertEqual(publicKey.x963Representation, publicKeyX963)
        XCTAssertEqual(publicKey.rawRepresentation, publicKeyRaw)
        if #available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *) {
            XCTAssertEqual(publicKey.pemRepresentation, publicKeyPem)
            XCTAssertEqual(publicKey.derRepresentation, publicKeyDer)
        }
    }

    func test_Given_NewPublicKeyinX963Representation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let newPublicKey = P256.KeyAgreement.PrivateKey().publicKey
        let publicKey = try KeyStore.publicKey(x963Representation: newPublicKey.x963Representation)

        XCTAssertEqual(publicKey.x963Representation, newPublicKey.x963Representation)
        XCTAssertEqual(publicKey.rawRepresentation, newPublicKey.rawRepresentation)
        if #available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *) {
            XCTAssertEqual(publicKey.pemRepresentation, newPublicKey.pemRepresentation)
            XCTAssertEqual(publicKey.derRepresentation, newPublicKey.derRepresentation)
        }
    }

    func test_Given_PublicKeyinRawRepresentation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let publicKey = try KeyStore.publicKey(rawRepresentation: publicKeyRaw)

        XCTAssertEqual(publicKey.x963Representation, publicKeyX963)
        XCTAssertEqual(publicKey.rawRepresentation, publicKeyRaw)
        if #available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *) {
            XCTAssertEqual(publicKey.pemRepresentation, publicKeyPem)
            XCTAssertEqual(publicKey.derRepresentation, publicKeyDer)
        }
    }

    func test_Given_NewPublicKeyinRawRepresentation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let newPublicKey = P256.KeyAgreement.PrivateKey().publicKey
        let publicKey = try KeyStore.publicKey(rawRepresentation: newPublicKey.rawRepresentation)

        XCTAssertEqual(publicKey.x963Representation, newPublicKey.x963Representation)
        XCTAssertEqual(publicKey.rawRepresentation, newPublicKey.rawRepresentation)
        if #available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *) {
            XCTAssertEqual(publicKey.pemRepresentation, newPublicKey.pemRepresentation)
            XCTAssertEqual(publicKey.derRepresentation, newPublicKey.derRepresentation)
        }
    }

    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    func test_Given_PublicKeyinPemRepresentation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let publicKey = try KeyStore.publicKey(pemRepresentation: publicKeyPem)

        XCTAssertEqual(publicKey.x963Representation, publicKeyX963)
        XCTAssertEqual(publicKey.rawRepresentation, publicKeyRaw)
        XCTAssertEqual(publicKey.pemRepresentation, publicKeyPem)
        XCTAssertEqual(publicKey.derRepresentation, publicKeyDer)
    }

    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    func test_Given_NewPublicKeyinPemRepresentation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let newPublicKey = P256.KeyAgreement.PrivateKey().publicKey
        let publicKey = try KeyStore.publicKey(pemRepresentation: newPublicKey.pemRepresentation)

        XCTAssertEqual(publicKey.x963Representation, newPublicKey.x963Representation)
        XCTAssertEqual(publicKey.rawRepresentation, newPublicKey.rawRepresentation)
        XCTAssertEqual(publicKey.pemRepresentation, newPublicKey.pemRepresentation)
        XCTAssertEqual(publicKey.derRepresentation, newPublicKey.derRepresentation)
    }

    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    func test_Given_PublicKeyinDerRepresentation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let publicKey = try KeyStore.publicKey(derRepresentation: publicKeyDer)

        XCTAssertEqual(publicKey.x963Representation, publicKeyX963)
        XCTAssertEqual(publicKey.rawRepresentation, publicKeyRaw)
        XCTAssertEqual(publicKey.pemRepresentation, publicKeyPem)
        XCTAssertEqual(publicKey.derRepresentation, publicKeyDer)
    }

    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    func test_Given_NewPublicKeyinDerRepresentation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let newPublicKey = P256.KeyAgreement.PrivateKey().publicKey
        let publicKey = try KeyStore.publicKey(derRepresentation: newPublicKey.derRepresentation)

        XCTAssertEqual(publicKey.x963Representation, newPublicKey.x963Representation)
        XCTAssertEqual(publicKey.rawRepresentation, newPublicKey.rawRepresentation)
        XCTAssertEqual(publicKey.pemRepresentation, newPublicKey.pemRepresentation)
        XCTAssertEqual(publicKey.derRepresentation, newPublicKey.derRepresentation)
    }

    func test_Given_FirstLaunch_When_GenerateSymmetricKey_Then_SymmetricKeyNotNull() {
        XCTAssertNotNil(try KeyStore().getSymmetricKey(publicKey: privateKey.publicKey, salt: salt))
    }

    func test_Given_FirstLaunch_When_GenerateSymmetricKey_Then_SymmetricKeyNotNilAndDoesntChangeOnSecondCall() throws {
        let key = try KeyStore().getSymmetricKey(publicKey: privateKey.publicKey, salt: salt)

        XCTAssertNotNil(key)

        let newKey = try KeyStore().getSymmetricKey(publicKey: privateKey.publicKey, salt: salt)

        XCTAssertNotNil(newKey)
        XCTAssertEqual(key, newKey)
    }

    func test_Given_FirstLaunch_When_GenerateSymmetricKeyAndRemoveFromKeyChain_Then_SymmetricKeyNotNilAndChangesOnSecondCall() throws {
        let key = try KeyStore().getSymmetricKey(publicKey: privateKey.publicKey, salt: salt)

        XCTAssertNotNil(key)

        deleteKey()

        let newKey = try KeyStore().getSymmetricKey(publicKey: privateKey.publicKey, salt: salt)

        XCTAssertNotNil(newKey)
        XCTAssertNotEqual(key, newKey)
    }

    func test_Given_FirstLaunch_When_GeneratePublicKey_Then_PublicKeyNotNull() {
        XCTAssertNotNil(try KeyStore().publicKey())
        XCTAssertNotNil(try KeyStore().publicKeyInX963Representation())
        XCTAssertNotNil(try KeyStore().publicKeyInRawRepresentation())
        if #available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *) {
            XCTAssertNotNil(try KeyStore().publicKeyInPemRepresentation())
            XCTAssertNotNil(try KeyStore().publicKeyInDerRepresentation())
        }
    }

    func test_Given_FirstLaunch_When_GeneratePublicKey_Then_PublicKeyNotNilAndDoesntChangeOnSecondCall() throws {
        let publicKey = try KeyStore().publicKey()

        XCTAssertNotNil(publicKey)
        XCTAssertEqual(publicKey.x963Representation, try KeyStore().publicKey().x963Representation)
        XCTAssertEqual(publicKey.x963Representation, try KeyStore().publicKeyInX963Representation())
        XCTAssertEqual(publicKey.rawRepresentation, try KeyStore().publicKeyInRawRepresentation())
        if #available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *) {
            XCTAssertEqual(publicKey.pemRepresentation, try KeyStore().publicKeyInPemRepresentation())
            XCTAssertEqual(publicKey.derRepresentation, try KeyStore().publicKeyInDerRepresentation())
        }
    }

    func test_Given_FirstLaunch_When_GeneratePublicKeyAndRemoveFromKeyChain_Then_PublicKeyNotNilAndChangesOnSecondCall() throws {
        let publicKey = try KeyStore().publicKey()

        XCTAssertNotNil(publicKey)

        deleteKey()

        let newPublicKey = try KeyStore().publicKey()

        XCTAssertNotNil(newPublicKey)
        XCTAssertNotEqual(publicKey.x963Representation, newPublicKey.x963Representation)
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
