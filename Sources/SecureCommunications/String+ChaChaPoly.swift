//  String+ChaChaPoly.swift
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

import Foundation
import CryptoKit

extension String {
    /**
     Encrypts current string using ChaChaPoly cipher.

     - Parameters:
        - recipientPublicKey: Recipient public key.
        - salt: The salt to use for key derivation.

     - Returns: Combined ChaChaPoly Selead box  (nonce || ciphertext || tag) coded on base64. If there's a problem encrypting, `nil` is retuned.
     */
    public func sealChaChaPoly(recipientPublicKey: P256.KeyAgreement.PublicKey, salt: String) -> String? {
        guard let data = self.data(using: .utf8) else {
            return nil
        }

        guard let saltData = salt.data(using: .utf8) else {
            return nil
        }

        return data.sealChaChaPoly(recipientPublicKey: recipientPublicKey, salt: saltData)?.base64EncodedString()
    }

    /**
     Decrypts current ChaChaPoly Selead box coded combined as `nonce || ciphertext || tag` and coded on Base64  using ChaChaPoly cipher.

     - Parameters:
        - senderPublicKey: Sender public key.
        - salt: The salt to use for key derivation.

     - Returns: Decrypts the message and verifies its authenticity using ChaChaPoly. If there's a problem decrypting, `nil` is retuned.
     */
    public func openChaChaPoly(senderPublicKey: P256.KeyAgreement.PublicKey, salt: String) -> String? {
        guard let data = Data(base64Encoded: self) else {
            return nil
        }

        guard let saltData = salt.data(using: .utf8) else {
            return nil
        }

        guard let decryptedData = data.openChaChaPoly(senderPublicKey: senderPublicKey, salt: saltData) else {
            return nil
        }

        return String(data: decryptedData, encoding: .utf8)
    }
}
