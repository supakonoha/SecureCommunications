//  Data+AES.swift
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

extension Data {
    /**
     Encrypts current data using AES.GCM cipher.

     - Parameters:
        - publicKey: Raw Representation of Recipient P-256 puiblic key.
        - salt: The salt to use for key derivation.

     - Returns:  combined AES Selead box  (nonce || ciphertext || tag). If there's a problem encrypting, nil is retuned.
     */
    func sealAES(publicKey: Data, salt: Data) -> Data? {
        guard let symmetricKey = try? KeyStore().getSymmetricKey(
            recipientPublicKey: publicKey,
            salt: salt) else {
            return nil
        }

        return try? AES.GCM.seal(self, using: symmetricKey).combined
    }

    /**
     Decrypts current combined AES Selead box data (nonce || ciphertext || tag) using AES.GCM cipher.

     - Parameters:
        - publicKey: Raw Representation of Recipient P-256 puiblic key.
        - salt: The salt to use for key derivation.

     - Returns: Decrypts the message and verifies its authenticity using AES.GCM. If there's a problem decrypting, nil is retuned.
     */
    func openAES(publicKey: Data, salt:Data) -> Data? {
        guard let symmetricKey = try? KeyStore().getSymmetricKey(
            recipientPublicKey: publicKey,
            salt: salt) else {
                return nil
        }

        guard let sealedBox = try? AES.GCM.SealedBox(combined: self) else {
                return nil
        }

        return try? AES.GCM.open(sealedBox, using: symmetricKey)
    }
}