//  Data+HMAC.swift
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
     Computes a message authentication code for the given data using HMAC from current data.

     - Parameters:
        - publicKey: Raw Representation of Recipient P-256 puiblic key.
        - salt: The salt to use for key derivation.

     - Returns: Message authentication code. If there's a problem computing, nil is retuned.
     */
    func authenticationCodeHMAC(publicKey: Data, salt: Data) -> Data? {
        guard let symmetricKey = try? KeyStore().getSymmetricKey(
            recipientPublicKey: publicKey,
            salt: salt) else {
                return nil
        }

        return Data(HMAC<SHA512>.authenticationCode(for: self, using: symmetricKey))
    }

    /**
     Returns a Boolean indicating whether the given code is valid for current data using HMAC.

     - Parameters:
        - authenticationCode: authentication code to validate.
        - publicKey: Raw Representation of Recipient P-256 puiblic key.
        - salt: The salt to use for key derivation.

     - Returns:  Boolean indicating whether the given code is valid for current data. If there's a problem validating, false is retuned.
     */
    func isValidAuthenticationCodeHMAC(authenticationCode: Data, publicKey: Data, salt: Data) -> Bool {
        guard let symmetricKey = try? KeyStore().getSymmetricKey(
            recipientPublicKey: publicKey,
            salt: salt) else {
                return false
        }

        return HMAC<SHA512>.isValidAuthenticationCode(authenticationCode, authenticating: self, using: symmetricKey)
    }
}
