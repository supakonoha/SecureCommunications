# SecureCommunications

![badge-languages][] ![badge-pms][] ![badge-platforms][]

---

SecureCommunications simplifies CryptoKit tasks using Secure Enclave and AES and ChaChaPoly Ciphers and HMAC Message Authentication Codes.

```swift
let salt = "This is our salt"
let message = "This is a top secret message"

let encryptedMessage = message.sealAES(
    publicKey: recipientPublicKey,
    salt: salt)

let myPublicKey = try KeyStore().getPublicKey()
```
# Note

This library requires Secure Enclave on device: iPhone 5s (or later), iPad Air (or later), Mac computers that contain the T1 chip or the Apple T2 Security Chip, Apple TV 4th generation (or later), Apple Watch Series 1 (or later), HomePod

Minimum requirements: iOS 13.0, OSX 10.15, watchOS 6.0 or tvOS 13.0

On MacOS don't forget to enable keychain sharing entitlement

# Quick Start

In your `Package.swift` file:

```swift
package.dependencies.append(
.package(url: "https://github.com/supakonoha/SecureCommunications", from: "1.0.0")
)
```
# Complying with Encryption Export Regulations

Declare the use of encryption in your app to streamline the app submission process.

## Overview

When you submit your app to TestFlight or the App Store, you upload your app to a server in the United States. If you distribute your app outside the U.S. or Canada, your app is subject to U.S. export laws, regardless of where your legal entity is based. If your app uses, accesses, contains, implements, or incorporates encryption, this is considered an export of encryption software, which means your app is subject to U.S. export compliance requirements, as well as the import compliance requirements of the countries where you distribute your app.

Every time you submit a new version of your app, App Store Connect asks you questions to guide you through a compliance review. You can bypass these questions and streamline the submission process by providing the required information in your app’s Information Property List file.

## Declare Your App’s Use of Encryption

Add the `ITSAppUsesNonExemptEncryption` key to your app’s Info.plist file with a Boolean value that indicates whether your app uses encryption. Set the value to NO if your app—including any third-party libraries it links against—doesn’t use encryption, or if it only uses forms of encryption that are exempt from export compliance documentation requirements. Otherwise, set it to YES.

Typically, the use of encryption that’s built into the operating system—for example, when your app makes HTTPS connections using `URLSession`—is exempt from export documentation upload requirements, whereas the use of proprietary encryption is not. To determine whether your use of encryption is considered exempt, see [Determine your export compliance requirements](https://help.apple.com/app-store-connect/#/dev63c95e436).

> **Important**
>
> If your app uses exempt forms of encryption, you might alternatively be required to submit a year-end self-classification report to the U.S. government. (If you use non-exempt encryption and provide documentation to Apple, the self-classification report isn’t necessary.) To learn more, see [How to file an Annual Self Classification Report](https://www.bis.doc.gov/index.php/policy-guidance/encryption/4-reports-and-reviews/a-annual-self-classification).

## Provide Compliance Documentation

If your app requires export compliance documentation, upload the required items to App Store Connect, as described in [Upload export compliance documentation](https://help.apple.com/app-store-connect/#/dev38f592ac9). After successfully reviewing the documents, Apple provides you with a code. Add this string as the value for the `ITSEncryptionExportComplianceCode` key in your app’s Info.plist file.

# Public Key

The `KeyStore` struct manages a P-256 private key used for key agreement. You don't have to worry about your key. It's totally secure using the Secure Enclave of the device and using KeyChain to reference to the right key. With that system, it creates internally a shared secret between two users by performing NIST P-256 elliptic curve Diffie Hellman (ECDH) key exchange.

If you want to send an encrypted message you will need to share your Public Key. For that you can use:

## `getPublicKey`

```swift
let myPublicKey = try KeyStore().getPublicKey()
```

This method will return a raw representation of your public key as `Data`

# Ciphers

If you want to encrypt a message and send it to a recipient you can use AES and ChaChaPoly. The recipient of the encrypted message will use same cipher and will need your public key and the salt used for creating the symmetic key. For the full process you will need:

- Recipient public key: A raw representation of the public key created from a P-256 private key on the recipient. You will need it to encrypt the message. In case the recipient is a server, please, share the server public key in a secure way like using `CloudKit`. Please, don't hard-code the public key on the source code or abfuscate it, don't store it on Xcode Configuration or Info.plist files and never stores it on device once you have received it.
- Your public key: If you are a client you can share it with the recipient. The recipient will need it to decrypt the message.
- Salt: The salt to use for key derivation. This salt can be shared between sender and recipient.

## AES.GCM

The Advanced Encryption Standard (AES) Galois Counter Mode (GCM) cipher suite.

### Encrypt a message

To encrypt a message the library has added some extensions to `String` and `Data` classes

If you want to encrypt some `Data` you will need to use `sealAES(publicKey: Data, salt: Data)`. It requieres the raw representation of the recipient public key and the salt

```swift
let salt = "This is our salt".data(using: .utf8)!
let message = "This is a top secret message".data(using: .utf8)!

let encryptedMessage = message.sealAES(
    publicKey: recipientPublicKey,
    salt: salt)

let myPublicKey = try KeyStore().getPublicKey()
```

If you want to encrypt some `String` you will need to use `sealAES(publicKey: String, salt: String)`. It requieres the raw representation of the recipient public key coded on Base64 and the salt

```swift
let salt = "This is our salt"
let message = "This is a top secret message"

let encryptedMessage = message.sealAES(
    publicKey: recipientPublicKey,
    salt: salt)

let myPublicKey = try KeyStore().getPublicKey().base64EncodedString()
```

### Decrypt a message

To decrypt a message the library has added some extensions to `String` and `Data` classes

If you want to decrypt some `Data` you will need to use `openAES(publicKey: Data, salt:Data)`. It requieres the encrypted message, the raw representation of the recipient public key and the salt

```swift
let salt = "This is our salt".data(using: .utf8)!

let message = encryptedMessage.openAES(
    publicKey: recipientPublicKey,
    salt: salt)
```

If you want to decrypt some `String` you will need to use `openAES(publicKey: String, salt: String)`. It requieres the encrypted message coded on Base64 the raw representation of the recipient public key coded on Base64 and the salt

```swift
let salt = "This is our salt"

let message = encryptedMessage.openAES(
    publicKey: recipientPublicKey,
    salt: salt)
```

## ChaChaPoly

ChaCha20-Poly1305 cipher.

### Encrypt a message

To encrypt a message the library has added some extensions to `String` and `Data` classes

If you want to encrypt some `Data` you will need to use `sealChaChaPoly(publicKey: Data, salt: Data)`. It requieres the raw representation of the recipient public key and the salt

```swift
let salt = "This is our salt".data(using: .utf8)!
let message = "This is a top secret message".data(using: .utf8)!

let encryptedMessage = message.sealChaChaPoly(
    publicKey: recipientPublicKey,
    salt: salt)

let myPublicKey = try KeyStore().getPublicKey()
```

If you want to encrypt some `String` you will need to use `sealChaChaPoly(publicKey: String, salt: String)`. It requieres the raw representation of the recipient public key coded on Base64 and the salt

```swift
let salt = "This is our salt"
let message = "This is a top secret message"

let encryptedMessage = message.sealChaChaPoly(
    publicKey: recipientPublicKey,
    salt: salt)

let myPublicKey = try KeyStore().getPublicKey().base64EncodedString()
```

### Decrypt a message

To decypt a message the library has added some extensions to `String` and `Data` classes

If you want to decrypt some `Data` you will need to use `openChaChaPoly(publicKey: Data, salt:Data)`. It requieres the encrypted message, the raw representation of the recipient public key and the salt

```swift
let salt = "This is our salt".data(using: .utf8)!

let message = encryptedMessage.openChaChaPoly(
    publicKey: recipientPublicKey,
    salt: salt)
```

If you want to decrypt some `String` you will need to use `openChaChaPoly(publicKey: String, salt: String)`. It requieres the encrypted message coded on Base64 the raw representation of the recipient public key coded on Base64 and the salt

```swift
let salt = "This is our salt"

let message = encryptedMessage.openChaChaPoly(
    publicKey: recipientPublicKey,
    salt: salt)
```

# Message Authentication Codes

Use hash-based message authentication to create a code with a value that’s dependent on both a block of data and a symmetric cryptographic key. Another party with access to the data and the same secret key can compute the code again and compare it to the original to detect whether the data changed. This serves a purpose similar to digital signing and verification, but depends on a shared symmetric key instead of public-key cryptography.

As with digital signing, the data isn’t hidden by this process.

If you want to compute or validate a message authentication code you can use HMAC. The recipient of the message authentication code will use same HMAC configurtion and will need your public key and the salt used for creating the symmetic key. For the full process you will need:

- The message.
- Recipient public key: A raw representation of the public key created from a P-256 private key on the recipient. You will need it to encrypt the message. In case the recipient is a server, please, share the server public key in a secure way like using `CloudKit`. Please, don't hard-code the public key on the source code or abfuscate it, don't store it on Xcode Configuration or Info.plist files and never stores it on device once you have received it.
- Your public key: If you are a client you can share it with the recipient. The recipient will need it to validate the message authentication code.
- Salt: The salt to use for key derivation. This salt can be shared between sender and recipient.

## HMAC

A hash-based message authentication algorithm.

### Compute a message authentication code

To compute a message authentication code the library has added some extensions to `String` and `Data` classes

If you want to compute some `Data` you will need to use `authenticationCodeHMAC(publicKey: Data, salt: Data)`. It requieres the raw representation of the recipient public key and the salt

```swift
let salt = "This is our salt".data(using: .utf8)!
let message = "This is a public message".data(using: .utf8)!

let messageAuthenticationCode = message.authenticationCodeHMAC(
    publicKey: recipientPublicKey,
    salt: salt)

let myPublicKey = try KeyStore().getPublicKey()
```

If you want to compute some `String` you will need to use `authenticationCodeHMAC(publicKey: String, salt: String)`. It requieres the raw representation of the recipient public key coded on Base64 and the salt

```swift
let salt = "This is our salt"
let message = "This is a public message"

let messageAuthenticationCode = message.authenticationCodeHMAC(
    publicKey: recipientPublicKey,
    salt: salt)

let myPublicKey = try KeyStore().getPublicKey().base64EncodedString()
```

### Validate a message authentication code

To validate a message authentication code the library has added some extensions to `String` and `Data` classes

If you want to validate some `Data` you will need to use `isValidAuthenticationCodeHMAC(authenticationCode: authenticationCodeData, publicKey: Data, salt:Data)` on the original message. It requieres the original message, the message authentication code, the raw representation of the recipient public key and the salt

```swift
let salt = "This is our salt".data(using: .utf8)!
let message = "This is a public message".data(using: .utf8)!

let isValid = message.isValidAuthenticationCodeHMAC(
    authenticationCode: authenticationCode, 
    publicKey: recipientPublicKey,
    salt: salt)
```

If you want to validate some `String` you will need to use `isValidAuthenticationCodeHMAC(authenticationCode: authenticationCodeData,publicKey: String, salt: String)`. It requieres the original message, the message authentication code coded on Base64 the raw representation of the recipient public key coded on Base64 and the salt

```swift
let salt = "This is our salt"
let message = "This is a public message"

let isValid = message.isValidAuthenticationCodeHMAC(
    authenticationCode: authenticationCode, 
    publicKey: recipientPublicKey,
    salt: salt)
```

[badge-languages]: https://img.shields.io/badge/languages-Swift-orange.svg
[badge-pms]: https://img.shields.io/badge/supports-SwiftPM-green.svg
[badge-platforms]: https://img.shields.io/badge/platforms-iOS%2013.0%20%7C%20OSX%2010.15%20%7C%20watchOS%206.0%20%7C%20tvOS%2013.0-lightgrey.svg
