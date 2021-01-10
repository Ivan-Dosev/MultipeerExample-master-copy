/// Copyright (c) 2021 Razeware LLC
/// 
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
/// 
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
/// 
/// Notwithstanding the foregoing, you may not use, copy, modify, merge, publish,
/// distribute, sublicense, create a derivative work, and/or sell copies of the
/// Software in any work that is designed, intended, or marketed for pedagogical or
/// instructional purposes related to programming, coding, application development,
/// or information technology.  Permission for such use, copying, modification,
/// merger, publication, distribution, sublicensing, creation of derivative works,
/// or sale is expressly withheld.
/// 
/// This project and source code may use libraries or frameworks that are
/// released under various Open-Source licenses. Use of those libraries and
/// frameworks are governed by their own individual licenses.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
/// THE SOFTWARE.

import Foundation
import CryptoKit
import Foundation

struct Crypto {
    let one = One()
    var lastMessageReceived: Message?
    let message = "I'm building a terrific new app!".data(using: .utf16)!

    func encrypt(_ data: Data, to theirEncryptionKey: Curve25519.KeyAgreement.PublicKey, signedBy ourSigningKey: Curve25519.Signing.PrivateKey) throws -> (Data) {
            let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
            let ephemeralPublicKey = ephemeralKey.publicKey.rawRepresentation
            
            let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: theirEncryptionKey)
            
            let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self,
                                                                    salt: one.protocolSalt,
                                                                    sharedInfo: ephemeralPublicKey +
                                                                        theirEncryptionKey.rawRepresentation +
                                                                        ourSigningKey.publicKey.rawRepresentation,
                                                                        outputByteCount: 32)
           
            let ciphertext = try ChaChaPoly.seal(data, using: symmetricKey).combined
            let signature = try ourSigningKey.signature(for: ciphertext + ephemeralPublicKey + theirEncryptionKey.rawRepresentation)
        let encode = Product(ephemeralPublicKey: ephemeralPublicKey, ciphertext: ciphertext, signature: signature,receiverEncryptionPublicKey: "\(theirEncryptionKey.rawRepresentation.hashValue)")
            let data = try JSONEncoder().encode(encode)
            return (data)
    }

    enum DecryptionErrors: Error {
        case authenticationError
    }
   
    func test(data:Data) throws -> Data {

        let sameEmployee = try? JSONDecoder().decode(Product.self, from: data)
        guard let ephemeralPublicKeyData = sameEmployee?.ephemeralPublicKey else { return message }
        guard let ciphertext = sameEmployee?.ciphertext else { return message }
        guard let signature = sameEmployee?.signature else { return message }
        guard let receiverEncryptionPublicKey = sameEmployee?.receiverEncryptionPublicKey else { return message }
        print("1: \(receiverEncryptionPublicKey)")
        print("2: \(one.receiverEncryptionKey.publicKey.rawRepresentation.hashValue)")
        let data = ciphertext  + ephemeralPublicKeyData + one.receiverEncryptionPublicKey.rawRepresentation
        guard one.senderSigningPublicKey.isValidSignature(signature , for: data) else { print("TUK");
              throw DecryptionErrors.authenticationError
          }
        guard let ephemeralKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublicKeyData) else { print("TUK1"); throw DecryptionErrors.authenticationError}
        guard let sharedSecret = try? one.receiverEncryptionKey.sharedSecretFromKeyAgreement(with: ephemeralKey) else { print("TUK2"); throw DecryptionErrors.authenticationError}
          let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self,
                                                                  salt: one.protocolSalt,
                                                                  sharedInfo: ephemeralKey.rawRepresentation +
                                                                    one.receiverEncryptionPublicKey.rawRepresentation +
                                                                    one.senderSigningPublicKey.rawRepresentation,
                                                                  outputByteCount: 32)

        let sealedBox = try! ChaChaPoly.SealedBox(combined: ciphertext)
        guard let unwrap = try? ChaChaPoly.open(sealedBox, using: symmetricKey) else { print("TUK4"); throw DecryptionErrors.authenticationError}
        print("The following message was successfully decrypted: \(String(data: unwrap, encoding: .utf8)!)")
          return unwrap
    }
}
