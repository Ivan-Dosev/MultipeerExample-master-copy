//
//  Message.swift
//  MultipeerExample
//
//  Created by Ben Gottlieb on 9/12/18.
//  Copyright © 2018 Stand Alone, Inc. All rights reserved.
//

import Foundation
import CryptoKit



struct Message: Codable {
	let body: String
}

extension Device {
	func send(text: String) throws {
        let message1 = text.data(using: .utf16)!
        let data = try! crypto.encrypt(message1, to: crypto.one.receiverEncryptionPublicKey, signedBy: crypto.one.senderSigningKey)
		try self.session?.send(data, toPeers: [self.peerID], with: .reliable)
	}
}
