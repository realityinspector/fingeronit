// finger-seal: the keeper's half of the seal.
// It writes the same format bin/finger-touch reads: "FINGER1\0" then AES-GCM
// (nonce, ciphertext, tag). It never touches the keychain. The key comes from
// a file the keeper received from finger-touch when the door opened.
//
//   finger-seal KEYFILE            plaintext on stdin, sealed box on stdout
//   finger-seal --check KEYFILE    sealed box on stdin, prints the plaintext size
import CryptoKit
import Foundation

let magic = Data("FINGER1\0".utf8)

func die(_ message: String, _ code: Int32 = 65) -> Never {
    FileHandle.standardError.write(Data("finger-seal: \(message)\n".utf8))
    exit(code)
}

var args = Array(CommandLine.arguments.dropFirst())
var check = false
if args.first == "--check" {
    check = true
    args.removeFirst()
}
guard args.count == 1 else { die("usage: finger-seal [--check] KEYFILE", 64) }
guard let raw = FileManager.default.contents(atPath: args[0]), raw.count == 32 else {
    die("the key file must hold 32 bytes")
}
let key = SymmetricKey(data: raw)
let input = FileHandle.standardInput.readDataToEndOfFile()
guard !input.isEmpty else { die("nothing on stdin") }

if check {
    guard input.count > magic.count, input.prefix(magic.count) == magic else {
        die("not a fingeronit seal")
    }
    do {
        let box = try AES.GCM.SealedBox(combined: Data(input.dropFirst(magic.count)))
        let plain = try AES.GCM.open(box, using: key)
        print(plain.count)
    } catch {
        die("the seal does not open with this key")
    }
    exit(0)
}

do {
    let box = try AES.GCM.seal(input, using: key)
    guard let combined = box.combined else { die("could not combine the sealed box") }
    var out = magic
    out.append(combined)
    FileHandle.standardOutput.write(out)
} catch {
    die("sealing failed")
}
