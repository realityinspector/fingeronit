import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

/// Touch ID (or the Mac password, if biometrics are unavailable) in front of
/// one AES-GCM key. The key lives in the login keychain, readable without a
/// second prompt only by this signed binary. A patched copy is a different
/// signature, so the keychain will not hand it the key.

let service = "dev.fingeronit.lock"
let magic = Data("FINGER1\0".utf8)

func die(_ message: String, _ code: Int32 = 1) -> Never {
    fputs("finger-touch: \(message)\n", stderr)
    exit(code)
}

func osStatusText(_ status: OSStatus) -> String {
    if let text = SecCopyErrorMessageString(status, nil) as String? {
        return "\(status) \(text)"
    }
    return "\(status)"
}

func requireTerminal() {
    if isatty(STDERR_FILENO) != 0 { return }
    let fd = open("/dev/tty", O_RDWR)
    if fd >= 0 {
        close(fd)
        return
    }
    die("refused. No terminal, so this lock stays shut.", 77)
}

func sanitizeReason(_ raw: String) -> String {
    let scalars = raw.unicodeScalars.filter { $0.value >= 32 && $0.value != 127 }
    var text = String(String.UnicodeScalarView(scalars))
    text = text.trimmingCharacters(in: .whitespacesAndNewlines)
    if text.count > 140 {
        text = String(text.prefix(140))
    }
    return text.isEmpty ? "Unlock fingeronit" : text
}

func executablePath() -> String {
    var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    let n = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
    if n > 0 {
        return String(cString: buffer)
    }
    die("cannot see the path of this binary")
}

func parentCommand() -> String {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/ps")
    task.arguments = ["-p", String(getppid()), "-o", "args="]
    let pipe = Pipe()
    task.standardOutput = pipe
    task.standardError = FileHandle.nullDevice
    do {
        try task.run()
    } catch {
        return ""
    }
    task.waitUntilExit()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    return String(data: data, encoding: .utf8) ?? ""
}

func wrapperPaths() -> [String] {
    let bin = URL(fileURLWithPath: executablePath()).deletingLastPathComponent().path
    let root = URL(fileURLWithPath: bin).deletingLastPathComponent().path
    return [bin + "/fingeronit", root + "/fingeronit"]
}

func appRoot() -> String {
    URL(fileURLWithPath: executablePath())
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .path
}

func reasonForCaller(_ supplied: String) -> String {
    let parent = parentCommand()
    for wrapper in wrapperPaths() where parent.contains(wrapper) {
        return sanitizeReason(supplied)
    }
    return "Something other than fingeronit wants the seal key. Cancel to keep it shut."
}

func authenticate(reason: String) {
    let context = LAContext()
    context.localizedCancelTitle = "Keep sealed"
    var policyError: NSError?
    let policy: LAPolicy
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) {
        policy = .deviceOwnerAuthenticationWithBiometrics
    } else {
        policy = .deviceOwnerAuthentication
    }

    var succeeded = false
    var finished = false
    context.evaluatePolicy(policy, localizedReason: reason) { success, _ in
        succeeded = success
        finished = true
        CFRunLoopStop(CFRunLoopGetMain())
    }
    while !finished {
        CFRunLoopRun()
    }
    if !succeeded {
        die("authentication canceled. The seal stays shut.", 77)
    }
}

func makeAccess() -> SecAccess {
    let exe = executablePath()
    var app: SecTrustedApplication?
    let appStatus = exe.withCString { SecTrustedApplicationCreateFromPath($0, &app) }
    guard appStatus == errSecSuccess, let app else {
        die("could not name this binary for the keychain (\(osStatusText(appStatus)))")
    }
    var access: SecAccess?
    let trusted = [app] as CFArray
    let accessStatus = SecAccessCreate("fingeronit" as CFString, trusted, &access)
    guard accessStatus == errSecSuccess, let access else {
        die("could not build the keychain access list (\(osStatusText(accessStatus)))")
    }
    return access
}

func deleteAccount(_ account: String, allowMissing: Bool) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status == errSecSuccess || status == errSecItemNotFound {
        if status == errSecItemNotFound && !allowMissing {
            die("no seal key for \(account)")
        }
        return
    }
    die("could not delete the seal key (\(osStatusText(status)))")
}

func accountExists(_ account: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    switch status {
    case errSecSuccess, errSecInteractionNotAllowed, errSecAuthFailed:
        return true
    case errSecItemNotFound:
        return false
    default:
        return false
    }
}

func storeKey(_ account: String, _ key: Data) {
    deleteAccount(account, allowMissing: true)
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecAttrLabel as String: "fingeronit seal key",
        kSecAttrDescription as String: "Key that seals one temporary mail login",
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
        kSecAttrAccess as String: makeAccess(),
        kSecValueData as String: key,
    ]
    let status = SecItemAdd(query as CFDictionary, nil)
    if status != errSecSuccess {
        die("could not store the seal key (\(osStatusText(status)))")
    }
}

func loadKey(_ account: String) -> Data {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
        die("no seal key for this instance. Log in again from Terminal.")
    }
    if status != errSecSuccess {
        die("keychain refused the seal key (\(osStatusText(status)))")
    }
    guard let data = result as? Data, data.count == 32 else {
        die("seal key has an unexpected shape")
    }
    return data
}

func ensureKey(_ account: String) -> Data {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecSuccess, let data = result as? Data, data.count == 32 {
        return data
    }
    if status != errSecItemNotFound && status != errSecSuccess {
        // A prompt would be required to read, or the item is unreadable.
        // Try the normal read once before minting a second key.
        if status != errSecInteractionNotAllowed {
            die("could not read the existing seal key (\(osStatusText(status)))")
        }
        return loadKey(account)
    }
    var bytes = [UInt8](repeating: 0, count: 32)
    let random = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    if random != errSecSuccess {
        die("could not mint a seal key (\(osStatusText(random)))")
    }
    let key = Data(bytes)
    storeKey(account, key)
    return key
}

func pathIsInsideVar(_ path: String) -> Bool {
    let root = URL(fileURLWithPath: appRoot()).appendingPathComponent("var").path
    let full = URL(fileURLWithPath: path).standardizedFileURL.path
    return full == root || full.hasPrefix(root + "/")
}

func requireInsideVar(_ path: String) {
    if !pathIsInsideVar(path) {
        die("refused a path outside the var directory")
    }
}

func sealFile(account: String, source: String, dest: String) {
    requireInsideVar(source)
    requireInsideVar(dest)
    let plain = try! Data(contentsOf: URL(fileURLWithPath: source))
    if plain.isEmpty {
        die("refusing to seal an empty file")
    }
    let key = SymmetricKey(data: ensureKey(account))
    let box = try! AES.GCM.seal(plain, using: key)
    guard let combined = box.combined else {
        die("could not combine the sealed box")
    }
    var out = Data()
    out.append(magic)
    out.append(combined)
    let destURL = URL(fileURLWithPath: dest)
    try! FileManager.default.createDirectory(
        at: destURL.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    let tmp = dest + ".tmp"
    try! out.write(to: URL(fileURLWithPath: tmp), options: .atomic)
    try! FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp)
    if FileManager.default.fileExists(atPath: dest) {
        try! FileManager.default.removeItem(atPath: dest)
    }
    try! FileManager.default.moveItem(atPath: tmp, toPath: dest)
}

func writeOwnerOnly(_ data: Data, to path: String) {
    let url = URL(fileURLWithPath: path)
    try! FileManager.default.createDirectory(
        at: url.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    try! data.write(to: url, options: .atomic)
    try! FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
}

func unsealFile(account: String, source: String, dest: String, keyOut: String) {
    requireInsideVar(source)
    requireInsideVar(dest)
    requireInsideVar(keyOut)
    let blob = try! Data(contentsOf: URL(fileURLWithPath: source))
    guard blob.count > magic.count, blob.prefix(magic.count) == magic else {
        die("sealed file is not a fingeronit seal")
    }
    let rawKey = loadKey(account)
    let box = try! AES.GCM.SealedBox(combined: Data(blob.dropFirst(magic.count)))
    let plain = try! AES.GCM.open(box, using: SymmetricKey(data: rawKey))
    writeOwnerOnly(plain, to: dest)
    writeOwnerOnly(rawKey, to: keyOut)
}

// The key as hex on one line, then the plaintext, on stdout. fingeronit pipes this
// straight into the keeper, so neither ever sits in a file on your side.
func unsealStream(account: String, source: String) {
    requireInsideVar(source)
    if isatty(STDOUT_FILENO) != 0 {
        die("refused. unseal-stream writes the key, so its output must go to a pipe.")
    }
    let blob = try! Data(contentsOf: URL(fileURLWithPath: source))
    guard blob.count > magic.count, blob.prefix(magic.count) == magic else {
        die("sealed file is not a fingeronit seal")
    }
    let rawKey = loadKey(account)
    let box = try! AES.GCM.SealedBox(combined: Data(blob.dropFirst(magic.count)))
    let plain = try! AES.GCM.open(box, using: SymmetricKey(data: rawKey))
    let hex = rawKey.map { String(format: "%02x", $0) }.joined()
    FileHandle.standardOutput.write(Data((hex + "\n").utf8))
    FileHandle.standardOutput.write(plain)
}

func sealRaw(keyFile: String, source: String, dest: String) {
    requireInsideVar(keyFile)
    requireInsideVar(source)
    requireInsideVar(dest)
    let rawKey = try! Data(contentsOf: URL(fileURLWithPath: keyFile))
    if rawKey.count != 32 {
        die("seal key file has an unexpected shape")
    }
    let plain = try! Data(contentsOf: URL(fileURLWithPath: source))
    if plain.isEmpty {
        die("refusing to seal an empty file")
    }
    let box = try! AES.GCM.seal(plain, using: SymmetricKey(data: rawKey))
    guard let combined = box.combined else {
        die("could not combine the sealed box")
    }
    var out = Data()
    out.append(magic)
    out.append(combined)
    writeOwnerOnly(out, to: dest + ".tmp")
    if FileManager.default.fileExists(atPath: dest) {
        try! FileManager.default.removeItem(atPath: dest)
    }
    try! FileManager.default.moveItem(atPath: dest + ".tmp", toPath: dest)
}

func splitReason(_ args: [String]) -> (flags: [String], reason: String) {
    guard let marker = args.firstIndex(of: "--") else {
        die("missing -- before the reason shown on the Touch ID prompt")
    }
    let reason = args[(marker + 1)...].joined(separator: " ")
    return (Array(args[..<marker]), reason)
}

func selftest() {
    let key = SymmetricKey(data: Data((0..<32).map { UInt8($0) }))
    let plain = Data("fingeronit-selftest".utf8)
    let box = try! AES.GCM.seal(plain, using: key)
    let opened = try! AES.GCM.open(box, using: key)
    if opened != plain {
        die("selftest round trip failed")
    }
    print("selftest ok")
}

func loadKeyFailClosed(_ account: String) -> OSStatus {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
    ]
    var result: CFTypeRef?
    return SecItemCopyMatching(query as CFDictionary, &result)
}

func probe() {
    SecKeychainSetUserInteractionAllowed(false)
    let account = "instance/__probe__"
    deleteAccount(account, allowMissing: true)
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
        die("probe could not mint a key")
    }
    storeKey(account, Data(bytes))
    let own = loadKeyFailClosed(account)
    if own != errSecSuccess {
        deleteAccount(account, allowMissing: true)
        die("probe: this binary could not read its own key (\(osStatusText(own)))")
    }

    let copy = NSTemporaryDirectory() + "finger-touch-probe-\(getpid())"
    try! FileManager.default.copyItem(atPath: executablePath(), toPath: copy)
    defer { try? FileManager.default.removeItem(atPath: copy) }
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    task.arguments = ["--force", "--sign", "-", copy]
    try! task.run()
    task.waitUntilExit()
    if task.terminationStatus != 0 {
        deleteAccount(account, allowMissing: true)
        die("probe: could not re-sign the copy")
    }

    let child = Process()
    child.executableURL = URL(fileURLWithPath: copy)
    child.arguments = ["probe-read", account]
    let pipe = Pipe()
    child.standardOutput = pipe
    child.standardError = pipe
    try! child.run()
    child.waitUntilExit()
    let childOut = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let copyStatus = child.terminationStatus

    let sec = Process()
    sec.executableURL = URL(fileURLWithPath: "/usr/bin/security")
    sec.arguments = ["find-generic-password", "-s", service, "-a", account, "-w"]
    let secOut = Pipe()
    sec.standardOutput = secOut
    sec.standardError = FileHandle.nullDevice
    try! sec.run()
    let deadline = Date().addingTimeInterval(2)
    while sec.isRunning && Date() < deadline {
        Thread.sleep(forTimeInterval: 0.05)
    }
    var securityLeaked = false
    if sec.isRunning {
        sec.terminate()
        sec.waitUntilExit()
    } else {
        let data = secOut.fileHandleForReading.readDataToEndOfFile()
        securityLeaked = sec.terminationStatus == 0 && !data.isEmpty
    }

    deleteAccount(account, allowMissing: true)
    if copyStatus == 0 {
        die("probe: a re-signed copy read the key. Refusing to trust this ACL.\n\(childOut)")
    }
    if securityLeaked {
        die("probe: security(1) read the seal key without a prompt")
    }
    print("probe ok (re-signed copy status \(copyStatus))")
}

let args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else {
    die("usage: finger-touch selftest|probe|status|seal|unseal|unseal-stream|drop")
}

switch command {
case "parent":
    print(parentCommand())
case "selftest":
    selftest()
case "probe":
    probe()
case "probe-read":
    SecKeychainSetUserInteractionAllowed(false)
    guard args.count == 2 else { die("probe-read needs an account") }
    let status = loadKeyFailClosed(args[1])
    if status == errSecSuccess {
        exit(0)
    }
    fputs("probe-read refused \(osStatusText(status))\n", stderr)
    exit(2)
case "status":
    guard args.count == 2 else { die("status needs an account") }
    print(accountExists(args[1]) ? "present" : "absent")
case "seal":
    requireTerminal()
    let parsed = splitReason(Array(args.dropFirst()))
    guard parsed.flags.count == 3 else { die("seal <account> <src> <dst> -- <reason>") }
    authenticate(reason: reasonForCaller(parsed.reason))
    sealFile(account: parsed.flags[0], source: parsed.flags[1], dest: parsed.flags[2])
case "unseal":
    requireTerminal()
    let parsed = splitReason(Array(args.dropFirst()))
    guard parsed.flags.count == 4 else { die("unseal <account> <src> <dst> <keyout> -- <reason>") }
    authenticate(reason: reasonForCaller(parsed.reason))
    unsealFile(
        account: parsed.flags[0],
        source: parsed.flags[1],
        dest: parsed.flags[2],
        keyOut: parsed.flags[3]
    )
case "streams":
    // fingeronit asks this to learn that unseal-stream exists.
    exit(0)
case "unseal-stream":
    requireTerminal()
    let parsed = splitReason(Array(args.dropFirst()))
    guard parsed.flags.count == 2 else { die("unseal-stream <account> <src> -- <reason>") }
    authenticate(reason: reasonForCaller(parsed.reason))
    unsealStream(account: parsed.flags[0], source: parsed.flags[1])
case "seal-raw":
    guard args.count == 4 else { die("seal-raw <keyfile> <src> <dst>") }
    sealRaw(keyFile: args[1], source: args[2], dest: args[3])
case "drop":
    requireTerminal()
    let parsed = splitReason(Array(args.dropFirst()))
    guard !parsed.flags.isEmpty else { die("drop <account> [account...] -- <reason>") }
    authenticate(reason: reasonForCaller(parsed.reason))
    for account in parsed.flags {
        deleteAccount(account, allowMissing: true)
    }
default:
    die("unknown command \(command)")
}
