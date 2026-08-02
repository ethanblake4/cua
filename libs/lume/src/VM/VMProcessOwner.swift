import Darwin
import Foundation

struct VMProcessFingerprint: Codable, Equatable {
  let processIdentifier: Int32
  let startTimeSeconds: UInt64
  let startTimeMicroseconds: UInt64
  let executablePath: String

  nonisolated static func current(processIdentifier: Int32 = getpid()) -> Self? {
    guard processIdentifier > 0 else { return nil }

    var processInfo = proc_bsdinfo()
    let expectedSize = Int32(MemoryLayout<proc_bsdinfo>.size)
    let actualSize = withUnsafeMutablePointer(to: &processInfo) { pointer in
      proc_pidinfo(processIdentifier, PROC_PIDTBSDINFO, 0, pointer, expectedSize)
    }
    guard actualSize == expectedSize else { return nil }

    var executablePath = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    guard proc_pidpath(processIdentifier, &executablePath, UInt32(executablePath.count)) > 0 else {
      return nil
    }

    let executableLength = executablePath.firstIndex(of: 0) ?? executablePath.endIndex
    return Self(
      processIdentifier: processIdentifier,
      startTimeSeconds: UInt64(processInfo.pbi_start_tvsec),
      startTimeMicroseconds: UInt64(processInfo.pbi_start_tvusec),
      executablePath: String(
        decoding: executablePath[..<executableLength].map(UInt8.init(bitPattern:)), as: UTF8.self)
    )
  }
}

struct VMProcessOwner: Codable, Equatable {
  let fingerprint: VMProcessFingerprint
  let generation: UUID

  var processIdentifier: Int32 { fingerprint.processIdentifier }
}

enum VMProcessOwnerRegistry {
  private nonisolated static let ownerFileName = ".vm-process-owner.json"

  nonisolated static func register(vmDirectory: VMDirectory) throws -> VMProcessOwner {
    guard let fingerprint = VMProcessFingerprint.current() else {
      throw VMError.internalError("Failed to identify the VM owner process")
    }

    let owner = VMProcessOwner(fingerprint: fingerprint, generation: UUID())
    let fileURL = ownerURL(for: vmDirectory)
    try JSONEncoder().encode(owner).write(to: fileURL, options: .atomic)
    chmod(fileURL.path, S_IRUSR | S_IWUSR)
    return owner
  }

  nonisolated static func unregister(_ owner: VMProcessOwner, vmDirectory: VMDirectory) {
    let fileURL = ownerURL(for: vmDirectory)
    guard read(from: fileURL) == owner else { return }
    try? FileManager.default.removeItem(at: fileURL)
  }

  nonisolated static func validatedOwner(for vmDirectory: VMDirectory) -> VMProcessOwner? {
    guard let owner = read(from: ownerURL(for: vmDirectory)),
      VMProcessFingerprint.current(processIdentifier: owner.processIdentifier) == owner.fingerprint
    else {
      return nil
    }
    return owner
  }

  nonisolated static func ownerRecordExists(for vmDirectory: VMDirectory) -> Bool {
    FileManager.default.fileExists(atPath: ownerURL(for: vmDirectory).path)
  }

  private nonisolated static func read(from fileURL: URL) -> VMProcessOwner? {
    guard let data = try? Data(contentsOf: fileURL) else { return nil }
    return try? JSONDecoder().decode(VMProcessOwner.self, from: data)
  }

  private nonisolated static func ownerURL(for vmDirectory: VMDirectory) -> URL {
    vmDirectory.dir.file(ownerFileName).url
  }
}
