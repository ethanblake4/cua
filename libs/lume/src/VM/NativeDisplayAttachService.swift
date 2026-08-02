import Darwin
import Foundation

enum NativeDisplayAttachError: LocalizedError {
  case unavailable
  case requestFailed

  var errorDescription: String? {
    switch self {
    case .unavailable:
      return "The running VM process does not support native display attachment."
    case .requestFailed:
      return "Failed to ask the running VM process to show its native display."
    }
  }
}

private struct NativeDisplayOwner: Codable, Equatable {
  let vmProcessOwner: VMProcessOwner
}

/// Provides a small, process-local control channel for revealing the native viewer.
///
/// The owning `lume run` process registers SIGUSR1 and records its verified VM-owner
/// identity. An `attach` process signals it only while that exact process is still alive.
@MainActor
enum NativeDisplayAttachService {
  private nonisolated static let ownerFileName = ".native-display-owner.json"
  private static var signalSource: DispatchSourceSignal?
  private static var ownerFileURL: URL?
  private static var registeredOwner: NativeDisplayOwner?
  private static var showAction: (@MainActor @Sendable () async -> Void)?

  static func register(
    vmDirectory: VMDirectory,
    show: @escaping @MainActor @Sendable () async -> Void
  ) throws {
    unregister()

    guard let vmProcessOwner = VMProcessOwnerRegistry.validatedOwner(for: vmDirectory) else {
      throw NativeDisplayAttachError.unavailable
    }
    let owner = NativeDisplayOwner(vmProcessOwner: vmProcessOwner)
    let fileURL = ownerURL(for: vmDirectory)
    let data = try JSONEncoder().encode(owner)
    try data.write(to: fileURL, options: .atomic)
    chmod(fileURL.path, S_IRUSR | S_IWUSR)

    showAction = show
    ownerFileURL = fileURL
    registeredOwner = owner
    signal(SIGUSR1, SIG_IGN)

    let source = DispatchSource.makeSignalSource(signal: SIGUSR1, queue: .main)
    source.setEventHandler {
      Task { @MainActor in
        await showAction?()
      }
    }
    signalSource = source
    source.resume()
  }

  static func unregister() {
    signalSource?.cancel()
    signalSource = nil
    showAction = nil

    if let ownerFileURL, let registeredOwner,
      let data = try? Data(contentsOf: ownerFileURL),
      let owner = try? JSONDecoder().decode(NativeDisplayOwner.self, from: data),
      owner == registeredOwner
    {
      try? FileManager.default.removeItem(at: ownerFileURL)
    }
    ownerFileURL = nil
    registeredOwner = nil
  }

  nonisolated static func isAvailable(vmDirectory: VMDirectory) -> Bool {
    guard let owner = validatedOwner(for: vmDirectory) else { return false }
    return kill(owner.vmProcessOwner.processIdentifier, 0) == 0
  }

  nonisolated static func requestNativeDisplay(vmDirectory: VMDirectory) throws {
    guard let owner = validatedOwner(for: vmDirectory) else {
      throw NativeDisplayAttachError.unavailable
    }
    guard kill(owner.vmProcessOwner.processIdentifier, SIGUSR1) == 0 else {
      throw NativeDisplayAttachError.requestFailed
    }
  }

  private nonisolated static func validatedOwner(
    for vmDirectory: VMDirectory
  ) -> NativeDisplayOwner? {
    let fileURL = ownerURL(for: vmDirectory)
    guard let data = try? Data(contentsOf: fileURL),
      let owner = try? JSONDecoder().decode(NativeDisplayOwner.self, from: data),
      owner.vmProcessOwner == VMProcessOwnerRegistry.validatedOwner(for: vmDirectory)
    else {
      return nil
    }
    return owner
  }

  private nonisolated static func ownerURL(for vmDirectory: VMDirectory) -> URL {
    vmDirectory.dir.file(ownerFileName).url
  }

}
