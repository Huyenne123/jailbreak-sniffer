import Foundation

public struct FilesystemDetector: Detector {
    private let suspiciousPaths = [
        "/var/jb",
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Filza.app",
        "/Library/MobileSubstrate",
        "/usr/libexec/cydia",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/stash",
        "/private/preboot/Applications"
    ]

    public init() {}

    public func run() -> [DetectionResult] {
        let matches = suspiciousPaths.filter { FileManager.default.fileExists(atPath: $0) }

        if matches.isEmpty {
            return [
                DetectionResult(
                    id: "filesystem-clean",
                    name: "Filesystem artifacts",
                    category: .filesystem,
                    detected: false,
                    severity: 0,
                    explanation: "No commonly associated jailbreak filesystem markers were found.",
                    technicalDetails: "Checked a list of known jailbreak paths, including /var/jb and Cydia/Sileo/Zebra app directories."
                )
            ]
        }

        return matches.map { path in
            DetectionResult(
                id: "filesystem-\(path.replacingOccurrences(of: "/", with: "-"))",
                name: "Suspicious filesystem artifact",
                category: .filesystem,
                detected: true,
                severity: 5,
                explanation: "A known jailbreak-related path exists on the device.",
                technicalDetails: "Path exists: \(path)"
            )
        }
    }
}
