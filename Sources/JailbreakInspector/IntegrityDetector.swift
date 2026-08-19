import Foundation

public struct IntegrityDetector: Detector {
    public init() {}

    public func run() -> [DetectionResult] {
        let executablePath = Bundle.main.executableURL?.path ?? ""
        let bundlePath = Bundle.main.bundleURL.path
        let executableWritable = !executablePath.isEmpty && FileManager.default.isWritableFile(atPath: executablePath)
        let bundleWritable = FileManager.default.isWritableFile(atPath: bundlePath)

        if executableWritable || bundleWritable {
            return [
                DetectionResult(
                    id: "integrity-modified",
                    name: "Code integrity check",
                    category: .integrity,
                    detected: true,
                    severity: 7,
                    explanation: "The app bundle or executable is writable, which indicates the runtime or bundle may have been tampered with.",
                    technicalDetails: "Executable path writable: \(executableWritable) | Bundle path writable: \(bundleWritable)"
                )
            ]
        }

        return [
            DetectionResult(
                id: "integrity-clean",
                name: "Code integrity check",
                category: .integrity,
                detected: false,
                severity: 0,
                explanation: "The app bundle and executable do not present an obvious writable-tampering condition.",
                technicalDetails: "Executable path writable: \(executableWritable) | Bundle path writable: \(bundleWritable)"
            )
        ]
    }
}
