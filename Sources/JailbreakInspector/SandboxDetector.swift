import Foundation

public struct SandboxDetector: Detector {
    private let restrictedLocations = [
        "/private",
        "/var",
        "/usr/lib",
        "/Applications",
        "/Library"
    ]

    public init() {}

    public func run() -> [DetectionResult] {
        let writablePaths = restrictedLocations.filter { FileManager.default.isWritableFile(atPath: $0) }

        if writablePaths.isEmpty {
            return [
                DetectionResult(
                    id: "sandbox-clean",
                    name: "Sandbox write access",
                    category: .sandbox,
                    detected: false,
                    severity: 0,
                    explanation: "No unexpected write access to restricted system locations was observed.",
                    technicalDetails: "Tests are performed using safe read-only checks and never modify protected system files."
                )
            ]
        }

        return [
            DetectionResult(
                id: "sandbox-suspicious",
                name: "Unexpected writable system locations",
                category: .sandbox,
                detected: true,
                severity: 6,
                explanation: "The app appears to have write access to locations that are typically protected by the sandbox.",
                technicalDetails: writablePaths.joined(separator: ", ")
            )
        ]
    }
}
