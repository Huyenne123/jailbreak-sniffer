import Foundation

public struct EnvironmentDetector: Detector {
    private let suspiciousVariables = [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_PRINT_STATISTICS",
        "SUBSTRATE",
        "CYDIA",
        "SILEO",
        "ZBRA",
        "JAILBREAK"
    ]

    public init() {}

    public func run() -> [DetectionResult] {
        let matches = suspiciousVariables.filter { getenv($0) != nil }

        if matches.isEmpty {
            return [
                DetectionResult(
                    id: "env-clean",
                    name: "Environment variables",
                    category: .environment,
                    detected: false,
                    severity: 0,
                    explanation: "No suspicious environment variables were observed.",
                    technicalDetails: "Environment variables are supplemental evidence because they can be influenced by the runtime context."
                )
            ]
        }

        return [
            DetectionResult(
                id: "env-suspicious",
                name: "Suspicious environment variables",
                category: .environment,
                detected: true,
                severity: 3,
                explanation: "The process environment contains values commonly seen in modified or instrumented jailbreak environments.",
                technicalDetails: matches.joined(separator: ", ")
            )
        ]
    }
}
