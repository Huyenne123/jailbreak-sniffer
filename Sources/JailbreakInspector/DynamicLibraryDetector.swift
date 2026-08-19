import Foundation
import MachO

public struct DynamicLibraryDetector: Detector {
    private let suspiciousLibraryNames = [
        "substrate",
        "mobile_substrate",
        "mobilesubstrate",
        "cycript",
        "frida",
        "libfrida",
        "libsubstrate",
        "cydia",
        "sileo",
        "zebra",
        "undecimus"
    ]

    public init() {}

    public func run() -> [DetectionResult] {
        var matches: [String] = []

        for index in 0..<_dyld_image_count() {
            guard let imageNamePointer = _dyld_get_image_name(index) else {
                continue
            }

            let imageName = String(cString: imageNamePointer)
            let lastComponent = URL(fileURLWithPath: imageName).lastPathComponent.lowercased()

            if suspiciousLibraryNames.contains(where: { lastComponent.contains($0) }) {
                matches.append(lastComponent)
            }
        }

        let uniqueMatches = Array(Set(matches)).sorted()

        if uniqueMatches.isEmpty {
            return [
                DetectionResult(
                    id: "dyld-clean",
                    name: "Loaded libraries",
                    category: .dynamicLibraries,
                    detected: false,
                    severity: 0,
                    explanation: "No suspicious dynamic libraries were observed in the current process.",
                    technicalDetails: "The detector only flags libraries with names commonly associated with jailbreak tooling."
                )
            ]
        }

        return [
            DetectionResult(
                id: "dyld-suspicious",
                name: "Suspicious dynamic libraries",
                category: .dynamicLibraries,
                detected: true,
                severity: 6,
                explanation: "The process is loading libraries that resemble jailbreak or injection tooling.",
                technicalDetails: uniqueMatches.joined(separator: ", ")
            )
        ]
    }
}
