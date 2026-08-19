import Foundation
import UIKit

public struct URLSchemeDetector: Detector {
    private let suspiciousSchemes = [
        "cydia://",
        "sileo://",
        "zbra://",
        "filza://",
        "undecimus://"
    ]

    public init() {}

    public func run() -> [DetectionResult] {
        let matches = suspiciousSchemes.filter { scheme in
            guard let url = URL(string: scheme) else { return false }
            return UIApplication.shared.canOpenURL(url)
        }

        if matches.isEmpty {
            return [
                DetectionResult(
                    id: "schemes-clean",
                    name: "Jailbreak URL schemes",
                    category: .environment,
                    detected: false,
                    severity: 0,
                    explanation: "No known jailbreak package-manager URL schemes were found to be openable. This detector can produce false negatives and false positives.",
                    technicalDetails: "Schemes searched: cydia://, sileo://, zbra://, filza://, undecimus://"
                )
            ]
        }

        return [
            DetectionResult(
                id: "schemes-suspicious",
                name: "Jailbreak package manager scheme detected",
                category: .environment,
                detected: true,
                severity: 4,
                explanation: "A jailbreak-related URL scheme is available on the device. This is supporting evidence and not definitive proof of compromise.",
                technicalDetails: matches.joined(separator: ", ")
            )
        ]
    }
}
