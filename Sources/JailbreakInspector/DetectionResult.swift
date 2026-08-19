import Foundation

public enum DetectionCategory: String, CaseIterable, Codable {
    case jailbreak = "Jailbreak"
    case filesystem = "Filesystem"
    case runtime = "Runtime"
    case dynamicLibraries = "Dynamic Libraries"
    case sandbox = "Sandbox"
    case debugger = "Debugger"
    case integrity = "Integrity"
    case environment = "Environment"
}

public struct DetectionResult: Identifiable, Codable {
    public let id: String
    public let name: String
    public let category: DetectionCategory
    public let detected: Bool
    public let severity: Int
    public let explanation: String
    public let technicalDetails: String?

    public init(
        id: String,
        name: String,
        category: DetectionCategory,
        detected: Bool,
        severity: Int,
        explanation: String,
        technicalDetails: String? = nil
    ) {
        self.id = id
        self.name = name
        self.category = category
        self.detected = detected
        self.severity = severity
        self.explanation = explanation
        self.technicalDetails = technicalDetails
    }
}
