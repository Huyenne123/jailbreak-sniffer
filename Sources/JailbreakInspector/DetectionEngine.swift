import Foundation

public final class DetectionEngine {
    private let detectors: [Detector]

    public init(detectors: [Detector] = [
        IOSSecuritySuiteDetector(),
        FilesystemDetector(),
        DynamicLibraryDetector(),
        SandboxDetector(),
        URLSchemeDetector(),
        EnvironmentDetector(),
        IntegrityDetector()
    ]) {
        self.detectors = detectors
    }

    public func evaluate() -> [DetectionResult] {
        detectors.flatMap { $0.run() }
    }
}
