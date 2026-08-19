import Foundation
import IOSSecuritySuite

public struct IOSSecuritySuiteDetector: Detector {
    public init() {}

    public func run() -> [DetectionResult] {
        var findings: [DetectionResult] = []

        let jailbreakStatus = IOSSecuritySuite.amIJailbrokenWithFailedChecks()
        findings.append(
            DetectionResult(
                id: "ios-jailbreak",
                name: "Jailbreak check",
                category: .jailbreak,
                detected: jailbreakStatus.jailbroken,
                severity: jailbreakStatus.jailbroken ? 9 : 0,
                explanation: jailbreakStatus.jailbroken
                    ? "The IOSSecuritySuite jailbreak detector reported a jailbreak condition."
                    : "No jailbreak condition was reported by IOSSecuritySuite.",
                technicalDetails: jailbreakStatus.jailbroken
                    ? jailbreakStatus.failedChecks.map { String(describing: $0) }.joined(separator: ", ")
                    : "No jailbreak indicators reported."
            )
        )

        let debuggerDetected = IOSSecuritySuite.amIDebugged()
        findings.append(
            DetectionResult(
                id: "ios-debugger",
                name: "Debugger check",
                category: .debugger,
                detected: debuggerDetected,
                severity: debuggerDetected ? 8 : 0,
                explanation: debuggerDetected
                    ? "The process appears to be attached to a debugger or instrumentation tool."
                    : "No active debugger was detected.",
                technicalDetails: debuggerDetected ? "IOSSecuritySuite.amIDebugged() returned true." : nil
            )
        )

        let reverseStatus = IOSSecuritySuite.amIReverseEngineeredWithFailedChecks()
        findings.append(
            DetectionResult(
                id: "ios-reverse-engineering",
                name: "Reverse engineering indicators",
                category: .runtime,
                detected: reverseStatus.reverseEngineered,
                severity: reverseStatus.reverseEngineered ? 7 : 0,
                explanation: reverseStatus.reverseEngineered
                    ? "The device or app environment shows signs associated with reverse engineering tooling."
                    : "No reverse-engineering indicators were reported.",
                technicalDetails: reverseStatus.reverseEngineered
                    ? reverseStatus.failedChecks.map { String(describing: $0) }.joined(separator: ", ")
                    : nil
            )
        )

        let emulatorDetected = IOSSecuritySuite.amIRunInEmulator()
        findings.append(
            DetectionResult(
                id: "ios-emulator",
                name: "Emulator detection",
                category: .environment,
                detected: emulatorDetected,
                severity: emulatorDetected ? 5 : 0,
                explanation: emulatorDetected
                    ? "The app is running in an emulator environment rather than a physical device."
                    : "The app is not reporting an emulator runtime.",
                technicalDetails: emulatorDetected ? "IOSSecuritySuite.amIRunInEmulator() returned true." : nil
            )
        )

        return findings
    }
}
