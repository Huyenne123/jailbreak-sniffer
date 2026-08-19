# Jailbreak Inspector

Jailbreak Inspector is a SwiftUI iOS security-diagnostic app built to evaluate a device for jailbreak evidence without assuming a single indicator is conclusive. The app is intentionally evidence-based: each sensor emits a `DetectionResult` independently, and the results are displayed as a structured security summary.

## Project status

This repository began empty, so a fresh SwiftUI iOS project structure was created using Swift Package Manager and the IOSSecuritySuite dependency.

## Runtime platform

- Swift tools version: 5.9
- Deployment target: iOS 15+
- UI framework: SwiftUI
- Package manager: Swift Package Manager
- External dependency: IOSSecuritySuite

## Architecture

- Evidence model: `DetectionResult`
- Category taxonomy: jailbreak, filesystem, runtime, dynamic libraries, sandbox, debugger, integrity, environment
- Detection engine: `DetectionEngine`
- Module detectors: IOSSecuritySuite, filesystem, dynamic libraries, sandbox, URL schemes, environment, integrity

## Dependency integration

The package manifest adds IOSSecuritySuite via SPM:

```swift
.package(url: "https://github.com/securing/IOSSecuritySuite.git", from: "1.0.0")
```

The app includes the required `LSApplicationQueriesSchemes` entries for suspicious jailbreak package-manager URLs.

## Run locally

Open the project in Xcode on macOS and build the `JailbreakInspectorApp` target. The package is ready to integrate with the iOS SwiftUI app lifecycle.
