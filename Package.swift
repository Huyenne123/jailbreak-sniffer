// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "JailbreakInspector",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "JailbreakInspector",
            targets: ["JailbreakInspector"]
        ),
        .executable(
            name: "JailbreakInspectorApp",
            targets: ["JailbreakInspectorApp"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/securing/IOSSecuritySuite.git", from: "1.0.0")
    ],
    targets: [
        .target(
            name: "JailbreakInspector",
            dependencies: [
                .product(name: "IOSSecuritySuite", package: "IOSSecuritySuite")
            ],
            path: "Sources/JailbreakInspector"
        ),
        .executableTarget(
            name: "JailbreakInspectorApp",
            dependencies: ["JailbreakInspector"],
            path: "Sources/JailbreakInspectorApp"
        )
    ]
)
