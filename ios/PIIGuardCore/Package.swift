// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "PIIGuardCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "PIIGuardCore", targets: ["PIIGuardCore"]),
    ],
    targets: [
        .target(name: "PIIGuardCore"),
        .testTarget(name: "PIIGuardCoreTests", dependencies: ["PIIGuardCore"]),
    ]
)
