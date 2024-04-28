// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "Fernet",
    products: [
        .library(
            name: "Fernet",
            targets: ["Fernet"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.0"),
    ],
    targets: [
        .target(
            name: "Fernet",
            dependencies: [
                .product(name: "CryptoSwift", package: "cryptoswift"),
            ]
        ),
        .testTarget(
            name: "FernetTests",
            dependencies: ["Fernet"]
        ),
    ]
)
