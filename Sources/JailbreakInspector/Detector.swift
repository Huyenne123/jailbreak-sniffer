import Foundation

public protocol Detector {
    func run() -> [DetectionResult]
}
