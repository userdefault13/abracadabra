import Foundation
import LocalAuthentication

// abracadabra biometric gate.
// Usage: auth-helper "<reason>" [timeoutSeconds]
// Prints "OK" and exits 0 on success, "DENY <detail>" and exits 1 otherwise.

let args = CommandLine.arguments
let reason = args.count > 1 ? args[1] : "Authenticate to access abracadabra"
let timeout: TimeInterval = args.count > 2 ? (TimeInterval(args[2]) ?? 30) : 30

let context = LAContext()
context.localizedReason = reason
context.localizedFallbackTitle = "Use Password"

var canEvaluateError: NSError?
let policy: LAPolicy
if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &canEvaluateError) {
    policy = .deviceOwnerAuthenticationWithBiometrics
} else if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &canEvaluateError) {
    // No Touch ID available (or not enrolled): fall back to passcode
    policy = .deviceOwnerAuthentication
} else {
    FileHandle.standardOutput.write("DENY biometrics unavailable: \(canEvaluateError?.localizedDescription ?? "unknown")\n".data(using: .utf8)!)
    exit(1)
}

let semaphore = DispatchSemaphore(value: 0)
var authSucceeded = false
var authErrorDescription: String = ""

context.evaluatePolicy(policy, localizedReason: reason) { success, evaluationError in
    authSucceeded = success
    if let err = evaluationError {
        authErrorDescription = err.localizedDescription
    }
    semaphore.signal()
}

_ = semaphore.wait(timeout: .now() + timeout)

if authSucceeded {
    FileHandle.standardOutput.write("OK\n".data(using: .utf8)!)
    exit(0)
} else {
    FileHandle.standardOutput.write("DENY \(authErrorDescription)\n".data(using: .utf8)!)
    exit(1)
}
