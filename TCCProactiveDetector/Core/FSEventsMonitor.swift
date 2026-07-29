import Foundation
import CoreServices

struct RiskScore {
    private(set) var score: Double = 0.0

    // веса факторов (можно потом расширить)
    private let weights: [String: Double] = [
        "rootProcess": 0.4,
        "accessTCCdb": 0.3,
        "anomalyEnv": 0.2,
        "unknownApp": 0.1
    ]

    mutating func addEvent(factor: String) {
        let weight = weights[factor] ?? 0.0
        score += weight
    }

    mutating func reset() {
        score = 0
    }
}

final class FSEventsMonitor {

    private var stream: FSEventStreamRef?
    private let queue = DispatchQueue(label: "fsevents.monitor.queue")
    private var risk = RiskScore()
    private let pathToWatch = "/Users/michael/Documents/"

    var onSuspiciousEvent: ((String) -> Void)?

    func start() {
        print("[FSEventsMonitor] Monitoring started")

        var context = FSEventStreamContext(
            version: 0,
            info: UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque()),
            retain: nil,
            release: nil,
            copyDescription: nil
        )

        stream = FSEventStreamCreate(
            kCFAllocatorDefault,
            { (_, clientInfo, numEvents, eventPathsPointer, eventFlagsPointer, _) in

                // Получаем ссылку на self
                let monitor = Unmanaged<FSEventsMonitor>
                    .fromOpaque(clientInfo!)
                    .takeUnretainedValue()

                // Преобразуем UnsafeMutableRawPointer в CFArray
                let cfArray = Unmanaged<CFArray>.fromOpaque(eventPathsPointer).takeUnretainedValue()
                let paths = cfArray as! [String]

                let flagsPointer = eventFlagsPointer // already non-optional UnsafePointer

                for i in 0..<numEvents {
                    let action = describeEvent(flags: flagsPointer[i])
                    let safePath = makePathRelativeToHome(paths[i])

                    print("⚠️ [FSEventsMonitor] \(action): \(safePath)")
                    monitor.onSuspiciousEvent?("\(action): \(safePath)")
                }

            },
            &context,
            [pathToWatch] as CFArray,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            0.1,
            FSEventStreamCreateFlags(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes)
        )




        guard let stream = stream else {
            print("[FSEventsMonitor] Failed to create stream")
            return
        }

        // 🔥 ВАЖНО: используем очередь, а НЕ main runloop
        FSEventStreamSetDispatchQueue(stream, queue)
        FSEventStreamStart(stream)
    }
}

private func makePathRelativeToHome(_ path: String) -> String {
    let homePath = FileManager.default.homeDirectoryForCurrentUser.path

    if path.hasPrefix(homePath) {
        return String(path.dropFirst(homePath.count))
    }

    return path
}
private func describeEvent(flags: FSEventStreamEventFlags) -> String {
    var actions: [String] = []

    if flags & UInt32(kFSEventStreamEventFlagItemCreated) != 0 {
        actions.append("CREATED")
    }
    if flags & UInt32(kFSEventStreamEventFlagItemModified) != 0 {
        actions.append("MODIFIED")
    }
    if flags & UInt32(kFSEventStreamEventFlagItemRemoved) != 0 {
        actions.append("DELETED")
    }
    if flags & UInt32(kFSEventStreamEventFlagItemRenamed) != 0 {
        actions.append("RENAMED")
    }
    if flags & UInt32(kFSEventStreamEventFlagItemInodeMetaMod) != 0 {
        actions.append("METADATA_CHANGED")
    }

    return actions.isEmpty ? "UNKNOWN" : actions.joined(separator: ", ")
}


extension String {
    func expandingTildeInPath() -> String {
        (self as NSString).expandingTildeInPath
    }
}

