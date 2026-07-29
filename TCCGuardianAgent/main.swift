import Foundation

let snapshotManager = TCCSnapshotManager()
let fsMonitor = FSEventsMonitor()
let processMonitor = ProcessMonitor()

processMonitor.onSuspiciousProcess = {
    print("🚨 ALERT:", $0)
}

fsMonitor.onSuspiciousEvent = { event in
    print("➡️ Event:", event)
}

snapshotManager.createBaseline()
fsMonitor.start()
processMonitor.start()

// 🔥 CLI LIFETIME
dispatchMain()
