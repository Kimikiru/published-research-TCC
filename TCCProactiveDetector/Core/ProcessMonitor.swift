import Foundation

final class ProcessMonitor {

    var onSuspiciousProcess: ((String) -> Void)?

    private var baselinePIDs: Set<Int> = []

    func start() {
        print("[ProcessMonitor] Monitoring started")

        baselinePIDs = currentProcessPIDs()
        print("[ProcessMonitor] Baseline created (\(baselinePIDs.count) processes)")

        // ⬇️ ВАЖНО: обычный цикл, НИКАКИХ таймеров
        while true {
            checkProcesses()
            sleep(1)
        }
    }

    private func checkProcesses() {
        let processes = currentProcesses()

        for proc in processes {
            guard let pid = proc.pid else { continue }

            if !baselinePIDs.contains(pid) {
                baselinePIDs.insert(pid)
                print("👁 New process: \(proc.raw)")

                if isSuspicious(proc.raw) {
                    print("⚠️ Suspicious process detected: \(proc.raw)")
                    onSuspiciousProcess?(proc.raw)
                }
            }
        }
    }

    private func currentProcessPIDs() -> Set<Int> {
        Set(currentProcesses().compactMap { $0.pid })
    }

    private func currentProcesses() -> [(pid: Int?, raw: String)] {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/ps")
        task.arguments = ["-axo", "pid,user,command"]

        let pipe = Pipe()
        task.standardOutput = pipe

        do {
            try task.run()
            task.waitUntilExit()
        } catch {
            print("[ProcessMonitor] ps failed: \(error)")
            return []
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return [] }

        return output
            .split(separator: "\n")
            .dropFirst()
            .map {
                let str = $0.trimmingCharacters(in: .whitespaces)
                let pid = Int(str.split(separator: " ", maxSplits: 1).first ?? "")
                return (pid: pid, raw: str)
            }
    }

    private func isSuspicious(_ process: String) -> Bool {
        process.contains("osascript")
        || process.contains("sudo")
        || process.contains("tccutil")
    }
}
