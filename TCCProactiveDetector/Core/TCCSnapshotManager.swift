
//
//  TCCSnapshotManager.swift
//  TCCProactiveDetector
//

import Foundation
import SQLite3

// Структура для одной записи
struct TCCEntry: Hashable {
    let service: String
    let client: String
    let authValue: Int
}

final class TCCSnapshotManager {

    // Используем тестовую базу
    private let tccPath = ("~/Documents/TCC_test.db")
        .expandingTildeInPath()
    private var baseline: Set<TCCEntry> = []

    // MARK: - Public API

    /// Создаёт baseline snapshot таблицы TCC
    func createBaseline() {
        baseline = readTCCEntries()
        log("Baseline snapshot created (\(baseline.count) entries)")
    }

    /// Возвращает изменения по сравнению с baseline
    func detectChanges() -> Set<TCCEntry> {
        let current = readTCCEntries()
        let diff = current.subtracting(baseline)
        if !diff.isEmpty {
            log("Detected \(diff.count) new/changed entries")
        }
        return diff
    }

    // MARK: - Core logic

    /// Чтение всех записей из TCC.db
    private func readTCCEntries() -> Set<TCCEntry> {
        var db: OpaquePointer?
        var result = Set<TCCEntry>()

        guard sqlite3_open(tccPath, &db) == SQLITE_OK else {
            log("Failed to open TCC.db at path \(tccPath)")
            return result
        }

        defer {
            sqlite3_close(db)
        }

        let query = "SELECT service, client, auth_value FROM access"

        var statement: OpaquePointer?
        if sqlite3_prepare_v2(db, query, -1, &statement, nil) == SQLITE_OK {
            defer { sqlite3_finalize(statement) }

            while sqlite3_step(statement) == SQLITE_ROW {
                let service = String(cString: sqlite3_column_text(statement, 0))
                let client = String(cString: sqlite3_column_text(statement, 1))
                let authValue = Int(sqlite3_column_int(statement, 2))

                let entry = TCCEntry(service: service, client: client, authValue: authValue)
                result.insert(entry)
            }
        } else {
            log("Failed to prepare SQL statement")
        }

        return result
    }

    // MARK: - Logging

    private func log(_ message: String) {
        print("[TCCSnapshotManager] \(message)")
    }
}

