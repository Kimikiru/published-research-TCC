//
//  RuleEngine.swift
//  TCCProactiveDetector
//
//  Created by Michael on 06/01/2026.
//


import Foundation

final class RuleEngine {
    func calculateRisk(event: String) -> Int {
        var score = 0
        if event.contains("TCC_test") { score += 50 }
        if event.contains("sqlite3") { score += 40 }
        return score
    }
}
