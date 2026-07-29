//
//  AlertCenter.swift
//  TCCProactiveDetector
//
//  Created by Michael on 06/01/2026.
//


import Foundation

final class AlertCenter {
    func sendAlert(message: String, riskScore: Int) {
        print("🚨 PROACTIVE ALERT")
        print("Risk-score: \(riskScore)")
        print("Reason: \(message)")
    }
}
