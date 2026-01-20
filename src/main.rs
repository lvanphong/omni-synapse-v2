mod auth;
mod audit;

use auth::license_gate::{LicenseGate, LicenseTier};
use audit::measure_latency;

fn main() {
    let mock_token = "KX-PRO-2026-01-ABCD1234";
    
    // --- PASUL 1: WARM-UP (Încălzirea Cache-ului) ---
    // Rulăm funcția de 1000 de ori înainte de măsurătoare
    for _ in 0..1000 {
        let _ = LicenseGate::validate_token(mock_token);
        let _ = (0..10).fold(0, |acc, x| acc ^ x);
    }

    // --- PASUL 2: MĂSURĂTOARE OFICIALĂ ---
    let total_cycles = measure_latency(|| {
        let tier = LicenseGate::validate_token(mock_token);
        if matches!(tier, LicenseTier::Invalid) { return; }
        let _ = (0..10).fold(0, |acc, x| acc ^ x);
    });

    println!("\n OMNI-SYNAPSE V2.0 FINAL AUDIT (Optimized)");
    println!("----------------------------------------------");
    println!("Total Latency: {} cycles", total_cycles);
    
    if total_cycles <= 109 {
        println!("STATUS: successsS (HFT Compliant )");
    } else {
        println!("STATUS: STILL ABOVE LIMIT  (Current: {})", total_cycles);
    }
}


