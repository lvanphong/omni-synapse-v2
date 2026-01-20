// Â© 2026 Korvex | Ultra-Low-Latency Core | FREEZE v1.1 (HMAC Secured)

mod platform;
mod audit;
mod security;
mod tracking;

use core::arch::x86_64::{_rdtsc, _mm_lfence};
use core::sync::atomic::{AtomicU64, Ordering};
use actix_web::{App, HttpServer, HttpResponse, Responder, post, HttpRequest, web};
use std::fs::{OpenOptions, File};
use std::io::{Write, BufReader};
use serde::{Serialize, Deserialize};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::HashMap;
use std::net::IpAddr;
use dashmap::DashMap;

// Criptografie
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// --- CONFIGURARE ---
const LOG_PATH: &str = r"E:\korvex\Korvex Omni-Synapse v2.0\korvex_security_audit.json";
const LICENSE_DB: &str = r"E:\korvex\licenses.json";
const SYSTEM_AUDIT_KEY: u64 = 16045690984503098046;
const HMAC_SECRET: &[u8] = b"KORVEX_ULTRA_SECRET_2026_DO_NOT_SHARE"; 

static DNA_COUNTER: AtomicU64 = AtomicU64::new(1);

// --- STRUCTURI DATE ---

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
enum LicenseTier { Basic, Pro, Enterprise }

#[derive(Deserialize)]
struct LicenseRaw {
    token: String,
    tier: LicenseTier,
    max_requests: u64,
    expiration: u64,
}

struct LicenseState {
    tier: LicenseTier,
    request_count: AtomicU64,
    max_requests: u64,
    expiration: u64,
}

#[derive(Serialize)]
struct AuditEntry {
    timestamp: String,
    ip: String,
    event: String,
    license: String,
    cycles: u64,
}

// --- ENGINE MANAGERS ---

struct LicenseManager {
    active_licenses: DashMap<String, Arc<LicenseState>>,
}

impl LicenseManager {
    fn new() -> Self {
        let manager = Self { active_licenses: DashMap::new() };
        manager.load_from_file();
        manager
    }

    fn load_from_file(&self) {
        if let Ok(file) = File::open(LICENSE_DB) {
            let reader = BufReader::new(file);
            if let Ok(licenses) = serde_json::from_reader::<_, Vec<LicenseRaw>>(reader) {
                for l in licenses {
                    self.active_licenses.insert(l.token, Arc::new(LicenseState {
                        tier: l.tier,
                        request_count: AtomicU64::new(0),
                        max_requests: l.max_requests,
                        expiration: l.expiration,
                    }));
                }
            }
        }
    }

    fn verify_hmac(&self, token: &str, provided_sig: &str) -> bool {
        let mut mac = HmacSha256::new_from_slice(HMAC_SECRET).expect("HMAC Error");
        mac.update(token.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());
        expected_sig == provided_sig
    }

    fn check_access(&self, key: &str) -> (bool, String) {
        if let Some(state) = self.active_licenses.get(key) {
            let now = chrono::Utc::now().timestamp() as u64;
            if now > state.expiration { return (false, "402_LICENSE_EXPIRED".to_string()); }

            if state.tier == LicenseTier::Basic {
                let current = state.request_count.fetch_add(1, Ordering::Relaxed);
                if current >= state.max_requests { return (false, "429_LIMIT_REACHED".to_string()); }
            }
            return (true, "VALID".to_string());
        }
        (false, "401_INVALID_LICENSE".to_string())
    }
}

struct BanManager {
    attempts: Mutex<HashMap<IpAddr, (u32, std::time::Instant)>>,
}

// --- HOT-PATH ---

#[inline(always)]
fn rdtsc_ordered() -> u64 {
    unsafe { _mm_lfence(); let t = _rdtsc(); _mm_lfence(); t }
}

#[no_mangle]
pub extern "C" fn handle_fire_request(token: u64) -> (u64, bool) {
    let start = rdtsc_ordered();
    if token != SYSTEM_AUDIT_KEY { return (rdtsc_ordered() - start, false); }
    let id = DNA_COUNTER.fetch_add(1, Ordering::Relaxed);
    unsafe { 
        crate::platform::PLATFORM_VALVES
            .get_unchecked((id as usize) & 31)
            .try_admit(id); 
    }
    (rdtsc_ordered() - start, true)
}

// --- HANDLER PORT ---

#[post("/fire")]
async fn fire_handler(
    req: HttpRequest,
    log_sender: web::Data<Sender<AuditEntry>>,
    ban_mgr: web::Data<BanManager>,
    lic_mgr: web::Data<LicenseManager>,
) -> impl Responder {
    let ip = req.peer_addr().map(|a| a.ip()).unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0,0,0,0)));

    // 1. Auto-Ban
    {
        let mut map = ban_mgr.attempts.lock().unwrap();
        let entry = map.entry(ip).or_insert((0, std::time::Instant::now()));
        if entry.1.elapsed().as_secs() > 60 { *entry = (0, std::time::Instant::now()); }
        if entry.0 >= 5 { return HttpResponse::Forbidden().body("IP_BANNED_BY_KORVEX"); }
    }

    // 2. Headere & HMAC Integrity
    let lic_key = req.headers().get("X-Korvex-License").and_then(|h| h.to_str().ok()).unwrap_or("");
    let lic_sig = req.headers().get("X-Korvex-Signature").and_then(|h| h.to_str().ok()).unwrap_or("");

    if !lic_mgr.verify_hmac(lic_key, lic_sig) {
        return HttpResponse::Unauthorized().body("CRYPTOGRAPHIC_SIGNATURE_MISMATCH");
    }

    // 3. License Logic
    let (lic_ok, lic_msg) = lic_mgr.check_access(lic_key);
    if !lic_ok { return HttpResponse::PaymentRequired().body(lic_msg); }

    // 4. Hot-Path Execution
    let token_val: u64 = req.headers().get("X-Korvex-Token").and_then(|h| h.to_str().ok()).and_then(|s| s.parse().ok()).unwrap_or(0);
    let (cycles, authorized) = handle_fire_request(token_val);

    // 5. Async Audit
    let _ = log_sender.send(AuditEntry {
        timestamp: chrono::Local::now().to_rfc3339(),
        ip: ip.to_string(),
        event: if authorized { "successsS".into() } else { "BREACH".into() },
        license: lic_key.to_string(),
        cycles,
    });

    if !authorized {
        ban_mgr.attempts.lock().unwrap().entry(ip).and_modify(|e| e.0 += 1);
        return HttpResponse::Unauthorized().body("SECURITY_BREACH_DETECTED");
    }

    HttpResponse::Ok().insert_header(("X-Korvex-Cycles", cycles.to_string())).body("ADMITTED")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let (tx, rx) = mpsc::channel::<AuditEntry>();
    let lic_manager = Arc::new(LicenseManager::new());
    
    thread::spawn(move || {
        let mut file = OpenOptions::new().create(true).append(true).open(LOG_PATH).unwrap();
        while let Ok(entry) = rx.recv() {
            if let Ok(j) = serde_json::to_string(&entry) { let _ = writeln!(file, "{}", j); }
        }
    });

    println!("==================================================");
    println!("ðŸ KORVEX OMNI-SYNAPSE v2.0 | COMMERCIAL CORE");
    println!("ðŸ” Mode: AES-HMAC Integrity Enabled");
    println!("ðŸ›¡ï¸  Auto-Ban & Audit-DNA: ACTIVE");
    println!("==================================================");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(tx.clone()))
            .app_data(web::Data::new(BanManager { attempts: Mutex::new(HashMap::new()) }))
            .app_data(web::Data::new(lic_manager.clone()))
            .service(fire_handler)
    })
    .workers(32).bind("0.0.0.0:8080")?.run().await
}

