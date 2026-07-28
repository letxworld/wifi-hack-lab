use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use pbkdf2::pbkdf2_hmac;
use hmac::Hmac;
use sha1::Sha1;
use hex;

/// Compute the Pairwise Master Key (PMK) from passphrase and SSID.
/// WPA2 uses PBKDF2-HMAC-SHA1 with 4096 iterations and a salt = SSID.
/// Returns the PMK as a 64-character hex string (32 bytes).
#[pyfunction]
fn compute_pmk(passphrase: &str, ssid: &str) -> String {
    let salt = ssid.as_bytes();
    let mut pmk = [0u8; 32]; // 256-bit PMK
    pbkdf2_hmac::<Hmac<Sha1>>(
        passphrase.as_bytes(),
        salt,
        4096,  // WPA2 iteration count (fixed)
        &mut pmk,
    );
    hex::encode(pmk)
}

/// Verify whether a given passphrase matches a target PMK.
/// Returns true if the computed PMK matches the target PMK (hex-encoded).
#[pyfunction]
fn verify_passphrase(passphrase: &str, ssid: &str, target_pmk_hex: &str) -> bool {
    let computed = compute_pmk(passphrase, ssid);
    computed == target_pmk_hex
}

/// Batch verify multiple passphrases against a target PMK.
/// Returns the first matching password, or None if none match.
#[pyfunction]
fn crack_batch(passphrases: Vec<String>, ssid: &str, target_pmk_hex: &str) -> Option<String> {
    for pwd in passphrases {
        if verify_passphrase(&pwd, ssid, target_pmk_hex) {
            return Some(pwd);
        }
    }
    None
}

/// Python module definition.
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(compute_pmk, m)?)?;
    m.add_function(wrap_pyfunction!(verify_passphrase, m)?)?;
    m.add_function(wrap_pyfunction!(crack_batch, m)?)?;
    Ok(())
}