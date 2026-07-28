use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;  // <-- This requires sha2 crate
use hex;

// ... rest of code
#[pyfunction]
fn compute_pmk(passphrase: &str, ssid: &str) -> String {
    let salt = ssid.as_bytes();
    let mut pmk = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        passphrase.as_bytes(),
        salt,
        4096,
        &mut pmk,
    );
    hex::encode(pmk)
}

#[pyfunction]
fn verify_passphrase(passphrase: &str, ssid: &str, target_pmk_hex: &str) -> bool {
    let computed = compute_pmk(passphrase, ssid);
    computed == target_pmk_hex
}

#[pyfunction]
fn crack_batch(passphrases: Vec<String>, ssid: &str, target_pmk_hex: &str) -> Option<String> {
    for pwd in passphrases {
        if verify_passphrase(&pwd, ssid, target_pmk_hex) {
            return Some(pwd);
        }
    }
    None
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(compute_pmk, m)?)?;
    m.add_function(wrap_pyfunction!(verify_passphrase, m)?)?;
    m.add_function(wrap_pyfunction!(crack_batch, m)?)?;
    Ok(())
}