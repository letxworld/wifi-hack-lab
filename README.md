# WiFi Hack Lab — Educational Security Tool

> Learn how WPA2-PSK handshakes work by attacking your *own* network in a safe, controlled environment.

---

## 🧪 What This Tool Does

- **Captures** the 4-way handshake from a target access point (your own WiFi)
- **Cracks** the password using dictionary + rule-based attacks (Rust core for speed)
- **Teaches** you *why* weak passwords fail and *how* strong passwords resist attacks
- **Spins up** an isolated lab AP so you can test without touching your real network

---

## ⚠️ Legal & Ethical Disclaimer

**This tool is for educational purposes only.**  
Use it **only** on:
- Networks you **own**
- Networks you have **explicit written permission** to test

Unauthorized access to WiFi networks is **illegal** in most countries (CFAA, NIS Directive, etc.).  
The author assumes **zero liability** for misuse.

---

## 🚀 Quick Start (Capture + Crack)

```bash
# Install
pip install -r requirements.txt
maturin develop

# Capture handshake and crack (replace with your own AP details)
wifi-hack-lab hack --interface wlan0mon --bssid AA:BB:CC:DD:EE:FF --ssid MyWiFi --wordlist dictionaries/rockyou.txt

```
## 📂 Project Structure
```
wifi-hack-lab/
├── src/                 # Rust core (PMK computation, verification)
├── wifi_hack_lab/       # Python CLI, sniffer, visualizer, lab mode
├── dictionaries/        # Wordlists + rule engine
├── tests/               # Unit tests (Python + Rust integration)
├── .github/workflows/   # CI: auto-build + test on push
└── README.md            # You are here
```

## 🧠 How It Works (Under the Hood)

    1.Capture — scapy sniffs 802.11 packets, extracts EAPOL frames (4-way handshake)

    2.Extract — PMKID / handshake is parsed and prepared for cracking

    3.Crack — Rust-based engine computes PMK for each dictionary entry and compares MIC

    4.Display — If found, password is shown with timing and attack metrics

## 🛠️ Tech Stack
```
-Layer	Technology
-CLI / orchestration	Python + Click
-Packet capture	Scapy
-Cracking core	Rust + PyO3 (PBKDF2, HMAC-SHA1)
-Terminal UI	Rich
-Testing	Pytest + cargo test
-CI/CD	GitHub Actions
```

## 📚 Educational Resources (cited in code)
```
    IEEE 802.11-2016 — WiFi standard

    Vanhoef & Piessens (2017) — Key Reinstallation Attacks (KRACK)

    Hashcat — benchmarking and attack modes

    NIST SP 800-63b — password strength guidelines
```
## 🤝 Contributing

**Pull requests are welcome — especially:**

    -Better rule engines

    -GPU support via CUDA/OpenCL

    -Lab mode improvements (Dockerized test AP)

## 📄 License

MIT — with an ethics clause (see LICENSE file)
⭐ Show Your Support

**If this helped you learn something, star the repo — it motivates me to keep improving it.**

`--Built with ❤️ for education, not exploitation.--`