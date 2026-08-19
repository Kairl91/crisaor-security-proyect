# Crisaor Security Engine (Project 醋)

A lightweight kernel-level security engine designed to detect, isolate, and neutralize military-grade spyware, advanced persistent threats (APTs), and government-sponsored surveillance tools.

---

## 🎯 Ultimate Project Goal & Vision

Commercial antivirus software relies on signature databases that fail against targeted, zero-day, and state-sponsored malware. **Crisaor Engine** is developed to be the ultimate sovereign defense tool for **journalists, human rights defenders, activists, and privacy-conscious users** targeted by high-level espionage software like **Pegasus** or **Predator**.

### Core Pillars:
- **Military & Government-Grade Defense:** Deep kernel-level visibility bypassing standard user-space evasion techniques.
- **Zero-Trust Observability:** Live socket-to-PID correlation and native memory inspection without reliance on generic third-party frameworks.
- **Sovereign Protection for High-Risk Targets:** Tailored for individuals operating in hostile cyber environments where privacy is a matter of physical safety.

---

## 🚀 Current Features (Phase 4)

- **Kernel Socket Audit:** Parses `/proc/net/tcp` to audit active network connections at the lowest system level.
- **Process Correlation:** Maps raw socket inodes directly to Process IDs (PIDs) and binary names via `/proc/[pid]/fd`.
- **Deception & Threat Containment Engine:** Matches remote IP addresses against Indicator of Compromise (IoC) databases and triggers isolated sinkhole containment.
- **Native C Integration:** Interfaces Python with a compiled C dynamic library (`libmemoria.so`) via `ctypes` for direct memory map verification.
- **Persistent Logging & Network Time Validation:** Generates audit logs (`crisaor_audit.log`) using network-validated UTC timestamps.

---

## 🔮 Roadmap & Future Features

- [ ] **Daemon / Continuous Guardian Mode:** Background process loop for real-time memory and socket polling.
- [ ] **Active Firewall Containment:** Real-time dynamic `iptables` and eBPF blocking for instant thread termination.
- [ ] **Heuristic Process Hollowing Detection:** Inspecting process memory maps to detect payload injection and legitimate process hijacking.
- [ ] **Encrypted Audit Vault:** Encrypted log storage to prevent anti-forensic tampering by advanced malware.

---

## 🛠️ Architecture & Project Structure

- `main.py`: Core orchestrator, privilege enforcement, and module manager.
- `modulo_red.py`: Kernel network parser and PID correlation engine.
- `modulo_engano.py`: Threat matching logic and sinkhole isolation handler.
- `modulo_memoria.c`: Native C dynamic engine for process memory verification.
- `modulo_log.py`: ANSI terminal interface and network-validated persistent logger.

---

## ⚙️ Building & Execution

### 1. Compile the C Native Module
```bash
gcc -shared -fPIC -o libmemoria.so modulo_memoria.c
