# Crisaor Security Engine (Project 醋)

A lightweight zero-trust security engine and kernel network auditor designed for Linux systems.

## Features

- **Kernel Socket Audit:** Parses `/proc/net/tcp` to inspect low-level active network connections.
- **Process Correlation:** Maps raw socket inodes directly to system Process IDs (PIDs) and binary names via `/proc/[pid]/fd`.
- **Threat Matching & Deception Engine:** Evaluates foreign IP addresses against Indicator of Compromise (IoC) blacklists and triggers isolated sinkhole containment.
- **Native C Integration:** Connects Python with a shared C dynamic library (`libmemoria.so`) via `ctypes` for direct process memory verification.

## Architecture & Project Structure

- `main.py`: Core entry point, privilege verification, and module orchestrator.
- `modulo_red.py`: Kernel network parser and PID correlation engine.
- `modulo_engano.py`: Threat matching logic and sinkhole isolation handler.
- `modulo_memoria.c`: Native C code for process memory map verification.

## Requirements & Building

- Linux OS (Debian/Ubuntu-based)
- Python 3.x
- GCC (GNU Compiler Collection)

### Compiling the C Dynamic Library

Before running the engine, compile the C module:

```bash
gcc -shared -fPIC -o libmemoria.so modulo_memoria.c
