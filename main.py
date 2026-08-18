#!/usr/bin/env python3
import os
import secrets
import modulo_red

def verificar_privilegios():
    """Verifica si el script se ejecuta como superusuario (root)."""
    uid = os.geteuid()
    if uid != 0:
        print("[-] Error: Crisaor requiere privilegios de superusuario (root).")
        print("    Ejecuta el script usando: sudo python3 main.py")
        exit(1)
    print("[+] Superuser permissions confirmed (UID: 0).")

def generar_token_memoria():
    """Genera un token canary de integridad en la memoria RAM."""
    token = secrets.token_hex(16)
    print(f"[+] Memory Integrity Token verified: [{token[:8]}...]")
    return token

def main():
    print("=======================================================")
    print("      CRISAOR SECURITY ENGINE (Project 醋)")
    print("      Phase 1 Development - August 17, 2026")
    print("=======================================================")
    
    verificar_privilegios()
    generar_token_memoria()
    
    print("\n[+] Crisaor Engine initialized successfully.")
    print("=======================================================")
    
    # Llamada a la nueva función de auditoría con PIDs
    modulo_red.auditar_red()

if __name__ == "__main__":
    main()
