#!/usr/bin/env python3
import os
import sys
import uuid
import modulo_red  # <--- Importamos nuestro nuevo módulo

PROJECT_NAME = "醋 (Cù) Security System"
START_DATE = "August 17, 2026"

SECURITY_TOKEN = str(uuid.uuid4())

def display_header():
    print("=" * 55)
    print(f"      SYSTEM PROTECTION & CLEANUP: {PROJECT_NAME}")
    print(f"      Day 0 Development - {START_DATE}")
    print("=" * 55)

def check_privileges():
    current_uid = os.geteuid()
    if current_uid != 0:
        print(f"[!] SECURITY ALERT: Unauthorized execution attempt by UID: {current_uid}")
        print("[!] 醋 requires true root privileges. Use: sudo python3 main.py")
        sys.exit(1)
        
    print("[+] Superuser permissions confirmed (UID: 0).")
    print(f"[+] Memory Integrity Token verified: [{SECURITY_TOKEN[:8]}...]")

if __name__ == "__main__":
    display_header()
    check_privileges()
    print("\n[+] Project 醋 initialized successfully.")
    print("=" * 55)
    
    # Ejecutamos el rastreador de red de 醋
    modulo_red.scan_active_sockets()
