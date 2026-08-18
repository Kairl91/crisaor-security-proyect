#!/usr/bin/env python3
import os

# Blacklist base para el motor de prueba de 醋
# En fases avanzadas, esta lista se descargará dinámicamente desde IOCs públicos
C2_BLACKLIST = [
    "185.220.101.5",
    "45.33.32.156",
    "192.0.2.1"
]

def hex_to_ip(hex_ip):
    """Converts a hexadecimal IP string from /proc/net/tcp to a human-readable IP."""
    try:
        r = int(hex_ip[6:8], 16)
        g = int(hex_ip[4:6], 16)
        b = int(hex_ip[2:4], 16)
        a = int(hex_ip[0:2], 16)
        return f"{r}.{g}.{b}.{a}"
    except:
        return "0.0.0.0"

def hex_to_port(hex_port):
    """Converts a hexadecimal port string to an integer port."""
    try:
        return int(hex_port, 16)
    except:
        return 0

def scan_active_sockets():
    """
    Scans active network connections and compares foreign IPs against C2 threat lists.
    """
    print("[*] Scanning and auditing active network sockets...")
    
    net_tcp_path = "/proc/net/tcp"
    
    if not os.path.exists(net_tcp_path):
        print("[!] Error: /proc/net/tcp not accessible.")
        return

    try:
        with open(net_tcp_path, "r") as file:
            lines = file.readlines()[1:] # Skip header
            
        print(f"[+] Active TCP sockets detected: {len(lines)}")
        print("    [Index] Local Address       -> Foreign Address     [Status]")
        print("    -----------------------------------------------------------------")
        
        for idx, line in enumerate(lines[:10]):
            parts = line.strip().split()
            
            local_ip_hex, local_port_hex = parts[1].split(":")
            foreign_ip_hex, foreign_port_hex = parts[2].split(":")
            
            local_ip = hex_to_ip(local_ip_hex)
            local_port = hex_to_port(local_port_hex)
            
            foreign_ip = hex_to_ip(foreign_ip_hex)
            foreign_port = hex_to_port(foreign_port_hex)
            
            full_foreign = f"{foreign_ip}:{foreign_port}"
            
            # Verificación de amenaza
            if foreign_ip in C2_BLACKLIST:
                status = "[!] C2 THREAT DETECTED!"
            elif foreign_ip == "0.0.0.0":
                status = "[+] LISTENING (Local)"
            else:
                status = "[+] OUTBOUND (CLEAN)"
            
            print(f"    [{idx+1:02d}] {local_ip}:{local_port:<5} -> {full_foreign:<20} {status}")
            
    except Exception as e:
        print(f"[!] Failed to read sockets: {e}")

if __name__ == "__main__":
    print("=== 醋 (Cù) Network Monitor Module ===")
    scan_active_sockets()
