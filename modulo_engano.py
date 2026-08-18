#!/usr/bin/env python3

# Lista de IoCs (IPs sospechosas o C2 simulados para pruebas)
BLACK_LIST_IOCS = [
    "34.107.243.93",
    "199.232.93.91",
    "185.220.101.5"
]

def evaluar_amenaza(ip_remota):
    """Verifica si una IP remota se encuentra en la lista de amenazas."""
    ip_limpia = ip_remota.split(":")[0]
    if ip_limpia in BLACK_LIST_IOCS:
        return True, "ALERT: IoC Detected"
    return False, "CLEAN"

def aislar_socket(pid, ip_remota):
    """Simula la intercepción y aislamiento de un socket sospechoso."""
    print(f"    └─> [!] [SINKHOLE] Intercepting traffic to {ip_remota} (PID: {pid})")
    print(f"    └─> [+] [ACTION] Socket isolated. Process {pid} flagged for containment.")
