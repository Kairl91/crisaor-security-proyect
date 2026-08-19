#!/usr/bin/env python3
import os
import glob
import modulo_engano
import modulo_log

def obtener_nombre_proceso(pid):
    """Retrieves executable name from PID."""
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return "Unknown"

def hex_a_ip(hex_str):
    """Converts hex address from /proc/net/tcp to decimal format."""
    try:
        addr_hex, port_hex = hex_str.split(":")
        ip = ".".join(str(int(addr_hex[i:i+2], 16)) for i in range(6, -1, -2))
        port = int(port_hex, 16)
        return f"{ip}:{port}"
    except Exception:
        return hex_str

def mapear_sockets_a_pids():
    """Maps socket inodes to PIDs."""
    socket_map = {}
    for pid_path in glob.glob("/proc/[0-9]*"):
        pid = os.path.basename(pid_path)
        fd_dir = os.path.join(pid_path, "fd")
        try:
            for fd in os.listdir(fd_dir):
                link = os.readlink(os.path.join(fd_dir, fd))
                if link.startswith("socket:["):
                    inode = link[8:-1]
                    socket_map[inode] = pid
        except (PermissionError, FileNotFoundError):
            continue
    return socket_map

def auditar_red():
    """Audits active network sockets, correlates with PIDs, and logs events."""
    ruta_tcp = "/proc/net/tcp"
    if not os.path.exists(ruta_tcp):
        msg = "Unable to access kernel network interface."
        print(f"[-] Error: {msg}")
        modulo_log.registrar_evento("ERROR", msg)
        return

    socket_pids = mapear_sockets_a_pids()

    print("[*] Auditing active network sockets in kernel...")
    modulo_log.registrar_evento("INFO", "Initiated kernel network socket audit.")
    
    print(f"{'Local Address':<20} -> {'Foreign Address':<20} {'PID':<8} {'Process':<12} {'Status':<15}")
    print("-" * 80)

    with open(ruta_tcp, "r") as f:
        lineas = f.readlines()[1:]

    for linea in lineas:
        partes = linea.strip().split()
        if len(partes) >= 10:
            local = hex_a_ip(partes[1])
            remota = hex_a_ip(partes[2])
            inode = partes[9]
            
            pid = socket_pids.get(inode, "N/A")
            nombre_proc = obtener_nombre_proceso(pid) if pid != "N/A" else "System/Kernel"

            es_amenaza, estado = modulo_engano.evaluar_amenaza(remota)
            estado_coloreado = modulo_log.formatear_alerta(estado)

            print(f"{local:<20} -> {remota:<20} {pid:<8} {nombre_proc:<12} {estado_coloreado}")

            if es_amenaza:
                detalles = f"Threat detected from {local} -> {remota} (PID: {pid}, Process: {nombre_proc})"
                modulo_log.registrar_evento("WARNING", detalles)
                modulo_engano.aislar_socket(pid, remota)

if __name__ == "__main__":
    auditar_red()
