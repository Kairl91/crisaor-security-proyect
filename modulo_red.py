#!/usr/bin/env python3
import os
import glob

def obtener_nombre_proceso(pid):
    """Obtiene el nombre del ejecutable a partir del PID."""
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return "Desconocido"

def hex_a_ip(hex_str):
    """Convierte la dirección IP en hexadecimal de /proc/net/tcp a formato decimal."""
    try:
        addr_hex, port_hex = hex_str.split(":")
        ip = ".".join(str(int(addr_hex[i:i+2], 16)) for i in range(6, -1, -2))
        port = int(port_hex, 16)
        return f"{ip}:{port}"
    except Exception:
        return hex_str

def mapear_sockets_a_pids():
    """Mapea los inodes de sockets a sus PIDs correspondientes."""
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
    """Lee /proc/net/tcp y muestra los sockets activos vinculados a su proceso."""
    ruta_tcp = "/proc/net/tcp"
    if not os.path.exists(ruta_tcp):
        print("[-] Error: No se puede acceder a la interfaz de red del kernel.")
        return

    socket_pids = mapear_sockets_a_pids()

    print("[*] Escaneando sockets de red activos en el kernel...")
    print(f"{'Local Address':<22} -> {'Foreign Address':<22} {'PID':<8} {'Proceso':<15}")
    print("-" * 70)

    with open(ruta_tcp, "r") as f:
        lineas = f.readlines()[1:] # Omitir encabezado

    for linea in lineas:
        partes = linea.strip().split()
        if len(partes) >= 10:
            local = hex_a_ip(partes[1])
            remota = hex_a_ip(partes[2])
            inode = partes[9]
            
            pid = socket_pids.get(inode, "N/A")
            nombre_proc = obtener_nombre_proceso(pid) if pid != "N/A" else "System/Kernel"

            print(f"{local:<22} -> {remota:<22} {pid:<8} {nombre_proc:<15}")

if __name__ == "__main__":
    auditar_red()
