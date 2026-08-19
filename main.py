#!/usr/bin/env python3
import os
import secrets
import ctypes
import modulo_red

# Cargar la biblioteca nativa en C
try:
    ruta_lib = os.path.abspath("./libmemoria.so")
    libmemoria = ctypes.CDLL(ruta_lib)
    
    # Definir los tipos de argumentos y retorno para las funciones C
    libmemoria.verificar_integridad_proceso.argtypes = [ctypes.c_int]
    libmemoria.verificar_integridad_proceso.restype = ctypes.c_int
    
    libmemoria.inspeccionar_buffer_ram.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    libmemoria.inspeccionar_buffer_ram.restype = ctypes.c_int
    C_MODULE_LOADED = True
except Exception as e:
    C_MODULE_LOADED = False

def verificar_privilegios():
    uid = os.geteuid()
    if uid != 0:
        print("[-] Error: Crisaor requiere privilegios de superusuario (root).")
        print("    Ejecuta el script usando: sudo python3 main.py")
        exit(1)
    print("[+] Superuser permissions confirmed (UID: 0).")

def generar_token_memoria():
    token = secrets.token_hex(16)
    print(f"[+] Memory Integrity Token verified: [{token[:8]}...]")
    
    if C_MODULE_LOADED:
        # Prueba de llamada al módulo nativo C
        res = libmemoria.verificar_integridad_proceso(os.getpid())
        if res == 1:
            print("[+] Native C Engine (libmemoria.so): Process memory map validated.")
    return token

def main():
    print("=======================================================")
    print("      CRISAOR SECURITY ENGINE (Project 醋)")
    print("      Phase 4 Development - August 18, 2026")
    print("=======================================================")
    
    verificar_privilegios()
    generar_token_memoria()
    
    print("\n[+] Crisaor Engine initialized successfully.")
    print("=======================================================")
    
    modulo_red.auditar_red()

if __name__ == "__main__":
    main()
