#!/usr/bin/env python3
import datetime
import os

LOG_FILE = "crisaor_audit.log"

# Códigos ANSI para dar formato y color en la terminal de Linux
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"

def registrar_evento(nivel, mensaje):
    """Guarda eventos en el archivo de log con marca de tiempo UTC."""
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    entrada_log = f"[{timestamp}] [{nivel.upper()}] {mensaje}\n"
    
    with open(LOG_FILE, "a") as f:
        f.write(entrada_log)

def formatear_alerta(estado):
    """Retorna el estado de la conexión con color según la gravedad."""
    if estado == "CLEAN":
        return f"{COLOR_GREEN}[CLEAN]{COLOR_RESET}"
    elif "ALERT" in estado:
        return f"{COLOR_RED}[{estado}]{COLOR_RESET}"
    else:
        return f"{COLOR_YELLOW}[{estado}]{COLOR_RESET}"
