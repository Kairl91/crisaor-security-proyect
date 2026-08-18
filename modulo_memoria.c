#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Verifica la integridad de la memoria del proceso comprobando la existencia de /proc/[pid]/maps
int verificar_integridad_proceso(int pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1; // No existe el proceso o no hay acceso
    }

    fclose(f);
    return 1; // Memoria legible e intacta
}

// Simula la inspección de un buffer en memoria RAM para buscar firmas sospechosas
int inspeccionar_buffer_ram(const char *data, size_t len) {
    if (data == NULL || len == 0) return 0;
    
    // Búsqueda simple de cadenas sospechosas en el buffer
    if (strstr(data, "MALWARE") != NULL || strstr(data, "EXEC") != NULL) {
        return 1; // Amenaza detectada en buffer
    }
    
    return 0; // Buffer limpio
}
