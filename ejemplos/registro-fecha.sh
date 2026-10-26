#!/bin/bash
# Script de ejemplo para la prueba de systemd (precondición e del enunciado):
# cada vez que se ejecuta, agrega al final de un archivo un mensaje con fecha y hora.
# Despliéguelo como servicio de tipo «Se ejecuta una vez y termina»; cada
# start/restart agrega una línea nueva a registro.txt dentro de /opt/<servicio>/.
echo "Ejecutado el $(date '+%Y-%m-%d a las %H:%M:%S')" >> "$(dirname "$0")/registro.txt"
