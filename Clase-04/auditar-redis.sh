#!/bin/bash
# =============================================================================
#  SENATI · Módulo 04 · Clase 4 — auditar-redis.sh
#  Auditor de SOLO LECTURA para Redis 6: 10 controles basados en la guía
#  oficial de seguridad de Redis y en el lineamiento BB-LIN-SEG-02.
#
#  Uso:  sudo bash /home/brian/auditar-redis.sh
#  Lee la configuración efectiva (redis.conf + archivos "include"), prueba
#  una conexión SIN credenciales y revisa proceso, permisos y firewall.
# =============================================================================
if [ "$EUID" -ne 0 ]; then echo "Ejecuta con sudo: sudo bash $0"; exit 1; fi

CONF=/etc/redis/redis.conf
PASS=0; FAIL=0

# Configuración efectiva: redis.conf seguido de sus include, en orden (el último valor gana)
ARCHIVOS="$CONF $(grep -E '^\s*include\s' $CONF | awk '{print $2}')"
EFECTIVA=$(cat $ARCHIVOS 2>/dev/null | grep -vE '^\s*(#|$)')

valor() { echo "$EFECTIVA" | grep -E "^\s*$1\s" | tail -1 | cut -d' ' -f2-; }

linea() {  # id, control, actual, esperado, ok(0/1)
  if [ "$5" = "1" ]; then R="PASS"; PASS=$((PASS+1)); else R="FAIL"; FAIL=$((FAIL+1)); fi
  printf "| %-5s | %-46s | %-28.28s | %-22s | %-4s |\n" "$1" "$2" "$3" "$4" "$R"
}

printf "+-------+------------------------------------------------+------------------------------+------------------------+------+\n"
printf "| %-5s | %-46s | %-28s | %-22s | %-4s |\n" "ID" "Control" "Actual" "Esperado" "Res."
printf "+-------+------------------------------------------------+------------------------------+------------------------+------+\n"

# RD-01 bind
B=$(valor bind); OK=1; echo "$B" | grep -qE '(^|\s)(0\.0\.0\.0|\*|::)(\s|$)' && OK=0
linea RD-01 "bind no escucha en todas las interfaces" "${B:-sin definir}" "IPs concretas" $OK

# RD-02 protected-mode
P=$(valor protected-mode); [ "$P" = "yes" ] && OK=1 || OK=0
linea RD-02 "protected-mode" "${P:-yes (defecto)}" "yes" $OK

# RD-03 acceso sin credenciales
RESP=$(timeout 3 redis-cli -h 127.0.0.1 PING 2>&1 | head -1)
[ "$RESP" = "PONG" ] && OK=0 || OK=1
linea RD-03 "Responde comandos SIN autenticarse" "$RESP" "NOAUTH / error" $OK

# RD-04 usuario default deshabilitado o con contraseña
if echo "$EFECTIVA" | grep -qE '^\s*user\s+default\s.*\boff\b' || [ -n "$(valor requirepass)" ]; then OK=1; A="off o requirepass"; else OK=0; A="default sin clave"; fi
linea RD-04 "Usuario 'default' deshabilitado o con clave" "$A" "off / requirepass" $OK

# RD-05 contraseñas de ACL en texto plano
if echo "$EFECTIVA" | grep -qE '^\s*user\s.*\s>'; then OK=0; A="hay claves >texto"; else OK=1; A="solo hash # o sin ACL"; fi
linea RD-05 "Claves ACL guardadas como hash (#sha256)" "$A" "solo #hash" $OK

# RD-06 comandos peligrosos
N=$(echo "$EFECTIVA" | grep -ciE '^\s*rename-command\s+(FLUSHALL|FLUSHDB|DEBUG|CONFIG)\s')
[ "$N" -ge 3 ] && OK=1 || OK=0
linea RD-06 "Comandos peligrosos renombrados/anulados" "$N de 4" ">= 3 de 4" $OK

# RD-07 escucha real en el sistema
L=$(ss -ltnH 'sport = :6379' | awk '{print $4}' | tr '\n' ' ')
echo "$L" | grep -qE '(^|\s)(0\.0\.0\.0|\*|\[::\]):6379' && OK=0 || OK=1
linea RD-07 "Socket 6379 no expuesto en 0.0.0.0" "${L:-no escucha}" "127.0.0.1 / IP LAN" $OK

# RD-08 proceso no corre como root
U=$(ps -o user= -C redis-server | head -1)
[ -n "$U" ] && [ "$U" != "root" ] && OK=1 || OK=0
linea RD-08 "Proceso redis-server no corre como root" "${U:-no corre}" "redis" $OK

# RD-09 permisos de los archivos de configuración
MALOS=""
for f in $ARCHIVOS; do
  [ -f "$f" ] || continue
  m=$(stat -c '%a' "$f"); o=$(stat -c '%U' "$f")
  if [ $((8#$m & 8#007)) -ne 0 ] || { [ "$o" != "redis" ] && [ "$o" != "root" ]; }; then MALOS="$MALOS $(basename $f):$m"; fi
done
[ -z "$MALOS" ] && OK=1 || OK=0
linea RD-09 "Configs sin permisos para 'otros' (<=640)" "${MALOS:-todos OK}" "640 redis" $OK

# RD-10 firewall
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  if ufw status | grep -E '^6379(/tcp)?\s+ALLOW\s+Anywhere' >/dev/null; then OK=0; A="abierto a Anywhere"; else OK=1; A="restringido"; fi
else OK=0; A="ufw inactivo"; fi
linea RD-10 "ufw limita el puerto 6379 por origen" "$A" "solo IP de la app" $OK

printf "+-------+------------------------------------------------+------------------------------+------------------------+------+\n"
echo "PASS: $PASS   FAIL: $FAIL   Total: $((PASS+FAIL))   Cumplimiento: $((100*PASS/(PASS+FAIL)))%"
