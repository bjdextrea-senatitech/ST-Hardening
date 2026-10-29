#!/usr/bin/env bash
# pruebas-firewall.sh - Batería de pruebas desde Kali (solo reconocimiento, sin explotación)
# SENATI · Módulo 04 · Clase 5 · Calentamiento iptables / firewalld / pfSense
#
# Uso:
#   sudo bash pruebas-firewall.sh <IP_OBJETIVO> <etiqueta> [puerto_ssh]
#       etiqueta: sin-firewall | iptables | firewalld | pfsense-antes | pfsense-despues
#       puerto_ssh: 22 por defecto; contra pfSense usa 2222 (el NAT hacia la DMZ)
#   sudo bash pruebas-firewall.sh comparar
#       arma una tabla con todas las corridas guardadas
#
# Solo contra VMs propias del laboratorio.

DIR="${RESULTADOS_DIR:-$HOME/resultados-firewall}"
PUERTOS_TCP="22,80,443,2222,3306,5432,6379,6333,8080"
PUERTOS_UDP="53,123,161"
PUERTO_SALIDA=4444
mkdir -p "$DIR"

if [ "$1" = "comparar" ]; then
  archivos=$(ls -tr "$DIR"/*.tsv 2>/dev/null)
  [ -z "$archivos" ] && { echo "No hay resultados en $DIR"; exit 1; }
  printf "| Prueba |"; for f in $archivos; do printf " %s |" "$(basename "$f" .tsv)"; done; echo
  printf "|---|"; for f in $archivos; do printf "%s" "---|"; done; echo
  awk -F'\t' '!vistos[$1]++ {print $1}' $archivos | while read -r prueba; do
    printf "| %s |" "$prueba"
    for f in $archivos; do r=$(awk -F'\t' -v p="$prueba" '$1==p{print $2}' "$f"); printf " %s |" "${r:-—}"; done
    echo
  done
  exit 0
fi

OBJ="$1"; ETQ="${2:-sin-etiqueta}"; PSSH="${3:-22}"
if [ -z "$OBJ" ]; then sed -n '2,15p' "$0"; exit 1; fi
if [ "$(id -u)" -ne 0 ]; then echo "Ejecuta con sudo (nmap -sS y -sU lo necesitan)"; exit 1; fi
command -v nmap >/dev/null || { echo "Falta nmap"; exit 1; }

TSV="$DIR/$ETQ.tsv"; MD="$DIR/$ETQ.md"; : > "$TSV"
TMP=$(mktemp -d)
echo "== Batería de pruebas contra $OBJ  (etiqueta: $ETQ)  $(date '+%F %T')"

# P1 - SYN scan: qué puertos responden y por qué (open / closed / filtered + razón)
echo "[P1] nmap -sS (TCP SYN) ..."
nmap -sS -Pn -n --reason -p "$PUERTOS_TCP" "$OBJ" -oG "$TMP/p1.gnmap" > "$TMP/p1.txt"
grep -E '^[0-9]+/tcp' "$TMP/p1.txt" | while read -r puerto estado servicio razon resto; do
  printf "P1 %s\t%s (%s)\n" "$puerto" "$estado" "$razon" >> "$TSV"
done

# P2 - ACK scan: ¿el firewall es con estado? (unfiltered = el ACK suelto llega al host)
echo "[P2] nmap -sA (TCP ACK) ..."
nmap -sA -Pn -n --reason -p "$PSSH",8080 "$OBJ" > "$TMP/p2.txt"
grep -E '^[0-9]+/tcp' "$TMP/p2.txt" | while read -r puerto estado servicio razon resto; do
  printf "P2 ACK %s\t%s (%s)\n" "$puerto" "$estado" "$razon" >> "$TSV"
done

# P3 - UDP: servicios UDP típicos
echo "[P3] nmap -sU (UDP) ..."
nmap -sU -Pn -n --reason --max-retries 1 -p "$PUERTOS_UDP" "$OBJ" > "$TMP/p3.txt"
grep -E '^[0-9]+/udp' "$TMP/p3.txt" | while read -r puerto estado servicio razon resto; do
  printf "P3 %s\t%s (%s)\n" "$puerto" "$estado" "$razon" >> "$TSV"
done

# P4 - ICMP echo (ping)
echo "[P4] ping ..."
if ping -c 2 -W 2 "$OBJ" >/dev/null 2>&1; then printf "P4 ping\tresponde\n" >> "$TSV"; else printf "P4 ping\tno responde\n" >> "$TSV"; fi

# P5 - Salida (egress): ¿el servidor puede abrir conexión hacia Kali como www-data?
echo
echo "[P5] Prueba de SALIDA. Kali escucha en el puerto $PUERTO_SALIDA durante 60 s."
echo "     En el Ubuntu ejecuta AHORA:"
echo "     echo SALIDA-www-data | sudo -u www-data nc -w 3 $(ip -4 -o route get "$OBJ" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}') $PUERTO_SALIDA"
if command -v ncat >/dev/null; then
  timeout 60 ncat -l -p "$PUERTO_SALIDA" > "$TMP/p5.txt" 2>/dev/null
else
  timeout 60 nc -l -p "$PUERTO_SALIDA" > "$TMP/p5.txt" 2>/dev/null
fi
if grep -q SALIDA "$TMP/p5.txt"; then printf "P5 salida www-data -> Kali:%s\tLLEGÓ (salida abierta)\n" "$PUERTO_SALIDA" >> "$TSV"
else printf "P5 salida www-data -> Kali:%s\tno llegó\n" "$PUERTO_SALIDA" >> "$TSV"; fi

# P6 - Límite de conexiones nuevas a SSH (fuerza bruta). Va al final a propósito.
echo "[P6] 10 conexiones seguidas a SSH (puerto $PSSH) ..."
primero=""
for i in $(seq 1 10); do
  if nc -z -w 2 "$OBJ" "$PSSH" >/dev/null 2>&1; then echo "   intento $i: abierto"; else echo "   intento $i: bloqueado"; [ -z "$primero" ] && primero=$i; fi
done
if [ -n "$primero" ]; then printf "P6 límite SSH\tbloquea desde el intento %s\n" "$primero" >> "$TSV"
else printf "P6 límite SSH\tsin límite (10/10 abiertos)\n" >> "$TSV"; fi

# Reporte
{
  echo "# Batería de pruebas: $ETQ"
  echo "Objetivo: $OBJ · Fecha: $(date '+%F %T')"
  echo
  echo "| Prueba | Resultado |"
  echo "|---|---|"
  awk -F'\t' '{printf "| %s | %s |\n", $1, $2}' "$TSV"
} > "$MD"
echo
cat "$MD"
echo
echo "Guardado en: $MD"
echo "Para comparar todas las corridas: sudo bash $0 comparar"
rm -rf "$TMP"
