#!/usr/bin/env bash
# =============================================================================
#  Clase 6 · Auditor de servidores web "desde afuera" — 20 controles (curl + openssl)
#  Sirve para Apache, Nginx o cualquier servidor web.
#
#  Uso:  bash auditar-web.sh -p PUERTO_HTTP -s PUERTO_HTTPS [-t HOST] [-a RUTA_API] [-o salida.md]
#   Apache (Parte A):  bash auditar-web.sh -p 8081 -s 8441 -o /home/brian/c6/antes/apache.md
#   Nginx  (Parte A):  bash auditar-web.sh -p 8082 -s 8442 -o /home/brian/c6/antes/nginx.md
#   Docker (Parte B):  bash auditar-web.sh -p 80 -s 443 -a /api/v1/pedidos -o /home/brian/c6/antes/web-docker.md
#
#  Solo hace peticiones HTTP/HTTPS normales a TU servidor del laboratorio.
#  Basado en OWASP Top 10:2025, OWASP Secure Headers y CIS Apache/Nginx (redacción propia).
#  El control de límite de peticiones va al final: puede bloquear tu IP unos segundos.
# =============================================================================
set -uo pipefail
H=localhost; P=80; S=443; API=""; SALIDA=""
while getopts "t:p:s:a:o:" op; do
  case $op in t) H=$OPTARG;; p) P=$OPTARG;; s) S=$OPTARG;; a) API=$OPTARG;; o) SALIDA=$OPTARG;; *) exit 1;; esac
done
C=(curl -s -k --noproxy "*" -m 5)
PASS=0; FAIL=0; NA=0; FILAS=""
registrar() {
  case "$3" in PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));; *) NA=$((NA+1));; esac
  printf "%-7s %-46s %-5s %s\n" "$1" "$2" "$3" "$4"
  FILAS+="| $1 | $2 | $3 | $4 |"$'\n'
}
codigo() { "${C[@]}" -o /dev/null -w '%{http_code}' "$@"; }

echo "=== Auditor web · $H (HTTP $P / HTTPS $S) · $(date '+%F %T') ==="
printf "%-7s %-46s %-5s %s\n" "ID" "Control" "Res." "Evidencia"
echo "-------------------------------------------------------------------------------------"

if [ "$(codigo "https://$H:$S/")" != "000" ]; then BASE="https://$H:$S"; TLS=si; else BASE="http://$H:$P"; TLS=no; fi
CAB=$("${C[@]}" -D - -o /dev/null "$BASE/")
CUERPO=$("${C[@]}" "$BASE/")

# ----------------------------- Transporte -----------------------------------
LOC=$("${C[@]}" -D - -o /dev/null "http://$H:$P/" | grep -i '^location:' | tr -d '\r')
echo "$LOC" | grep -qi 'https://' && registrar WEB-01 "HTTP redirige a HTTPS" PASS "$LOC" \
                                  || registrar WEB-01 "HTTP redirige a HTTPS" FAIL "sin redirección"
[ "$TLS" = si ] && registrar WEB-02 "El sitio responde por HTTPS" PASS "https:$S" \
                || registrar WEB-02 "El sitio responde por HTTPS" FAIL "no hay HTTPS en $S"
for v in "tls1:WEB-03:TLS 1.0" "tls1_1:WEB-04:TLS 1.1"; do
  op=${v%%:*}; r=${v#*:}; id=${r%%:*}; nom=${r#*:}
  if [ "$TLS" = no ]; then registrar "$id" "$nom rechazado" FAIL "no hay HTTPS"; continue; fi
  if echo | openssl s_client -connect "$H:$S" -"$op" -cipher 'DEFAULT:@SECLEVEL=0' 2>/dev/null | grep -q 'Cipher is [A-Z0-9]'; then
    registrar "$id" "$nom rechazado" FAIL "el servidor acepta $nom"
  else registrar "$id" "$nom rechazado" PASS "handshake rechazado"; fi
done
if [ "$TLS" = si ] && echo | openssl s_client -connect "$H:$S" -tls1_2 2>/dev/null | grep -q 'Cipher is [A-Z0-9]'; then
  registrar WEB-05 "TLS 1.2 o superior disponible" PASS "TLS 1.2 OK"
else registrar WEB-05 "TLS 1.2 o superior disponible" FAIL "sin TLS 1.2"; fi

# ------------------------------ Cabeceras -----------------------------------
SRV=$(echo "$CAB" | grep -i '^server:' | tr -d '\r')
echo "$SRV" | grep -qE '[0-9]+\.[0-9]+' && registrar WEB-06 "Cabecera Server sin versión" FAIL "$SRV" \
                                         || registrar WEB-06 "Cabecera Server sin versión" PASS "${SRV:-sin Server}"
chk() { local v; v=$(echo "$CAB" | grep -iE "^$3" | head -1 | tr -d '\r')
  [ -n "$v" ] && registrar "$1" "$2" PASS "$(echo "$v" | cut -c1-38)" || registrar "$1" "$2" FAIL "no está"; }
chk WEB-07 "HSTS (Strict-Transport-Security)" "strict-transport-security:"
chk WEB-08 "Content-Security-Policy" "content-security-policy:"
chk WEB-09 "X-Frame-Options" "x-frame-options:"
chk WEB-10 "X-Content-Type-Options: nosniff" "x-content-type-options: *nosniff"
chk WEB-11 "Referrer-Policy" "referrer-policy:"

# ------------------------- Exposición de información ------------------------
"${C[@]}" "$BASE/descargas/" | grep -qi 'Index of' && registrar WEB-12 "Sin listado de directorios" FAIL "/descargas/ lista archivos" \
                                                    || registrar WEB-12 "Sin listado de directorios" PASS "-"
E404=$("${C[@]}" "$BASE/no-existe-$RANDOM")
echo "$E404" | grep -qiE '(apache|nginx)/[0-9]' && registrar WEB-13 "Páginas de error sin versión" FAIL "$(echo "$E404" | grep -oiE '(apache|nginx)/[0-9.]+' | head -1)" \
                                               || registrar WEB-13 "Páginas de error sin versión" PASS "-"
L=""; for f in /.env /.git/HEAD /.htaccess; do [ "$(codigo "$BASE$f")" = 200 ] && L+="$f "; done
[ -z "$L" ] && registrar WEB-14 "Archivos ocultos no se sirven" PASS "-" || registrar WEB-14 "Archivos ocultos no se sirven" FAIL "200 en: $L"
L=""; for f in /server-status /server-info /nginx_status /status; do [ "$(codigo "$BASE$f")" = 200 ] && L+="$f "; done
[ -z "$L" ] && registrar WEB-15 "Páginas de estado internas cerradas" PASS "-" || registrar WEB-15 "Páginas de estado internas cerradas" FAIL "200 en: $L"
echo "$CUERPO" | grep -qiE 'Apache2 (Ubuntu|Debian) Default Page|Welcome to nginx' \
  && registrar WEB-16 "Sin página por defecto del servidor" FAIL "página de instalación" \
  || registrar WEB-16 "Sin página por defecto del servidor" PASS "-"
if [ -n "$API" ]; then
  ERR=$("${C[@]}" -X POST -H 'Content-Type: application/json' -d '[1]' "$BASE$API")
  echo "$ERR" | grep -qiE 'traceback|werkzeug|exception' && registrar WEB-17 "Errores sin detalles internos" FAIL "muestra traza" \
                                                         || registrar WEB-17 "Errores sin detalles internos" PASS "error genérico"
else registrar WEB-17 "Errores sin detalles internos" N/A "sin API (-a)"; fi

# -------------------------- Métodos y abuso ---------------------------------
M=""; for m in TRACE PUT DELETE; do c=$(codigo -X "$m" "$BASE/"); case $c in 405|403|400|501) ;; *) M+="$m=$c ";; esac; done
[ -z "$M" ] && registrar WEB-18 "Métodos TRACE/PUT/DELETE rechazados" PASS "405/403" \
            || registrar WEB-18 "Métodos TRACE/PUT/DELETE rechazados" FAIL "$M"
RUTA="${API:-/}"
c=$(head -c 300000 /dev/zero | tr '\0' 'a' | "${C[@]}" -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: text/plain' --data-binary @- "$BASE$RUTA")
[ "$c" = 413 ] && registrar WEB-19 "Límite de tamaño de petición" PASS "300 KB → 413" \
               || registrar WEB-19 "Límite de tamaño de petición" FAIL "300 KB → $c"
N=0; for i in $(seq 1 30); do case "$(codigo "$BASE$RUTA")" in 429|403|503) N=$((N+1));; esac; done
[ "$N" -gt 0 ] && registrar WEB-20 "Límite de peticiones (rate limit)" PASS "$N de 30 bloqueadas" \
               || registrar WEB-20 "Límite de peticiones (rate limit)" FAIL "30 de 30 aceptadas"

TOTAL=$((PASS+FAIL)); PCT=$(( TOTAL>0 ? PASS*100/TOTAL : 0 ))
echo "-------------------------------------------------------------------------------------"
echo "Resultado: $PASS PASS · $FAIL FAIL · $NA N/A · Cumplimiento: ${PCT} %"
if [ -n "$SALIDA" ]; then
  { echo "# Auditoría web · $H HTTP $P / HTTPS $S · $(date '+%F %T')"; echo
    echo "**Cumplimiento: ${PCT} %** ($PASS PASS · $FAIL FAIL · $NA N/A)"; echo
    echo "| ID | Control | Resultado | Evidencia |"; echo "|----|---------|-----------|-----------|"; printf "%s" "$FILAS"; } > "$SALIDA"
  echo "Guardado en $SALIDA"
fi
