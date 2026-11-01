#!/usr/bin/env bash
# =============================================================================
#  Clase 6 · Auditor de APIs y web services — 12 controles (OWASP API Security Top 10 2023)
#  Prueba la API REST /api/v1/pedidos y el web service SOAP /ws/facturacion.
#
#  Uso:  bash auditar-api.sh [-t HOST] [-k claves.json] [-o salida.md]
#   Versión insegura:   bash auditar-api.sh -o /home/brian/c6/antes/api.md
#   Versión endurecida: sudo bash auditar-api.sh -k ../parte-b-docker/endurecido/secrets/api_keys.json -o /home/brian/c6/despues/api.md
#
#  Usa los datos FICTICIOS sembrados por la API: pedido 1 = ana, pedido 2 = luis.
#  Solo hace peticiones a TU laboratorio. El control de límite de peticiones va al final.
# =============================================================================
set -uo pipefail
H=localhost; KF=""; SALIDA=""
while getopts "t:k:o:" op; do case $op in t) H=$OPTARG;; k) KF=$OPTARG;; o) SALIDA=$OPTARG;; *) exit 1;; esac; done
C=(curl -s -k --noproxy "*" -m 8)
PASS=0; FAIL=0; NA=0; FILAS=""
registrar() {
  case "$3" in PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));; *) NA=$((NA+1));; esac
  printf "%-7s %-50s %-5s %s\n" "$1" "$2" "$3" "$4"
  FILAS+="| $1 | $2 | $3 | $4 |"$'\n'
}
if [ "$("${C[@]}" -o /dev/null -w '%{http_code}' "https://$H/")" != "000" ]; then BASE="https://$H"; else BASE="http://$H"; fi
ANA=""; LUIS=""
if [ -n "$KF" ]; then
  ANA=$(python3 -c "import json,sys;d=json.load(open('$KF'));print([k for k,v in d.items() if v=='ana'][0])" 2>/dev/null)
  LUIS=$(python3 -c "import json,sys;d=json.load(open('$KF'));print([k for k,v in d.items() if v=='luis'][0])" 2>/dev/null)
  [ -z "$ANA" ] && echo "AVISO: no se pudieron leer las claves de $KF (¿falta sudo?)"
fi
AUTH=(); [ -n "$ANA" ] && AUTH=(-H "X-API-Key: $ANA")
R="$BASE/api/v1/pedidos"; WS="$BASE/ws/facturacion"

echo "=== Auditor de APIs · $BASE · $(date '+%F %T') ==="
printf "%-7s %-50s %-5s %s\n" "ID" "Control" "Res." "Evidencia"
echo "-----------------------------------------------------------------------------------------"

# API2 · Autenticación
c=$("${C[@]}" -o /dev/null -w '%{http_code}' "$R")
case $c in 401|403) registrar API-01 "API2 · La API exige autenticación" PASS "sin clave → $c";;
           *)       registrar API-01 "API2 · La API exige autenticación" FAIL "sin clave → $c";; esac
"${C[@]}" "${AUTH[@]}" "$R" > /dev/null    # siembra los datos de prueba

# API1 · BOLA: ana pide el pedido 2 (de luis)
CU=$("${C[@]}" "${AUTH[@]}" "$R/2")
if echo "$CU" | grep -q '"luis"\|Papas grandes'; then registrar API-02 "API1 · Un cliente no ve pedidos ajenos (BOLA)" FAIL "pedido 2 de luis visible"
else registrar API-02 "API1 · Un cliente no ve pedidos ajenos (BOLA)" PASS "pedido ajeno → oculto"; fi

# API3 · Exposición de datos y asignación masiva
L=$("${C[@]}" "${AUTH[@]}" "$R")
if echo "$L" | grep -qE '[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}|costo_interno'; then registrar API-03 "API3 · Sin datos sensibles en la respuesta" FAIL "tarjeta completa / costo interno"
else registrar API-03 "API3 · Sin datos sensibles en la respuesta" PASS "campos filtrados"; fi
M=$("${C[@]}" "${AUTH[@]}" -X POST -H 'Content-Type: application/json' -d '{"producto":"Papas","cantidad":1,"estado":"pagado","cliente":"luis","precio":0}' "$R")
if echo "$M" | grep -qE '"estado": *"pagado"|"precio"'; then registrar API-04 "API3 · Campos no permitidos se ignoran" FAIL "acepta estado=pagado / precio"
elif [ -z "$ANA" ] && ! echo "$M" | grep -q '"id"'; then registrar API-04 "API3 · Campos no permitidos se ignoran" N/A "sin claves (-k)"
else registrar API-04 "API3 · Campos no permitidos se ignoran" PASS "estado y precio ignorados"; fi

# API8 · CORS
AC=$("${C[@]}" "${AUTH[@]}" -D - -o /dev/null -H 'Origin: https://sitio-malicioso.example' "$R" | grep -i '^access-control-allow-origin' | tr -d '\r')
echo "$AC" | grep -qE '\*|malicioso' && registrar API-05 "API8 · CORS no abierto a cualquier origen" FAIL "$AC" \
                                      || registrar API-05 "API8 · CORS no abierto a cualquier origen" PASS "${AC:-sin ACAO para orígenes ajenos}"

# API9 · Inventario: versión vieja y endpoints de depuración
c0=$("${C[@]}" -o /dev/null -w '%{http_code}' "$BASE/api/v0/pedidos"); ci=$("${C[@]}" -o /dev/null -w '%{http_code}' "$BASE/api/info")
[ "$c0" != 200 ] && [ "$ci" != 200 ] && registrar API-06 "API9 · Sin versiones viejas ni endpoints de depuración" PASS "v0=$c0 info=$ci" \
                                     || registrar API-06 "API9 · Sin versiones viejas ni endpoints de depuración" FAIL "v0=$c0 info=$ci"

# API8 · Errores
E=$("${C[@]}" "${AUTH[@]}" -X POST -H 'Content-Type: application/json' -d '[1]' "$R")
echo "$E" | grep -qiE 'traceback|werkzeug|exception' && registrar API-07 "API8 · Errores sin detalles internos" FAIL "traza del servidor" \
                                                     || registrar API-07 "API8 · Errores sin detalles internos" PASS "error genérico"

# ---------------------------- Web service SOAP ------------------------------
W=$("${C[@]}" "$WS?wsdl")
echo "$W" | grep -q 'definitions' && registrar API-08 "SOAP · WSDL no público (requiere clave)" FAIL "WSDL visible sin autenticación" \
                                  || registrar API-08 "SOAP · WSDL no público (requiere clave)" PASS "-"
XXE='<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/hostname">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><consultarFactura xmlns="urn:burgerbank:facturacion"><numero>&x;</numero></consultarFactura></soap:Body></soap:Envelope>'
X=$("${C[@]}" "${AUTH[@]}" -X POST -H 'Content-Type: text/xml' --data-binary "$XXE" "$WS" | tr -d '\n')
if echo "$X" | grep -qE '<numero>[^<&]+</numero>'; then registrar API-09 "SOAP · Entidades externas bloqueadas (XXE)" FAIL "resolvió file:///etc/hostname"
else registrar API-09 "SOAP · Entidades externas bloqueadas (XXE)" PASS "DTD/entidades rechazadas"; fi
c=$(head -c 65536 /dev/zero | tr '\0' 'a' | "${C[@]}" "${AUTH[@]}" -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: text/xml' --data-binary @- "$WS")
[ "$c" = 413 ] && registrar API-10 "SOAP · Límite de tamaño del mensaje" PASS "64 KB → 413" \
               || registrar API-10 "SOAP · Límite de tamaño del mensaje" FAIL "64 KB → $c"

# ------------------------- Superficie y consumo ------------------------------
abierto() { timeout 2 bash -c "</dev/tcp/$H/$1" 2>/dev/null; }
L=""; for p in 5000 5001; do abierto $p && L+="$p "; done
[ -z "$L" ] && registrar API-11 "Microservicios no expuestos directo (5000/5001)" PASS "solo vía proxy" \
            || registrar API-11 "Microservicios no expuestos directo (5000/5001)" FAIL "abiertos: $L"
N=0; for i in $(seq 1 30); do [ "$("${C[@]}" "${AUTH[@]}" -o /dev/null -w '%{http_code}' "$R")" = 429 ] && N=$((N+1)); done
[ "$N" -gt 0 ] && registrar API-12 "API4 · Límite de consumo (rate limit)" PASS "$N de 30 con 429" \
               || registrar API-12 "API4 · Límite de consumo (rate limit)" FAIL "30 de 30 aceptadas"

TOTAL=$((PASS+FAIL)); PCT=$(( TOTAL>0 ? PASS*100/TOTAL : 0 ))
echo "-----------------------------------------------------------------------------------------"
echo "Resultado: $PASS PASS · $FAIL FAIL · $NA N/A · Cumplimiento: ${PCT} %"
if [ -n "$SALIDA" ]; then
  { echo "# Auditoría de APIs · $BASE · $(date '+%F %T')"; echo
    echo "**Cumplimiento: ${PCT} %** ($PASS PASS · $FAIL FAIL · $NA N/A)"; echo
    echo "| ID | Control | Resultado | Evidencia |"; echo "|----|---------|-----------|-----------|"; printf "%s" "$FILAS"; } > "$SALIDA"
  echo "Guardado en $SALIDA"
fi
