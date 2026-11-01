#!/usr/bin/env bash
# =============================================================================
#  Clase 6 · Auditor de contenedores (Docker) — 20 controles de solo lectura
#  Uso:   sudo bash auditar-contenedores.sh                 (muestra en pantalla)
#         sudo bash auditar-contenedores.sh -o antes.md     (además guarda Markdown)
#
#  Revisa el demonio Docker, los contenedores EN EJECUCIÓN y los puertos.
#  Basado en el CIS Docker Benchmark y NIST SP 800-190 (redacción propia).
#  No cambia nada en el sistema.
# =============================================================================
set -uo pipefail
SALIDA=""
[ "${1:-}" = "-o" ] && SALIDA="${2:-}"

if [ "$(id -u)" -ne 0 ]; then echo "Ejecuta con sudo: sudo bash $0"; exit 1; fi
command -v docker >/dev/null || { echo "Docker no está instalado"; exit 1; }

DJ=/etc/docker/daemon.json
USUARIO="${SUDO_USER:-brian}"
CONTS=$(docker ps -q)
PASS=0; FAIL=0; FILAS=""

registrar() {   # registrar ID "Control" PASS|FAIL "evidencia"
  if [ "$3" = PASS ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
  printf "%-7s %-52s %-5s %s\n" "$1" "$2" "$3" "$4"
  FILAS+="| $1 | $2 | $3 | $4 |"$'\n'
}

valor_dj() {    # lee una clave de daemon.json (vacío si no existe)
  [ -f "$DJ" ] || { echo ""; return; }
  python3 -c "import json,sys;d=json.load(open('$DJ'));v=d.get('$1','');print(json.dumps(v) if isinstance(v,(dict,list,bool)) else v)" 2>/dev/null
}

nombres_si() {  # devuelve los nombres de contenedores donde la plantilla imprime "SI"
  local plantilla="$1" lista=""
  for c in $CONTS; do
    [ "$(docker inspect --format "$plantilla" "$c")" = "SI" ] && lista+="$(docker inspect --format '{{.Name}}' "$c" | tr -d /) "
  done
  echo "$lista"
}

echo "=== Auditor de contenedores · $(hostname) · $(date '+%F %T') ==="
printf "%-7s %-52s %-5s %s\n" "ID" "Control" "Res." "Evidencia"
echo "-----------------------------------------------------------------------------------------"

# ---------------------------- Demonio y host ---------------------------------
[ "$(valor_dj icc)" = "false" ] && registrar DMN-01 "Tráfico entre contenedores restringido (icc=false)" PASS "daemon.json" \
                                   || registrar DMN-01 "Tráfico entre contenedores restringido (icc=false)" FAIL "icc no está en false"
[ "$(valor_dj no-new-privileges)" = "true" ] && registrar DMN-02 "no-new-privileges por defecto en el demonio" PASS "daemon.json" \
                                   || registrar DMN-02 "no-new-privileges por defecto en el demonio" FAIL "no configurado"
[ "$(valor_dj live-restore)" = "true" ] && registrar DMN-03 "live-restore activado" PASS "daemon.json" \
                                   || registrar DMN-03 "live-restore activado" FAIL "no configurado"
[ "$(valor_dj userland-proxy)" = "false" ] && registrar DMN-04 "userland-proxy desactivado" PASS "daemon.json" \
                                   || registrar DMN-04 "userland-proxy desactivado" FAIL "no configurado"
echo "$(valor_dj log-opts)" | grep -q max-size && registrar DMN-05 "Rotación de logs (max-size)" PASS "$(valor_dj log-opts)" \
                                   || registrar DMN-05 "Rotación de logs (max-size)" FAIL "logs sin límite de tamaño"
if id -nG "$USUARIO" 2>/dev/null | grep -qw docker; then
  registrar DMN-06 "El usuario $USUARIO NO está en el grupo docker" FAIL "grupo docker = root sin contraseña"
else
  registrar DMN-06 "El usuario $USUARIO NO está en el grupo docker" PASS "usa sudo docker"
fi
PERM=$(stat -c '%a %U:%G' /var/run/docker.sock 2>/dev/null)
[ "$PERM" = "660 root:docker" ] && registrar DMN-07 "Socket de Docker 660 root:docker" PASS "$PERM" \
                                 || registrar DMN-07 "Socket de Docker 660 root:docker" FAIL "$PERM"

# ------------------------------ Contenedores ---------------------------------
if [ -z "$CONTS" ]; then
  echo "(No hay contenedores en ejecución: los controles CNT y RED se marcan FAIL)"
fi

L=$(nombres_si '{{if or (eq .Config.User "") (eq .Config.User "root") (eq .Config.User "0")}}SI{{end}}')
[ -n "$CONTS" ] && [ -z "$L" ] && registrar CNT-01 "Ningún contenedor corre como root" PASS "todos con USER" \
                                || registrar CNT-01 "Ningún contenedor corre como root" FAIL "root: ${L:-sin contenedores}"
L=$(nombres_si '{{if .HostConfig.Privileged}}SI{{end}}')
[ -n "$CONTS" ] && [ -z "$L" ] && registrar CNT-02 "Ningún contenedor privilegiado" PASS "-" \
                                || registrar CNT-02 "Ningún contenedor privilegiado" FAIL "privileged: ${L:-sin contenedores}"
L=$(nombres_si '{{range .Mounts}}{{if eq .Source "/var/run/docker.sock"}}SI{{end}}{{end}}')
[ -n "$CONTS" ] && [ -z "$L" ] && registrar CNT-03 "Socket de Docker no montado en contenedores" PASS "-" \
                                || registrar CNT-03 "Socket de Docker no montado en contenedores" FAIL "docker.sock en: ${L:-sin contenedores}"
L=$(nombres_si '{{$a := "SI"}}{{range .HostConfig.CapDrop}}{{if eq . "ALL"}}{{$a = ""}}{{end}}{{end}}{{$a}}')
[ -n "$CONTS" ] && [ -z "$L" ] && registrar CNT-04 "Capacidades eliminadas (cap_drop: ALL)" PASS "-" \
                                || registrar CNT-04 "Capacidades eliminadas (cap_drop: ALL)" FAIL "sin cap_drop ALL: ${L:-sin contenedores}"
L=$(nombres_si '{{if not .HostConfig.ReadonlyRootfs}}SI{{end}}')
[ -n "$CONTS" ] && [ -z "$L" ] && registrar CNT-05 "Sistema de archivos de solo lectura" PASS "-" \
                                || registrar CNT-05 "Sistema de archivos de solo lectura" FAIL "escribible: ${L:-sin contenedores}"
L=$(nombres_si '{{$a := "SI"}}{{range .HostConfig.SecurityOpt}}{{if eq . "no-new-privileges:true" "no-new-privileges"}}{{$a = ""}}{{end}}{{end}}{{$a}}')
[ -n "$CONTS" ] && [ -z "$L" ] && registrar CNT-06 "no-new-privileges en cada contenedor" PASS "-" \
                                || registrar CNT-06 "no-new-privileges en cada contenedor" FAIL "falta en: ${L:-sin contenedores}"
L=$(nombres_si '{{if eq .HostConfig.Memory 0}}SI{{end}}')
[ -n "$CONTS" ] && [ -z "$L" ] && registrar CNT-07 "Límite de memoria" PASS "-" \
                                || registrar CNT-07 "Límite de memoria" FAIL "sin límite: ${L:-sin contenedores}"
L=$(nombres_si '{{$p := printf "%v" .HostConfig.PidsLimit}}{{if or (eq $p "<nil>") (eq $p "0") (eq $p "-1")}}SI{{end}}')
[ -n "$CONTS" ] && [ -z "$L" ] && registrar CNT-08 "Límite de procesos (pids_limit)" PASS "-" \
                                || registrar CNT-08 "Límite de procesos (pids_limit)" FAIL "sin límite: ${L:-sin contenedores}"
L=$(nombres_si '{{if not .State.Health}}SI{{end}}')
[ -n "$CONTS" ] && [ -z "$L" ] && registrar CNT-09 "Healthcheck configurado" PASS "-" \
                                || registrar CNT-09 "Healthcheck configurado" FAIL "sin healthcheck: ${L:-sin contenedores}"
L=$(nombres_si '{{if eq .HostConfig.RestartPolicy.Name "always"}}SI{{end}}')
[ -n "$CONTS" ] && [ -z "$L" ] && registrar CNT-10 "Reinicio acotado (no 'always')" PASS "on-failure" \
                                || registrar CNT-10 "Reinicio acotado (no 'always')" FAIL "always: ${L:-sin contenedores}"
L=""
for c in $CONTS; do
  if docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$c" \
     | grep -iE '^[A-Z_]*(PASS|PASSWORD|TOKEN|SECRET|APIKEY|API_KEY)[A-Z_]*=.+' >/dev/null; then
    L+="$(docker inspect --format '{{.Name}}' "$c" | tr -d /) "
  fi
done
[ -n "$CONTS" ] && [ -z "$L" ] && registrar CNT-11 "Sin secretos en variables de entorno" PASS "-" \
                                || registrar CNT-11 "Sin secretos en variables de entorno" FAIL "secretos en env: ${L:-sin contenedores}"

# --------------------------------- Red ---------------------------------------
PUERTOS=$(docker ps --format '{{.Ports}}' | grep -oE '(0\.0\.0\.0|\[::\]|[0-9.]+):[0-9]+->' | sed -E 's/.*:([0-9]+)->/\1/' | sort -un | tr '\n' ' ')
EXTRA=$(for p in $PUERTOS; do [ "$p" != 80 ] && [ "$p" != 443 ] && echo -n "$p "; done)
[ -n "$CONTS" ] && [ -z "$EXTRA" ] && registrar RED-01 "Solo se publican los puertos 80 y 443" PASS "publicados: ${PUERTOS:-ninguno}" \
                                    || registrar RED-01 "Solo se publican los puertos 80 y 443" FAIL "extra: ${EXTRA:-sin contenedores}"
L=""
for c in $CONTS; do
  img=$(docker inspect --format '{{.Config.Image}}' "$c")
  if echo "$img" | grep -qiE 'redis|postgres|mysql|mariadb|mongo'; then
    interna=no
    for n in $(docker inspect --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$c"); do
      [ "$(docker network inspect --format '{{.Internal}}' "$n")" = "true" ] && interna=si
    done
    [ "$interna" = no ] && L+="$(docker inspect --format '{{.Name}}' "$c" | tr -d /) "
  fi
done
[ -n "$CONTS" ] && [ -z "$L" ] && registrar RED-02 "Bases de datos/cachés solo en redes internas" PASS "-" \
                                || registrar RED-02 "Bases de datos/cachés solo en redes internas" FAIL "expuestas: ${L:-sin contenedores}"

# ------------------------------- Resumen -------------------------------------
TOTAL=$((PASS+FAIL)); PCT=$(( TOTAL>0 ? PASS*100/TOTAL : 0 ))
echo "-----------------------------------------------------------------------------------------"
echo "Resultado: $PASS PASS · $FAIL FAIL · Cumplimiento: ${PCT} %"

if [ -n "$SALIDA" ]; then
  {
    echo "# Auditoría de contenedores · $(hostname) · $(date '+%F %T')"
    echo
    echo "**Cumplimiento: ${PCT} %** ($PASS PASS · $FAIL FAIL)"
    echo
    echo "| ID | Control | Resultado | Evidencia |"
    echo "|----|---------|-----------|-----------|"
    printf "%s" "$FILAS"
  } > "$SALIDA"
  echo "Guardado en $SALIDA"
fi
