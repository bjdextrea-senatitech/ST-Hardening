#!/usr/bin/env bash
# =============================================================================
#  Clase 7 · Auditor de Azure — 18 controles de solo lectura con az CLI
#  Uso:   bash auditar-azure.sh                     (muestra en pantalla)
#         bash auditar-azure.sh -o antes.md         (además guarda Markdown)
#
#  Lee los nombres de $HOME/c7/entorno.env (creado por 00-crear-entorno-inseguro.sh).
#  Basado en CIS Microsoft Azure Foundations y Microsoft Cloud Security Benchmark
#  (redacción propia). No cambia nada. Los controles que no se pueden leer con
#  tu tipo de cuenta salen N/A y no cuentan en el porcentaje.
# =============================================================================
set -uo pipefail
SALIDA=""
[ "${1:-}" = "-o" ] && SALIDA="${2:-}"
ENV_F="$HOME/c7/entorno.env"
[ -f "$ENV_F" ] || { echo "No existe $ENV_F: ejecuta primero 00-crear-entorno-inseguro.sh"; exit 1; }
# shellcheck disable=SC1090
source "$ENV_F"
az account show -o none 2>/dev/null || { echo "Sesión vencida: az login --use-device-code"; exit 1; }

RGID="/subscriptions/$SUB/resourceGroups/$RG"
PASS=0; FAIL=0; NA=0; FILAS=""
registrar() {
  case "$3" in PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));; *) NA=$((NA+1));; esac
  printf "%-7s %-50s %-5s %s\n" "$1" "$2" "$3" "$4"
  FILAS+="| $1 | $2 | $3 | $4 |"$'\n'
}
q() { az "$@" -o tsv 2>/dev/null; }   # consulta corta que devuelve texto

echo "=== Auditor Azure · suscripción $SUB · grupo $RG · $(date '+%F %T') ==="
printf "%-7s %-50s %-5s %s\n" "ID" "Control" "Res." "Evidencia"
echo "-----------------------------------------------------------------------------------------"

# ------------------------------ Identidad -----------------------------------
SD=$(q rest --method get --url https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy --query isEnabled)
case "$SD" in
  true)  registrar IAM-01 "Valores de seguridad predeterminados (MFA) activos" PASS "isEnabled=true" ;;
  false) registrar IAM-01 "Valores de seguridad predeterminados (MFA) activos" FAIL "isEnabled=false" ;;
  *)     registrar IAM-01 "Valores de seguridad predeterminados (MFA) activos" N/A "sin permiso para leer Entra ID" ;;
esac
if [ -n "${PRACT_ID:-}" ]; then
  N=$(q role assignment list --assignee "$PRACT_ID" --scope "/subscriptions/$SUB" \
       --query "length([?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor'])")
  [ "${N:-0}" = 0 ] && registrar IAM-02 "Practicante sin Owner/Contributor en la suscripción" PASS "0 asignaciones" \
                    || registrar IAM-02 "Practicante sin Owner/Contributor en la suscripción" FAIL "$N asignación(es) amplias"
  N=$(q role assignment list --assignee "$PRACT_ID" --scope "$RGID" --query "length([?roleDefinitionName=='Reader'])")
  [ "${N:-0}" -ge 1 ] && registrar IAM-03 "Practicante con rol mínimo (Reader) en el grupo" PASS "Reader en $RG" \
                      || registrar IAM-03 "Practicante con rol mínimo (Reader) en el grupo" FAIL "sin Reader en $RG"
else
  registrar IAM-02 "Practicante sin Owner/Contributor en la suscripción" N/A "no hay usuario practicante"
  registrar IAM-03 "Practicante con rol mínimo (Reader) en el grupo" N/A "no hay usuario practicante"
fi

# ---------------------------- Almacenamiento --------------------------------
V=$(q storage account show -n "$SA" -g "$RG" --query allowBlobPublicAccess)
[ "$V" = "false" ] && registrar STG-01 "Acceso público a blobs deshabilitado" PASS "allowBlobPublicAccess=false" \
                   || registrar STG-01 "Acceso público a blobs deshabilitado" FAIL "allowBlobPublicAccess=${V:-?}"
V=$(q storage account show -n "$SA" -g "$RG" --query enableHttpsTrafficOnly)
[ "$V" = "true" ] && registrar STG-02 "Solo HTTPS (transferencia segura)" PASS "enableHttpsTrafficOnly=true" \
                  || registrar STG-02 "Solo HTTPS (transferencia segura)" FAIL "enableHttpsTrafficOnly=${V:-?}"
V=$(q storage account show -n "$SA" -g "$RG" --query minimumTlsVersion)
[ "$V" = "TLS1_2" ] || [ "$V" = "TLS1_3" ] && registrar STG-03 "TLS mínimo 1.2" PASS "$V" \
                                          || registrar STG-03 "TLS mínimo 1.2" FAIL "${V:-?}"
V=$(q storage account show -n "$SA" -g "$RG" --query allowSharedKeyAccess)
[ "$V" = "false" ] && registrar STG-04 "Acceso con clave compartida deshabilitado" PASS "solo Entra ID (RBAC)" \
                   || registrar STG-04 "Acceso con clave compartida deshabilitado" FAIL "allowSharedKeyAccess=${V:-true}"
V=$(q storage container-rm list --storage-account "$SA" -g "$RG" --query "[?publicAccess!='None' && publicAccess!=null].name")
[ -z "$V" ] && registrar STG-05 "Ningún contenedor con acceso público" PASS "-" \
            || registrar STG-05 "Ningún contenedor con acceso público" FAIL "públicos: $(echo $V)"
V=$(q storage account blob-service-properties show -n "$SA" -g "$RG" --query deleteRetentionPolicy.enabled)
[ "$V" = "true" ] && registrar STG-06 "Eliminación temporal de blobs (soft delete)" PASS "activada" \
                  || registrar STG-06 "Eliminación temporal de blobs (soft delete)" FAIL "desactivada"
V=$(q storage account blob-service-properties show -n "$SA" -g "$RG" --query containerDeleteRetentionPolicy.enabled)
[ "$V" = "true" ] && registrar STG-07 "Eliminación temporal de contenedores" PASS "activada" \
                  || registrar STG-07 "Eliminación temporal de contenedores" FAIL "desactivada"
COD=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "https://${SA}.blob.core.windows.net/publico/planilla-clientes.csv")
[ "$COD" = "200" ] && registrar STG-08 "El CSV NO se descarga sin autenticación" FAIL "HTTP 200 anónimo" \
                   || registrar STG-08 "El CSV NO se descarga sin autenticación" PASS "HTTP $COD"

# --------------------------------- Red --------------------------------------
abierto() {   # abierto PUERTO -> nombres de reglas que lo permiten desde internet
  q network nsg rule list -g "$RG" --nsg-name "$NSG" --query \
   "[?access=='Allow' && direction=='Inbound' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet' || sourceAddressPrefix=='0.0.0.0/0' || sourceAddressPrefix=='Any') && (destinationPortRange=='$1' || destinationPortRange=='*' || contains(destinationPortRanges, '$1'))].name"
}
V=$(abierto 22);   [ -z "$V" ] && registrar NET-01 "SSH (22) no abierto a internet" PASS "-" || registrar NET-01 "SSH (22) no abierto a internet" FAIL "regla: $(echo $V)"
V=$(abierto 3389); [ -z "$V" ] && registrar NET-02 "RDP (3389) no abierto a internet" PASS "-" || registrar NET-02 "RDP (3389) no abierto a internet" FAIL "regla: $(echo $V)"

# --------------------------- Registros y costos -----------------------------
N=$(az monitor diagnostic-settings subscription list -o json 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);d=d.get('value',d) if isinstance(d,dict) else d;print(len(d))" 2>/dev/null)
if [ -z "$N" ]; then registrar LOG-01 "Registro de actividad exportado (diagnóstico)" N/A "sin permiso de lectura en la suscripción"
elif [ "$N" -ge 1 ]; then registrar LOG-01 "Registro de actividad exportado (diagnóstico)" PASS "$N configuración(es)"
else registrar LOG-01 "Registro de actividad exportado (diagnóstico)" FAIL "sin exportar"; fi
N=$(az monitor activity-log alert list -g "$RG" -o json 2>/dev/null | grep -ci 'networkSecurityGroups')
[ "${N:-0}" -ge 1 ] && registrar LOG-02 "Alerta ante cambios en reglas de NSG" PASS "alerta configurada" \
                    || registrar LOG-02 "Alerta ante cambios en reglas de NSG" FAIL "sin alerta"
N=$(q consumption budget list --query "length(@)")
if [ -z "$N" ]; then registrar LOG-03 "Presupuesto con alerta de costos" N/A "tu tipo de suscripción no lo permite leer"
elif [ "$N" -ge 1 ]; then registrar LOG-03 "Presupuesto con alerta de costos" PASS "$N presupuesto(s)"
else registrar LOG-03 "Presupuesto con alerta de costos" FAIL "sin presupuesto"; fi

# ------------------------------- Gobierno -----------------------------------
N=$(q security contact list --query "length([?emails!=null && emails!=''])")
if [ -z "$N" ]; then registrar GOV-01 "Contacto de seguridad en Defender for Cloud" N/A "sin permiso de lectura en la suscripción"
elif [ "$N" -ge 1 ]; then registrar GOV-01 "Contacto de seguridad en Defender for Cloud" PASS "$N contacto(s)"
else registrar GOV-01 "Contacto de seguridad en Defender for Cloud" FAIL "sin contacto"; fi
N=$(q policy assignment list --scope "$RGID" --query "length([?contains(displayName, 'public access')])")
[ "${N:-0}" -ge 1 ] && registrar GOV-02 "Política que prohíbe almacenamiento público" PASS "asignada en $RG" \
                    || registrar GOV-02 "Política que prohíbe almacenamiento público" FAIL "sin política"
N=$(q lock list -g "$RG" --query "length([?level=='CanNotDelete'])")
[ "${N:-0}" -ge 1 ] && registrar GOV-03 "Bloqueo contra borrado del grupo de recursos" PASS "CanNotDelete" \
                    || registrar GOV-03 "Bloqueo contra borrado del grupo de recursos" FAIL "sin bloqueo"
T=$(q group show -n "$RG" --query "tags.propietario")
[ -n "$T" ] && registrar GOV-04 "Etiquetas de propietario y entorno" PASS "propietario=$T" \
            || registrar GOV-04 "Etiquetas de propietario y entorno" FAIL "sin etiquetas"

TOTAL=$((PASS+FAIL)); PCT=$(( TOTAL>0 ? PASS*100/TOTAL : 0 ))
echo "-----------------------------------------------------------------------------------------"
echo "Resultado: $PASS PASS · $FAIL FAIL · $NA N/A · Cumplimiento: ${PCT} %"
if [ -n "$SALIDA" ]; then
  { echo "# Auditoría Azure · $RG · $(date '+%F %T')"; echo
    echo "**Cumplimiento: ${PCT} %** ($PASS PASS · $FAIL FAIL · $NA N/A)"; echo
    echo "| ID | Control | Resultado | Evidencia |"; echo "|----|---------|-----------|-----------|"; printf "%s" "$FILAS"; } > "$SALIDA"
  echo "Guardado en $SALIDA"
fi
