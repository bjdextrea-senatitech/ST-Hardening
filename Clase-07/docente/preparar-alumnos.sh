#!/usr/bin/env bash
# =============================================================================
#  DOCENTE · Clase 7 — Invita alumnos a TU suscripción, cada uno con su grupo de recursos
#  Uso:   bash preparar-alumnos.sh alumnos.csv [región] [correo_del_docente]
#         alumnos.csv  →  una línea por alumno:  usuario,correo   (sin encabezado)
#                         ejemplo:  jperez,juan.perez@gmail.com
#
#  Para cada alumno:
#   1. Crea el grupo rg-c7-<usuario> con etiquetas.
#   2. Lo invita como usuario invitado (B2B) de tu directorio (le llega un correo).
#   3. Le da Owner SOLO sobre su grupo (no ve ni toca nada más de la suscripción).
#   4. Le crea un presupuesto de US$3 en su grupo con alerta a ti.
#  Además, una sola vez a nivel suscripción: registro de actividad y contacto de Defender.
#
#  Requisitos: az login con tu cuenta (Owner de la suscripción y administrador del directorio).
#  Al terminar la clase: bash limpiar-alumnos.sh alumnos.csv
# =============================================================================
set -uo pipefail
CSV="${1:?Uso: bash preparar-alumnos.sh alumnos.csv [región] [correo_docente]}"
UBIC="${2:-eastus}"
CORREO_DOC="${3:-}"
SUB=$(az account show --query id -o tsv) || { echo "Primero: az login"; exit 1; }
TENANT=$(az account show --query tenantId -o tsv)
INICIO=$(date -u '+%Y-%m-01')
FIN=$(date -u -d '+2 months' '+%Y-%m-01')

echo "Suscripción: $SUB · Tenant: $TENANT · Región: $UBIC"
while IFS=, read -r USR CORREO; do
  USR=$(echo "$USR" | tr -d '[:space:]' | tr 'A-Z' 'a-z'); CORREO=$(echo "$CORREO" | tr -d '[:space:]')
  [ -z "$USR" ] && continue
  RG="rg-c7-$USR"
  echo "--- $USR <$CORREO> → $RG"
  az group create -n "$RG" -l "$UBIC" --tags curso=senati-m4 clase=7 alumno="$USR" -o none
  ID=$(az rest --method post --url https://graph.microsoft.com/v1.0/invitations \
        --body "{\"invitedUserEmailAddress\":\"$CORREO\",\"inviteRedirectUrl\":\"https://portal.azure.com/$TENANT\",\"sendInvitationMessage\":true}" \
        --query invitedUser.id -o tsv 2>/dev/null)
  if [ -z "$ID" ]; then echo "   ERROR: no se pudo invitar a $CORREO"; continue; fi
  sleep 15   # replicación de Entra ID
  az role assignment create --assignee-object-id "$ID" --assignee-principal-type User --role Owner \
    --scope "/subscriptions/$SUB/resourceGroups/$RG" -o none && echo "   Owner en $RG"
  if [ -n "$CORREO_DOC" ]; then
    az consumption budget create --budget-name "presupuesto-$USR" --amount 3 --category cost --time-grain monthly \
      --start-date "$INICIO" --end-date "$FIN" --resource-group "$RG" -o none 2>/dev/null \
      && echo "   Presupuesto US\$3 en $RG (la alerta por correo se agrega en el portal)" || echo "   (crea el presupuesto de $RG en el portal)"
  fi
done < "$CSV"

echo "--- Nivel suscripción (una sola vez)"
LAW_RG="rg-c7-docente"
az group create -n "$LAW_RG" -l "$UBIC" -o none
az monitor log-analytics workspace create -g "$LAW_RG" -n law-c7-docente -l "$UBIC" --retention-time 30 -o none
LAW=$(az monitor log-analytics workspace show -g "$LAW_RG" -n law-c7-docente --query id -o tsv)
az monitor diagnostic-settings subscription create -n c7-actividad -l "$UBIC" --workspace "$LAW" \
  --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},{"category":"Policy","enabled":true},{"category":"Alert","enabled":true}]' -o none 2>/dev/null \
  && echo "   Registro de actividad exportado" || echo "   (registro de actividad ya existía)"
if [ -n "$CORREO_DOC" ]; then
  az provider register --namespace Microsoft.Security -o none
  az security contact create -n default --emails "$CORREO_DOC" --alert-notifications '{"state":"On","minimalSeverity":"Medium"}' \
    --notifications-by-role '{"state":"On","roles":["Owner"]}' -o none && echo "   Contacto de Defender: $CORREO_DOC"
fi
echo
echo "Listo. Comparte con los alumnos el ID de tenant para iniciar sesión:"
echo "  az login --use-device-code --tenant $TENANT"
