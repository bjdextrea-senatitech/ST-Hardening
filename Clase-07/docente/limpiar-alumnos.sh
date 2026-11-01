#!/usr/bin/env bash
# =============================================================================
#  DOCENTE · Clase 7 — Borra los grupos y los invitados creados con preparar-alumnos.sh
#  Uso:   bash limpiar-alumnos.sh alumnos.csv
# =============================================================================
set -uo pipefail
CSV="${1:?Uso: bash limpiar-alumnos.sh alumnos.csv}"
read -r -p "Se borrarán los grupos rg-c7-* de la lista, sus invitados y rg-c7-docente. Escribe BORRAR: " R
[ "$R" = "BORRAR" ] || { echo "Cancelado."; exit 0; }
while IFS=, read -r USR CORREO; do
  USR=$(echo "$USR" | tr -d '[:space:]' | tr 'A-Z' 'a-z'); CORREO=$(echo "$CORREO" | tr -d '[:space:]')
  [ -z "$USR" ] && continue
  RG="rg-c7-$USR"
  for L in $(az lock list -g "$RG" --query "[].name" -o tsv 2>/dev/null); do az lock delete -n "$L" -g "$RG"; done
  az group delete -n "$RG" --yes --no-wait 2>/dev/null && echo "Borrando $RG"
  ID=$(az ad user list --filter "mail eq '$CORREO'" --query "[0].id" -o tsv 2>/dev/null)
  [ -n "$ID" ] && az ad user delete --id "$ID" && echo "Invitado $CORREO eliminado"
done < "$CSV"
az monitor diagnostic-settings subscription delete -n c7-actividad --yes 2>/dev/null || true
az group delete -n rg-c7-docente --yes --no-wait 2>/dev/null || true
echo "Listo (los grupos terminan de borrarse en segundo plano)."
