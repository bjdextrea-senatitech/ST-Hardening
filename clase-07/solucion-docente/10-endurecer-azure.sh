#!/usr/bin/env bash
# =============================================================================
#  SOLUCIÓN DOCENTE · Clase 7 — aplica todo el Lab 3 de una vez (NO repartir)
#  Uso:   bash 10-endurecer-azure.sh tu-correo@dominio.com
# =============================================================================
set -euo pipefail
CORREO="${1:?Uso: bash 10-endurecer-azure.sh tu-correo@dominio.com}"
source "$HOME/c7/entorno.env"
RGID="/subscriptions/$SUB/resourceGroups/$RG"
SAID=$(az storage account show -n "$SA" -g "$RG" --query id -o tsv)

echo "[3A] Identidad"
if [ -n "${PRACT_ID:-}" ]; then
  az role assignment delete --assignee "$PRACT_ID" --role Owner --scope "/subscriptions/$SUB" || true
  az role assignment create --assignee-object-id "$PRACT_ID" --assignee-principal-type User --role Reader --scope "$RGID" -o none
  az ad user update --id "$PRACT_ID" --account-enabled false
fi

echo "[3B] Almacenamiento"
az role assignment create --assignee-object-id "$YO_ID" --assignee-principal-type User \
  --role "Storage Blob Data Contributor" --scope "$SAID" -o none || true
az storage account update -n "$SA" -g "$RG" --allow-blob-public-access false --https-only true --min-tls-version TLS1_2 -o none
az storage container-rm update --storage-account "$SA" -g "$RG" -n publico --public-access off -o none
az storage account blob-service-properties update -n "$SA" -g "$RG" \
  --enable-delete-retention true --delete-retention-days 7 \
  --enable-container-delete-retention true --container-delete-retention-days 7 -o none
az storage account update -n "$SA" -g "$RG" --allow-shared-key-access false -o none

echo "[3C] Red"
MI_IP=$(curl -s https://api.ipify.org)
az network nsg rule delete -g "$RG" --nsg-name "$NSG" -n permitir-rdp-internet
az network nsg rule update -g "$RG" --nsg-name "$NSG" -n permitir-ssh-internet --source-address-prefixes "$MI_IP/32" -o none

echo "[3D] Registros y alertas"
az monitor log-analytics workspace create -g "$RG" -n law-c7 -l "$UBIC" --retention-time 30 -o none
LAW=$(az monitor log-analytics workspace show -g "$RG" -n law-c7 --query id -o tsv)
az monitor diagnostic-settings subscription create -n c7-actividad -l "$UBIC" --workspace "$LAW" \
  --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},{"category":"Policy","enabled":true},{"category":"Alert","enabled":true}]' -o none
az monitor action-group create -g "$RG" -n ag-c7 --short-name agc7 --action email responsable "$CORREO" -o none
AG=$(az monitor action-group show -g "$RG" -n ag-c7 --query id -o tsv)
az monitor activity-log alert create -g "$RG" -n alerta-cambio-nsg --scope "$RGID" \
  --condition category=Administrative and operationName=Microsoft.Network/networkSecurityGroups/securityRules/write \
  --action-group "$AG" --description "Cambio en una regla de NSG" -o none

echo "[3E] Gobierno"
az provider register --namespace Microsoft.Security -o none
az security contact create -n default --emails "$CORREO" \
  --alert-notifications '{"state":"On","minimalSeverity":"Medium"}' \
  --notifications-by-role '{"state":"On","roles":["Owner"]}' -o none
POL=$(az policy definition list --query "[?displayName=='Storage account public access should be disallowed'].name | [0]" -o tsv)
EF=$(az policy definition show -n "$POL" --query "parameters.effect.allowedValues[?@=='Deny' || @=='deny'] | [0]" -o tsv)
az policy assignment create -n c7-sin-almacenamiento-publico --display-name "C7 - Storage account public access should be disallowed" \
  --policy "$POL" --scope "$RGID" --params "{\"effect\":{\"value\":\"$EF\"}}" -o none
az group update -n "$RG" --tags propietario=brian entorno=laboratorio clasificacion=interno -o none
az lock create -n no-borrar -g "$RG" --lock-type CanNotDelete --notes "Laboratorio C7: quitar antes de limpiar" -o none
echo "Listo."
