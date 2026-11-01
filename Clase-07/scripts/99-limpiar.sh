#!/usr/bin/env bash
# =============================================================================
#  Clase 7 · Limpieza: borra TODO lo creado en el laboratorio (deja el presupuesto)
#  Uso:   bash 99-limpiar.sh
#  Orden: bloqueo → asignaciones de rol del practicante → usuario → diagnóstico
#         de la suscripción → grupo de recursos completo.
# =============================================================================
set -uo pipefail
source "$HOME/c7/entorno.env" || { echo "No existe \$HOME/c7/entorno.env"; exit 1; }
az account show -o none 2>/dev/null || { echo "Sesión vencida: az login --use-device-code"; exit 1; }

echo "Se borrará el grupo $RG con todo su contenido y el usuario ${PRACT_UPN:-'(sin practicante)'}."
read -r -p "Escribe BORRAR para continuar: " R
[ "$R" = "BORRAR" ] || { echo "Cancelado."; exit 0; }

echo "[1/5] Quitando bloqueos del grupo"
for L in $(az lock list -g "$RG" --query "[].name" -o tsv 2>/dev/null); do az lock delete -n "$L" -g "$RG"; done

if [ -n "${PRACT_ID:-}" ]; then
  echo "[2/5] Quitando roles del practicante"
  for A in $(az role assignment list --assignee "$PRACT_ID" --all --query "[].id" -o tsv 2>/dev/null); do
    az role assignment delete --ids "$A"
  done
  echo "[3/5] Borrando el usuario practicante"
  az ad user delete --id "$PRACT_ID" || true
else
  echo "[2/5][3/5] Sin usuario practicante"
fi

echo "[4/5] Borrando la exportación del registro de actividad"
az monitor diagnostic-settings subscription delete -n c7-actividad --yes 2>/dev/null || true

echo "[5/5] Borrando el grupo de recursos (tarda 2–5 minutos)"
az group delete -n "$RG" --yes

echo "Listo. Verifica en el portal que no quedan recursos y revisa Cost Management mañana."
