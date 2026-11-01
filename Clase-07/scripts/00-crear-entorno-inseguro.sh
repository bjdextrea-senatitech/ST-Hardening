#!/usr/bin/env bash
# =============================================================================
#  Clase 7 · Crea en TU suscripción de Azure un entorno inseguro "de tutorial"
#  Uso:   bash 00-crear-entorno-inseguro.sh            (región eastus)
#         bash 00-crear-entorno-inseguro.sh brazilsouth
#  En la suscripción del docente (invitado):  RG_C7=rg-c7-tuusuario bash 00-crear-entorno-inseguro.sh
#
#  Requisitos: az login hecho (az login --use-device-code).
#  Crea (todo gratis o centavos del crédito):
#   - Grupo de recursos rg-c7-senati
#   - Cuenta de almacenamiento con acceso público, HTTP permitido y clave compartida
#   - Contenedor "publico" con un CSV FICTICIO de clientes, legible por cualquiera
#   - NSG con SSH (22) y RDP (3389) abiertos a todo internet
#   - Usuario "practicante-c7" con rol Owner en TODA la suscripción
#  Guarda los nombres en $HOME/c7/entorno.env para los siguientes pasos.
# =============================================================================
set -euo pipefail
UBIC="${1:-eastus}"
DIR="$HOME/c7"
mkdir -p "$DIR/antes" "$DIR/despues"

az account show -o none 2>/dev/null || { echo "Primero inicia sesión: az login --use-device-code"; exit 1; }

SUB=$(az account show --query id -o tsv)
YO_UPN=$(az ad signed-in-user show --query userPrincipalName -o tsv)
YO_ID=$(az ad signed-in-user show --query id -o tsv)
DOMINIO="${YO_UPN##*@}"
SUF=$(tr -dc 'a-z0-9' </dev/urandom | head -c 6)
RG="${RG_C7:-rg-c7-senati}"
# Si el grupo ya existe (lo creó el docente), se usa su región
UBIC_RG=$(az group show -n "$RG" --query location -o tsv 2>/dev/null || true)
[ -n "$UBIC_RG" ] && UBIC="$UBIC_RG"
SA="stc7${SUF}"
NSG="nsg-c7-web"
PRACT_UPN="practicante-c7@${DOMINIO}"
PRACT_ID=""

echo "[1/6] Grupo de recursos $RG en $UBIC"
[ -n "$UBIC_RG" ] || az group create -n "$RG" -l "$UBIC" -o none

echo "[2/6] Cuenta de almacenamiento $SA (acceso público y HTTP permitidos)"
az storage account create -n "$SA" -g "$RG" -l "$UBIC" --sku Standard_LRS --kind StorageV2 \
  --allow-blob-public-access true --https-only false --allow-shared-key-access true -o none

echo "[3/6] Contenedor público con datos ficticios"
KEY=$(az storage account keys list -n "$SA" -g "$RG" --query "[0].value" -o tsv)
for i in 1 2 3 4 5 6 7 8; do
  if az storage container create -n publico --account-name "$SA" --account-key "$KEY" --public-access blob -o none 2>/dev/null; then
    break
  fi
  echo "   (Azure aún aplica el acceso público, reintento $i/8 en 15 s)"; sleep 15
done
cat > "$DIR/planilla-clientes.csv" <<'EOF'
dni,nombre,correo,tarjeta,linea_credito
40123456,Ana Quispe (FICTICIO),ana.quispe@correo.pe,4111-XXXX-XXXX-1111,15000
41234567,Luis Mamani (FICTICIO),lmamani@correo.pe,5500-XXXX-XXXX-0004,8000
42345678,Rosa Huaman (FICTICIO),rhuaman@correo.pe,3400-XXXX-XXXX-0009,20000
EOF
az storage blob upload --account-name "$SA" --account-key "$KEY" -c publico -n planilla-clientes.csv \
  -f "$DIR/planilla-clientes.csv" --overwrite -o none

echo "[4/6] NSG $NSG con SSH y RDP abiertos a internet"
az network nsg create -g "$RG" -n "$NSG" -l "$UBIC" -o none
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n permitir-ssh-internet --priority 100 \
  --direction Inbound --access Allow --protocol Tcp --source-address-prefixes '*' --destination-port-ranges 22 -o none
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n permitir-rdp-internet --priority 110 \
  --direction Inbound --access Allow --protocol Tcp --source-address-prefixes '*' --destination-port-ranges 3389 -o none

echo "[5/6] Usuario practicante con rol Owner en toda la suscripción"
CLAVE_P="C7-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 14)!"
if az ad user create --display-name "Practicante C7" --user-principal-name "$PRACT_UPN" \
     --password "$CLAVE_P" --force-change-password-next-sign-in true -o none 2>/dev/null; then
  PRACT_ID=$(az ad user show --id "$PRACT_UPN" --query id -o tsv)
  sleep 20   # Entra ID tarda unos segundos en replicar el usuario
  az role assignment create --assignee-object-id "$PRACT_ID" --assignee-principal-type User \
    --role Owner --scope "/subscriptions/$SUB" -o none
else
  echo "   AVISO: no se pudo crear el usuario (¿Azure for Students o invitado en la suscripción del docente?)."
  echo "   Sigue sin él: los controles IAM saldrán N/A."
  PRACT_UPN=""
fi

echo "[6/6] Guardando nombres en $DIR/entorno.env"
cat > "$DIR/entorno.env" <<EOF
# Variables del laboratorio de la Clase 7 (carga con: source \$HOME/c7/entorno.env)
SUB=$SUB
RG=$RG
UBIC=$UBIC
SA=$SA
NSG=$NSG
YO_UPN=$YO_UPN
YO_ID=$YO_ID
PRACT_UPN=$PRACT_UPN
PRACT_ID=$PRACT_ID
EOF
chmod 600 "$DIR/entorno.env"

echo
echo "Listo. Entorno inseguro creado. URL pública del archivo:"
echo "  https://${SA}.blob.core.windows.net/publico/planilla-clientes.csv"
