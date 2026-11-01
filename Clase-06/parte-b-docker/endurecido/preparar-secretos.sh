#!/usr/bin/env bash
# =============================================================================
#  Clase 6 · Prepara los secretos y el certificado de la versión endurecida
#  Uso:  cd /home/brian/clase-06-contenedores/endurecido
#        sudo bash preparar-secretos.sh
#
#  Crea:
#   secrets/redis_password.txt  clave aleatoria que usa el microservicio pedidos
#   secrets/redis_users.acl     usuarios de Redis (la clave va como hash SHA-256)
#   secrets/api_keys.json       claves de API de los clientes ana y luis (REST y SOAP)
#   certs/web.crt  certs/web.key  certificado autofirmado para nginx (1 año)
#  Y deja cada archivo legible solo por el usuario del contenedor que lo usa.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
umask 077
mkdir -p secrets certs

# 1) Clave aleatoria de 32 caracteres para Redis
CLAVE=$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 32)
printf '%s' "$CLAVE" > secrets/redis_password.txt

# 2) Archivo ACL: default deshabilitado y un usuario "pedidos" con permisos mínimos
HASH=$(printf '%s' "$CLAVE" | sha256sum | cut -d' ' -f1)
cat > secrets/redis_users.acl <<EOF
user default off
user pedidos on #$HASH ~* +@read +@write +@connection +hello -@dangerous
EOF

# 2b) Claves de API: una por cliente (las usan pedidos y facturacion)
K_ANA=$(openssl rand -hex 20); K_LUIS=$(openssl rand -hex 20)
printf '{"%s": "ana", "%s": "luis"}\n' "$K_ANA" "$K_LUIS" > secrets/api_keys.json

# 3) Certificado autofirmado (CN y SAN con la IP del Ubuntu)
IP=$(hostname -I | awk '{print $1}')
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout certs/web.key -out certs/web.crt \
  -subj "/C=PE/O=BurgerBank Lab/CN=burgerbank.lab" \
  -addext "subjectAltName=DNS:burgerbank.lab,DNS:localhost,IP:127.0.0.1,IP:${IP}" 2>/dev/null

# 4) Dueños y permisos: cada secreto solo para el usuario de su contenedor
#    pedidos = uid 10001 · redis (alpine) = uid 999 · nginx-unprivileged = uid 101
chown 10001:10001 secrets/redis_password.txt && chmod 400 secrets/redis_password.txt
chown 999:1000    secrets/redis_users.acl    && chmod 400 secrets/redis_users.acl
chown 10001:10001 secrets/api_keys.json      && chmod 400 secrets/api_keys.json
chown 101:101     certs/web.key              && chmod 400 certs/web.key
chmod 444 certs/web.crt
chmod 755 secrets certs

echo "Secretos y certificado listos:"
ls -ln secrets certs
echo
echo "Claves de API para tus pruebas con curl (guárdalas en variables):"
echo "  CLAVE_ANA=$K_ANA"
echo "  CLAVE_LUIS=$K_LUIS"
