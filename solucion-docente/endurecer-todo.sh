#!/usr/bin/env bash
# =============================================================================
#  SOLUCIÓN DOCENTE · Clase 6 — aplica A3, A4 y B5 de una vez (NO repartir)
#  Útil para la demo en vivo o para rescatar a un alumno atrasado.
#  Uso:  sudo bash endurecer-todo.sh [a|b|todo] [/home/brian/clase-06-servicios-web]
# =============================================================================
set -euo pipefail
PARTE="${1:-todo}"
BASE="${2:-/home/brian/clase-06-servicios-web}"
A="$BASE/parte-a-host"; B="$BASE/parte-b-docker"
chmod -R o+rX "$BASE"

if [ "$PARTE" = a ] || [ "$PARTE" = todo ]; then
  echo "[A3] Apache"
  sed -i 's/^ServerTokens .*/ServerTokens Prod/; s/^ServerSignature .*/ServerSignature Off/; s/^TraceEnable .*/TraceEnable Off/' /etc/apache2/conf-available/security.conf
  sed -i 's/^Timeout 300/Timeout 60/' /etc/apache2/apache2.conf
  a2dismod -q -f status autoindex || true
  a2enmod -q ssl headers rewrite evasive
  cp "$A/apache/evasive.conf" /etc/apache2/mods-available/evasive.conf
  mkdir -p /var/log/apache2/evasive && chown www-data:www-data /var/log/apache2/evasive
  cp "$A/apache/burgerbank-ssl.conf" /etc/apache2/sites-available/
  a2dissite -q 000-default || true; a2ensite -q burgerbank-ssl
  cp "$A/sitio/index.html" /var/www/html/index.html
  apache2ctl configtest && systemctl restart apache2
  echo "[A4] Nginx"
  sed -i 's/# server_tokens off;/server_tokens off;/' /etc/nginx/nginx.conf
  cp "$A/nginx/burgerbank-nginx.conf" /etc/nginx/sites-available/burgerbank
  rm -f /etc/nginx/sites-enabled/lab-inseguro
  ln -sf /etc/nginx/sites-available/burgerbank /etc/nginx/sites-enabled/burgerbank
  cp "$A/sitio/index.html" /var/www/nginx-lab/index.html
  nginx -t && systemctl reload nginx
fi

if [ "$PARTE" = b ] || [ "$PARTE" = todo ]; then
  echo "[B5.1] daemon.json"
  cat > /etc/docker/daemon.json <<'JSON'
{
  "icc": false,
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
JSON
  python3 -m json.tool /etc/docker/daemon.json >/dev/null
  systemctl restart docker; sleep 5
  echo "[B5.2] Imágenes 2.0"
  docker build -q -t burgerbank/pedidos:2.0 "$B/endurecido/pedidos"
  docker build -q -t burgerbank/facturacion:2.0 "$B/endurecido/facturacion"
  echo "[B5.3] Secretos"
  bash "$B/endurecido/preparar-secretos.sh"
  echo "[B5.6] Cambio de versión"
  (cd "$B/inseguro" && docker compose down) || true
  (cd "$B/endurecido" && docker compose up -d)
  echo "Esperando healthchecks (45 s)..."; sleep 45
  (cd "$B/endurecido" && docker compose ps)
fi
