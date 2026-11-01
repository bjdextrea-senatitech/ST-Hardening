#!/usr/bin/env bash
# =============================================================================
#  Clase 6 · Parte A — Instala Apache y Nginx en el Ubuntu "como vienen" + errores típicos
#  Uso:  sudo bash preparar-web-host.sh
#
#  Apache  → http://localhost:8081   (8441 queda reservado para HTTPS)
#  Nginx   → http://localhost:8082   (8442 queda reservado para HTTPS)
#  Los puertos 80/443 quedan libres para la Parte B (Docker).
#
#  Errores que deja (a propósito):
#   - Páginas por defecto ("It works" / "Welcome to nginx")
#   - Versión del servidor visible (cabecera y páginas de error)
#   - Listado de directorios en /descargas/ con un respaldo con claves
#   - Archivo .env servido en la raíz
#   - Páginas de estado (/server-status, /nginx_status)
#   - Solo HTTP, sin cabeceras de seguridad ni límites
#  Datos FICTICIOS. Solo para la VM del laboratorio.
# =============================================================================
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Ejecuta con sudo"; exit 1; }
umask 022    # los archivos web deben ser legibles por www-data (la VM tiene umask 027 desde la Clase 3)

echo "[1/5] Instalando Apache, Nginx, mod_evasive, nmap y ssl-cert"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq apache2 nginx libapache2-mod-evasive nmap ssl-cert curl >/dev/null
systemctl stop apache2 nginx || true

echo "[2/5] Apache en el puerto 8081"
sed -i 's/^Listen 80$/Listen 8081/; s/Listen 443$/Listen 8441/' /etc/apache2/ports.conf
sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8081>/' /etc/apache2/sites-available/000-default.conf
a2dismod -q evasive >/dev/null 2>&1 || true          # el límite de peticiones se activa en el Lab A3
a2enmod -q status autoindex >/dev/null

echo "[3/5] Contenido inseguro para Apache (/var/www/html)"
mkdir -p /var/www/html/descargas
cat > /var/www/html/descargas/backup-config-2026.txt <<'EOF'
# Respaldo de configuración (FICTICIO)
db_host=10.0.0.15
db_password=BurgerDB2024!
api_admin_token=bb-admin-7f3a9c2e1d
EOF
cat > /var/www/html/.env <<'EOF'
APP_ENV=produccion
DB_PASSWORD=BurgerDB2024!
SMTP_PASSWORD=Correo2024!
EOF

echo "[4/5] Nginx en el puerto 8082 con su sitio inseguro"
rm -f /etc/nginx/sites-enabled/default
mkdir -p /var/www/nginx-lab/descargas
cp /var/www/html/index.nginx-debian.html /var/www/nginx-lab/index.html
cp /var/www/html/descargas/backup-config-2026.txt /var/www/nginx-lab/descargas/
cp /var/www/html/.env /var/www/nginx-lab/.env
cat > /etc/nginx/sites-available/lab-inseguro <<'EOF'
# Sitio del laboratorio · VERSIÓN INSEGURA (Clase 6, Parte A)
server {
    listen 8082;
    server_name _;
    root /var/www/nginx-lab;
    index index.html;

    location /descargas/ {
        autoindex on;                 # lista los archivos de la carpeta
    }
    location /nginx_status {
        stub_status;                  # estadísticas internas del servidor, para cualquiera
    }
}
EOF
ln -sf /etc/nginx/sites-available/lab-inseguro /etc/nginx/sites-enabled/lab-inseguro

echo "[5/5] Iniciando ambos servidores"
apache2ctl configtest
nginx -t
systemctl enable --now apache2 nginx >/dev/null 2>&1 || true
systemctl restart apache2 nginx

echo
echo "Listo:"
echo "  Apache → http://localhost:8081/"
echo "  Nginx  → http://localhost:8082/"
