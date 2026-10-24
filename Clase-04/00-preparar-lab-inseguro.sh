#!/bin/bash
# =============================================================================
#  SENATI · Módulo 04 · Clase 4 — Hardening de Bases de Datos
#  00-preparar-lab-inseguro.sh
#
#  Deja MySQL 8, PostgreSQL 14 y Redis 6 INSEGUROS A PROPÓSITO, imitando
#  errores reales que se encuentran en auditorías. Úsalo SOLO en la VM del lab.
#
#  Requisitos: Ubuntu Server 22.04 con los motores ya instalados (Lab 0).
#  Uso:        sudo bash /home/brian/00-preparar-lab-inseguro.sh
# =============================================================================
set -e
umask 022   # la VM de C3 usa umask 027: sin esto los servicios no podrían leer sus configs

if [ "$EUID" -ne 0 ]; then
  echo "ERROR: ejecuta con sudo:  sudo bash $0"
  exit 1
fi

for b in mysqld psql redis-server; do
  if ! command -v "$b" >/dev/null 2>&1; then
    echo "ERROR: falta $b. Primero haz el Lab 0 (apt install ...)."
    exit 1
  fi
done

PGVER=$(ls /etc/postgresql | sort -V | tail -1)
PGCONF=/etc/postgresql/$PGVER/main
BACKUP=/root/backup-lab-bd-$(date +%Y%m%d-%H%M%S)
mkdir -p "$BACKUP"
cp -a /etc/mysql "$BACKUP/" ; cp -a "$PGCONF" "$BACKUP/postgresql-main" ; cp -a /etc/redis "$BACKUP/"
echo "[i] Respaldo de configuraciones originales en $BACKUP"

reiniciar() {
  # Funciona con systemd (VM real) o sin él (contenedor / chroot)
  if [ -d /run/systemd/system ]; then systemctl restart "$1"; else service "$1" restart >/dev/null; fi
}

# -----------------------------------------------------------------------------
echo "[1/4] MySQL: red abierta, archivos del servidor accesibles, cuentas débiles"
# -----------------------------------------------------------------------------
cat > /etc/mysql/mysql.conf.d/zz-lab-inseguro.cnf <<'EOF'
# ---- LAB INSEGURO (no usar en producción) ----
[mysqld]
bind-address        = 0.0.0.0
mysqlx-bind-address = 0.0.0.0
local_infile        = 1
secure_file_priv    = ""
general_log         = 1
general_log_file    = /var/log/mysql/general.log
log_raw             = 1
EOF
chmod 644 /etc/mysql/mysql.conf.d/zz-lab-inseguro.cnf
reiniciar mysql

mysql <<'EOF'
CREATE DATABASE IF NOT EXISTS burgerbank;
USE burgerbank;
CREATE TABLE IF NOT EXISTS clientes (
  id INT PRIMARY KEY AUTO_INCREMENT,
  nombre VARCHAR(80), dni CHAR(8), email VARCHAR(80),
  tarjeta VARCHAR(19), saldo DECIMAL(12,2));
INSERT INTO clientes (nombre,dni,email,tarjeta,saldo) VALUES
 ('Ana Quispe','40123456','ana.q@correo.pe','4111-1111-1111-1111',15200.50),
 ('Luis Mamani','41234567','lmamani@correo.pe','5500-0000-0000-0004',830.00),
 ('Rosa Huamán','42345678','rosa.h@correo.pe','3400-000000-00009',99100.75);
CREATE TABLE IF NOT EXISTS usuarios_web (usuario VARCHAR(40), clave_md5 CHAR(32));
INSERT INTO usuarios_web VALUES ('ana','e10adc3949ba59abbe56e057f20f883e'),('luis','5f4dcc3b5aa765d61d8327deb882cf99');

CREATE DATABASE IF NOT EXISTS test;

-- Usuario anónimo (cualquiera entra sin usuario ni contraseña)
CREATE USER IF NOT EXISTS ''@'%';
GRANT ALL ON test.* TO ''@'%';

-- root accesible desde cualquier IP con contraseña trivial y plugin antiguo
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED WITH mysql_native_password BY 'root';
GRANT ALL ON *.* TO 'root'@'%' WITH GRANT OPTION;

-- Cuenta de la aplicación con TODOS los privilegios globales (incluye FILE y SUPER)
CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED WITH mysql_native_password BY 'app123';
GRANT ALL ON *.* TO 'app'@'%';

-- Cuenta de reportes SIN contraseña
CREATE USER IF NOT EXISTS 'reportes'@'%' IDENTIFIED BY '';
GRANT SELECT ON burgerbank.* TO 'reportes'@'%';

-- Cuenta de un ex empleado que nadie dio de baja
CREATE USER IF NOT EXISTS 'exempleado'@'%' IDENTIFIED BY 'Verano2019';
GRANT SELECT, INSERT, UPDATE, DELETE ON burgerbank.* TO 'exempleado'@'%';
FLUSH PRIVILEGES;
EOF

# -----------------------------------------------------------------------------
echo "[2/4] PostgreSQL: escucha en todo, 'trust' desde cualquier IP, sin TLS"
# -----------------------------------------------------------------------------
mkdir -p "$PGCONF/conf.d"
cat > "$PGCONF/conf.d/zz-lab-inseguro.conf" <<'EOF'
# ---- LAB INSEGURO (no usar en producción) ----
listen_addresses     = '*'
ssl                  = off
password_encryption  = md5
log_connections      = off
log_disconnections   = off
EOF
chown postgres:postgres "$PGCONF/conf.d/zz-lab-inseguro.conf"; chmod 644 "$PGCONF/conf.d/zz-lab-inseguro.conf"

# Reglas peligrosas AL INICIO de pg_hba.conf (la primera que coincide gana)
sed -i '/LAB INSEGURO/,/fin LAB INSEGURO/d' "$PGCONF/pg_hba.conf"   # por si se ejecuta dos veces
{
  echo "# ---- LAB INSEGURO (no usar en producción) ----"
  echo "host    burgerbank      all             0.0.0.0/0               trust"
  echo "host    all             all             0.0.0.0/0               md5"
  echo "# ---- fin LAB INSEGURO ----"
  cat "$PGCONF/pg_hba.conf"
} > /tmp/pg_hba.lab && mv /tmp/pg_hba.lab "$PGCONF/pg_hba.conf"
chown postgres:postgres "$PGCONF/pg_hba.conf"; chmod 640 "$PGCONF/pg_hba.conf"
reiniciar postgresql
sleep 2

su - postgres -c "psql -q" <<'EOF'
SET password_encryption = 'md5';
ALTER USER postgres PASSWORD 'postgres';
DROP DATABASE IF EXISTS burgerbank;
CREATE DATABASE burgerbank;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='app')        THEN CREATE ROLE app LOGIN SUPERUSER PASSWORD 'app123'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='reportes')   THEN CREATE ROLE reportes LOGIN PASSWORD 'reportes'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='exempleado') THEN CREATE ROLE exempleado LOGIN PASSWORD 'Verano2019' VALID UNTIL 'infinity'; END IF;
END $$;
GRANT pg_read_server_files TO reportes;
GRANT ALL ON DATABASE burgerbank TO PUBLIC;
\c burgerbank
CREATE TABLE clientes (id serial PRIMARY KEY, nombre text, dni char(8), email text, tarjeta text, saldo numeric(12,2));
INSERT INTO clientes (nombre,dni,email,tarjeta,saldo) VALUES
 ('Ana Quispe','40123456','ana.q@correo.pe','4111-1111-1111-1111',15200.50),
 ('Luis Mamani','41234567','lmamani@correo.pe','5500-0000-0000-0004',830.00),
 ('Rosa Huamán','42345678','rosa.h@correo.pe','3400-000000-00009',99100.75);
GRANT ALL ON clientes TO PUBLIC;
EOF

# -----------------------------------------------------------------------------
echo "[3/4] Redis: abierto a la red, sin contraseña, con sesiones de clientes"
# -----------------------------------------------------------------------------
cat > /etc/redis/zz-lab-inseguro.conf <<'EOF'
# ---- LAB INSEGURO (no usar en producción) ----
bind 0.0.0.0
protected-mode no
EOF
chown redis:redis /etc/redis/zz-lab-inseguro.conf; chmod 640 /etc/redis/zz-lab-inseguro.conf
grep -q 'include /etc/redis/zz-lab-inseguro.conf' /etc/redis/redis.conf || \
  echo 'include /etc/redis/zz-lab-inseguro.conf' >> /etc/redis/redis.conf
reiniciar redis-server
sleep 1
redis-cli -n 0 SET "sesion:ana"  "token=9f8e7d6c5b4a;dni=40123456;rol=cliente" >/dev/null
redis-cli -n 0 SET "sesion:luis" "token=1a2b3c4d5e6f;dni=41234567;rol=cliente" >/dev/null
redis-cli -n 0 SET "sesion:admin" "token=ADMIN-0000-ffff;rol=administrador" >/dev/null
redis-cli -n 0 SET "config:api_pagos" "sk_live_FAKE_51HxYz_no_es_real" >/dev/null

# -----------------------------------------------------------------------------
echo "[4/4] Firewall: se abren los puertos de BD a cualquier origen"
# -----------------------------------------------------------------------------
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  for p in 3306 33060 5432 6379; do ufw allow "$p/tcp" >/dev/null; done
  echo "    ufw: abiertos 3306, 33060, 5432 y 6379 a cualquier origen"
else
  echo "    ufw no está activo: los puertos ya quedan expuestos"
fi

echo
echo "LISTO. El servidor quedó INSEGURO a propósito. Respaldo en: $BACKUP"
echo "Siguiente paso: Lab 1 (reconocimiento)."
