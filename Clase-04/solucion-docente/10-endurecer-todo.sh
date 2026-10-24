#!/bin/bash
# =============================================================================
#  SENATI · Módulo 04 · Clase 4 — SOLUCIÓN DOCENTE (NO REPARTIR)
#  10-endurecer-todo.sh: aplica en un solo paso lo que el Lab 3 hace a mano
#  sobre MySQL, PostgreSQL y Redis. Sirve para preparar la demo o rescatar
#  a un alumno atrasado.
#
#  Uso:  sudo IP_UBUNTU=10.0.2.15 IP_KALI=10.0.2.4 bash 10-endurecer-todo.sh
# =============================================================================
set -e
: "${IP_UBUNTU:?Define IP_UBUNTU}"; : "${IP_KALI:?Define IP_KALI}"
[ "$EUID" -eq 0 ] || { echo "Ejecuta con sudo"; exit 1; }
PGVER=$(ls /etc/postgresql | sort -V | tail -1); PGCONF=/etc/postgresql/$PGVER/main
reiniciar() { if [ -d /run/systemd/system ]; then systemctl restart "$1"; else service "$1" restart >/dev/null; fi; }

echo "== MySQL =="
# 3A.1 Sobrantes
mysql -e "DROP USER IF EXISTS ''@'%'; DROP USER IF EXISTS 'root'@'%'; DROP USER IF EXISTS 'exempleado'@'%'; DROP DATABASE IF EXISTS test;"
# 3A.2 Política de contraseñas
mysql -e "INSTALL COMPONENT 'file://component_validate_password';" 2>/dev/null || true
mysql -e "SET PERSIST validate_password.length = 12; SET PERSIST validate_password.policy = 'MEDIUM'; SET PERSIST default_password_lifetime = 90; SET PERSIST password_history = 5; SET PERSIST password_reuse_interval = 365;"
# 3A.3 Cuentas con mínimo privilegio
mysql -e "RENAME USER 'app'@'%' TO 'app'@'$IP_KALI';"
mysql -e "REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'app'@'$IP_KALI';"
mysql -e "GRANT SELECT, INSERT, UPDATE ON burgerbank.* TO 'app'@'$IP_KALI';"
mysql -e "ALTER USER 'app'@'$IP_KALI' IDENTIFIED WITH caching_sha2_password BY 'App#Burger2026!' REQUIRE SSL FAILED_LOGIN_ATTEMPTS 4 PASSWORD_LOCK_TIME 1;"
mysql -e "RENAME USER 'reportes'@'%' TO 'reportes'@'$IP_KALI';"
mysql -e "ALTER USER 'reportes'@'$IP_KALI' IDENTIFIED BY 'Rep#Burger2026!' REQUIRE SSL FAILED_LOGIN_ATTEMPTS 4 PASSWORD_LOCK_TIME 1;"
# 3A.4 Configuración del servidor
cat > /etc/mysql/mysql.conf.d/zzz-hardening.cnf <<EOF
[mysqld]
bind-address = 127.0.0.1,$IP_UBUNTU
mysqlx = OFF
local_infile = OFF
secure_file_priv = /var/lib/mysql-files
require_secure_transport = ON
tls_version = TLSv1.2,TLSv1.3
general_log = OFF
log_raw = OFF
log_error_verbosity = 3
plugin-load-add = connection_control.so
connection_control_failed_connections_threshold = 3
connection_control_min_connection_delay = 2000
EOF
reiniciar mysql
rm -f /var/log/mysql/general.log
ln -sf /dev/null /root/.mysql_history

echo "== PostgreSQL =="
cat > "$PGCONF/conf.d/zzz-hardening.conf" <<EOF
listen_addresses = 'localhost,$IP_UBUNTU'
ssl = on
ssl_min_protocol_version = 'TLSv1.3'
password_encryption = 'scram-sha-256'
authentication_timeout = '30s'
shared_preload_libraries = 'auth_delay,passwordcheck,pgaudit'
auth_delay.milliseconds = '2000'
pgaudit.log = 'role,ddl'
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d.log'
log_connections = on
log_disconnections = on
log_line_prefix = '%m [%p] db=%d,user=%u,app=%a,client=%h '
log_statement = 'ddl'
log_error_verbosity = 'verbose'
log_timezone = 'UTC'
log_truncate_on_rotation = on
EOF
chown postgres:postgres "$PGCONF/conf.d/zzz-hardening.conf"
sed -i '/LAB INSEGURO/,/fin LAB INSEGURO/d' "$PGCONF/pg_hba.conf"
sed -i "1i hostssl   burgerbank  app       $IP_KALI/32  scram-sha-256\nhostssl   burgerbank  reportes  $IP_KALI/32  scram-sha-256\nhostnossl all         all       0.0.0.0/0    reject" "$PGCONF/pg_hba.conf"
reiniciar postgresql
sleep 2
su postgres -s /bin/bash -c "psql -q" <<'EOF'
ALTER ROLE app NOSUPERUSER CONNECTION LIMIT 20 PASSWORD 'App#Burger2026!';
REVOKE pg_read_server_files FROM reportes;
ALTER ROLE reportes CONNECTION LIMIT 5 PASSWORD 'Rep#Burger2026!';
DROP ROLE IF EXISTS exempleado;
ALTER ROLE postgres PASSWORD NULL;
REVOKE ALL ON DATABASE burgerbank FROM PUBLIC;
GRANT CONNECT ON DATABASE burgerbank TO app, reportes;
\c burgerbank
REVOKE ALL ON clientes FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON clientes TO app;
GRANT USAGE ON SEQUENCE clientes_id_seq TO app;
GRANT SELECT (id, nombre, saldo) ON clientes TO reportes;
CREATE EXTENSION IF NOT EXISTS pgaudit;
EOF
for db in postgres template1 burgerbank; do
  su postgres -s /bin/bash -c "psql -q -d $db -c 'REVOKE ALL ON SCHEMA public FROM PUBLIC;'"
done
su postgres -s /bin/bash -c "psql -q -d burgerbank -c 'GRANT USAGE ON SCHEMA public TO app, reportes;'"

echo "== Redis =="
HADMIN=$(echo -n 'Admin#Redis2026!' | sha256sum | cut -d' ' -f1)
HAPP=$(echo -n 'App#Redis2026!' | sha256sum | cut -d' ' -f1)
cat > /etc/redis/zzz-hardening.conf <<EOF
bind 127.0.0.1 $IP_UBUNTU
protected-mode yes
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command DEBUG ""
rename-command CONFIG "CONFIG_bb2026"
user default off
user admin on #$HADMIN ~* +@all
user app on #$HAPP ~sesion:* -@all +get +set +del +expire +ttl +@connection
EOF
chown redis:redis /etc/redis/zzz-hardening.conf; chmod 640 /etc/redis/zzz-hardening.conf
grep -q 'include /etc/redis/zzz-hardening.conf' /etc/redis/redis.conf || echo 'include /etc/redis/zzz-hardening.conf' >> /etc/redis/redis.conf
reiniciar redis-server

echo "== Firewall =="
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  for p in 3306 33060 5432 6379; do ufw delete allow "$p/tcp" >/dev/null 2>&1 || true; done
  for p in 3306 5432 6379; do ufw allow from "$IP_KALI" to any port "$p" proto tcp >/dev/null; done
fi
echo "Listo."
