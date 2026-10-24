# Clase 4 · Laboratorio — Hardening de Bases de Datos (SQL, NoSQL y vectoriales)

**SENATI · Diplomado Gestión de la Ciberseguridad · Módulo 04 "Aseguramiento de los Sistemas"**
**Docente:** Ademir Cuadros · **Duración de la práctica:** 2 horas (+ Lab 6 opcional / tarea)

> Ciclo de siempre: **medir → enumerar riesgos → endurecer → re-medir → mirar desde afuera.**
> Hoy lo aplicamos a **tres motores a la vez** en la misma VM Ubuntu de la Clase 3:
> **MySQL 8** (SQL), **PostgreSQL 14** (SQL) y **Redis 6** (NoSQL clave-valor). El Lab 6 agrega una
> **base de datos vectorial (Qdrant)**, la que usan los chatbots con IA.

---

## Antes de empezar (leer 1 minuto)

- Todo se hace en la VM **Ubuntu Server 22.04** de la Clase 3 (usuario `brian`, red NAT `LabSENATI`).
  Si tu usuario no es `brian`, reemplaza `/home/brian/` por tu carpeta en todos los comandos.
- Reemplaza **`IP_UBUNTU`** por la IP de tu Ubuntu y **`IP_KALI`** por la IP de tu Kali
  (en cada VM: `ip -4 addr show`). Kali hace de "servidor de aplicación" y de "atacante externo".
- **Toma un snapshot** de la VM Ubuntu antes del Lab 0 y otro antes del Lab 3.
- Trabaja por **SSH** y **no cierres la sesión** cuando cambies configuraciones: si algo falla, la sesión abierta te salva.
- Bloques que empiezan con `# 🐉 En Kali` se ejecutan en Kali. Todo lo demás, en Ubuntu.
- Las contraseñas de este lab son de ejemplo. En la vida real: gestor de secretos y nunca en un `.md`.

### Agenda (120 min)

| Bloque | Qué haces | Min |
|---|---|---|
| Lab 0 | Instalar los 3 motores y dejarlos inseguros a propósito | 10 |
| Lab 1 | Reconocimiento: qué escucha, quién lo corre, qué ve Kali | 15 |
| Lab 1b | ¿Qué podría salir mal? Enumerar privilegios y configuraciones peligrosas | 10 |
| Lab 2 | Medir ANTES: auditor MySQL, pgDSAT (CIS PostgreSQL) y auditor Redis | 10 |
| Lab 3 | Hardening: 3A MySQL (20) · 3B PostgreSQL (20) · 3C Redis (10) | 50 |
| Lab 4 | Medir DESPUÉS y comparar | 10 |
| Lab 5 | Vista desde Kali después del hardening | 10 |
| Entrega | Evidencias al repositorio | 5 |
| Lab 6 | **Opcional / tarea:** base vectorial Qdrant expuesta y endurecida | 20 |

### Mapa de la clase

```
            Red NAT LabSENATI
 ┌──────────────┐                ┌───────────────────────────────────────┐
 │  Kali        │  3306 MySQL    │  Ubuntu 22.04 (VM de la Clase 3)      │
 │  IP_KALI     │ ─────────────▶ │   MySQL 8      burgerbank.clientes    │
 │  app + ojo   │  5432 Postgres │   PostgreSQL 14 burgerbank.clientes   │
 │  externo     │  6379 Redis    │   Redis 6       sesiones de clientes  │
 │              │  6333 Qdrant   │   Qdrant (Lab 6) memoria del chatbot  │
 └──────────────┘                └───────────────────────────────────────┘
```

---

## Lab 0 · Preparación (10 min)

### 0.1 Instalar los motores

```bash
# Actualiza la lista de paquetes de los repositorios de Ubuntu
sudo apt update
# Instala MySQL 8, PostgreSQL 14 (+ extensión de auditoría pgaudit), Redis 6 y herramientas
sudo apt install -y mysql-server postgresql postgresql-14-pgaudit redis-server nmap git
# Confirma las versiones instaladas de cada motor
mysqld --version ; psql --version ; redis-server --version
```

### 0.2 Copiar los scripts de la clase a /home/brian/

```bash
# 🐉 En Kali (o en tu PC): copia la carpeta de la clase a la VM Ubuntu por SSH
scp -r clase-04-bases-de-datos/* brian@IP_UBUNTU:/home/brian/
```

```bash
# Crea la carpeta donde guardarás todas las evidencias de hoy
mkdir -p /home/brian/evidencias
# Comprueba que llegaron los scripts
ls -l /home/brian/*.sh /home/brian/*.sql
```

### 0.3 Dejar el servidor inseguro (a propósito)

```bash
# Ejecuta el sabotaje: abre red, crea cuentas débiles, quita TLS, carga datos de clientes
sudo bash /home/brian/00-preparar-lab-inseguro.sh
```

> El script imita errores reales de auditoría: usuario anónimo, `root` remoto, app con `ALL ON *.*`,
> `trust` en PostgreSQL, Redis sin contraseña... y **guarda un respaldo** de las configuraciones originales en `/root/backup-lab-bd-*`.

---

## Lab 1 · Reconocimiento (15 min)

### 1.1 Desde dentro (Ubuntu)

```bash
# Lista los puertos TCP en escucha y qué proceso los abrió (0.0.0.0 = todas las interfaces)
sudo ss -ltnp | grep -E '3306|33060|5432|6379'
# Muestra con qué usuario del sistema corre cada motor (nunca debería ser root)
ps -o user,pid,cmd -C mysqld,postgres,redis-server | head -8
# Muestra los permisos de las carpetas de configuración de cada motor
ls -ld /etc/mysql/mysql.conf.d /etc/postgresql/14/main /etc/redis
# Muestra los archivos que el sabotaje agregó (en producción buscarías "el último que gana")
ls -l /etc/mysql/mysql.conf.d/ /etc/postgresql/14/main/conf.d/ /etc/redis/
# Revisa el estado del firewall de la Clase 3 y los puertos que se abrieron
sudo ufw status numbered
```

### 1.2 Desde afuera (Kali)

```bash
# 🐉 En Kali: identifica servicios y versiones en los puertos de bases de datos
nmap -sV -p 3306,33060,5432,6379 IP_UBUNTU
# Scripts NSE de solo lectura: info del servidor MySQL y cuentas con contraseña vacía
nmap -p 3306 --script mysql-info,mysql-empty-password IP_UBUNTU
# Script NSE que pide a Redis su información interna (versión, SO, clientes conectados)
nmap -p 6379 --script redis-info IP_UBUNTU
```

```bash
# 🐉 En Kali: entra a MySQL con un usuario inventado (el usuario anónimo lo acepta)
mysql -h IP_UBUNTU -u cualquiera --skip-ssl -e "SELECT CURRENT_USER(); SHOW DATABASES;"
# Entra con la cuenta de reportes, que no tiene contraseña, y lee datos de clientes
mysql -h IP_UBUNTU -u reportes --skip-ssl -e "SELECT nombre, tarjeta FROM burgerbank.clientes;"
# Entra a PostgreSQL como superusuario postgres SIN contraseña (regla trust)
psql "host=IP_UBUNTU user=postgres dbname=burgerbank" -c "SELECT current_user, usesuper FROM pg_user WHERE usename = current_user;"
# Lista todas las llaves de Redis sin autenticarte
redis-cli -h IP_UBUNTU KEYS '*'
# Lee una sesión de cliente y un secreto de la aplicación
redis-cli -h IP_UBUNTU MGET sesion:admin config:api_pagos
```

> **Anota en tu evidencia:** ¿cuántos de estos accesos debieron ser imposibles?
> Si tu cliente `mysql` de Kali no reconoce `--skip-ssl`, quítalo (versiones antiguas no lo necesitan).

---

## Lab 1b · ¿Qué podría salir mal? (10 min, solo lectura)

Equivalente al "Lab 1b de escalada" de la Clase 3, pero dentro de las bases de datos.

### MySQL

```bash
# Lista cuentas, desde dónde pueden entrar, plugin de autenticación y si tienen contraseña
sudo mysql -e "SELECT user, host, plugin, authentication_string='' AS sin_clave, account_locked FROM mysql.user;"
# Cuentas con FILE (leer/escribir archivos del SO) o SUPER (administrar el servidor)
sudo mysql -e "SELECT user, host, File_priv, Super_priv, Grant_priv FROM mysql.user WHERE File_priv='Y' OR Super_priv='Y';"
# secure_file_priv vacío = FILE puede tocar cualquier carpeta; local_infile = carga de archivos del cliente
sudo mysql -e "SHOW VARIABLES WHERE Variable_name IN ('secure_file_priv','local_infile','bind_address','require_secure_transport');"
# Los privilegios exactos de la cuenta de la aplicación
sudo mysql -e "SHOW GRANTS FOR 'app'@'%';"
# El log general con log_raw guarda contraseñas en texto plano: búscalas
sudo grep -i "identified" /var/log/mysql/general.log | head -5
```

### PostgreSQL

```bash
# El usuario postgres no puede entrar a /home/brian (750): trabaja desde /tmp para evitar avisos
cd /tmp
# Roles: ¿quién es superusuario, quién puede crear roles o bases?
sudo -u postgres psql -c "\du"
# Roles con poderes sobre archivos y programas del servidor (leer archivos, ejecutar comandos)
sudo -u postgres psql -c "SELECT r.rolname AS rol, m.rolname AS miembro FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member WHERE r.rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program');"
# Contraseñas guardadas con md5 (débil) en vez de SCRAM-SHA-256
sudo -u postgres psql -c "SELECT rolname, left(rolpassword,6) AS formato FROM pg_authid WHERE rolpassword IS NOT NULL;"
# Reglas de acceso efectivas: busca 'trust' y rangos 0.0.0.0/0
sudo -u postgres psql -c "SELECT line_number, type, database, user_name, address, auth_method FROM pg_hba_file_rules;"
# ¿Cualquier usuario (PUBLIC) puede crear objetos en el esquema public de burgerbank?
sudo -u postgres psql -d burgerbank -c "SELECT has_schema_privilege('public','public','CREATE') AS public_puede_crear;"
```

### Redis

```bash
# Interfaces de escucha y modo protegido (protege solo si NO hay bind ni contraseña)
redis-cli CONFIG GET bind ; redis-cli CONFIG GET protected-mode
# 'dir' y 'dbfilename': con CONFIG SET un intruso puede escribir archivos donde Redis tenga permiso
redis-cli CONFIG GET dir ; redis-cli CONFIG GET dbfilename
# Usuarios ACL: 'default' con nopass y +@all = cualquiera es administrador
redis-cli ACL LIST
# Cuenta las llaves sin recorrerlas todas (KEYS * bloquea Redis en producción)
redis-cli DBSIZE
```

> **Pregunta para la evidencia:** de todo lo anterior, ¿qué permitiría saltar de la base de datos al sistema operativo?

---

## Lab 2 · Medir ANTES (10 min)

### 2.1 MySQL — auditor de 20 controles (CIS MySQL 8.0 + BB-LIN-SEG-02)

```bash
# Ejecuta el auditor de solo lectura y guarda la tabla PASS/FAIL como evidencia
sudo mysql -t < /home/brian/auditar-mysql.sql | tee /home/brian/evidencias/mysql-antes.txt
```

### 2.2 PostgreSQL — pgDSAT (≈90 controles del CIS PostgreSQL Benchmark)

pgDSAT es el "OpenSCAP de PostgreSQL": open source, lo ejecuta el usuario `postgres` y genera un reporte HTML.

```bash
# Descarga pgDSAT en /opt (el usuario postgres no puede leer /home/brian, que es 750 desde la Clase 3)
sudo git clone https://github.com/HexaCluster/pgdsat.git /opt/pgdsat
# Entrega la carpeta al usuario postgres, que es quien ejecuta la herramienta
sudo chown -R postgres:postgres /opt/pgdsat
# Te ubicas en /tmp porque postgres no puede entrar a tu carpeta personal
cd /tmp
# Genera el reporte HTML (sin consultar internet por la última versión de PostgreSQL)
sudo -u postgres perl -I /opt/pgdsat/lib /opt/pgdsat/pgdsat -D /var/lib/postgresql/14/main -V 14 --no-pg-version-check -f html -o /tmp/pgdsat-antes.html
# Genera la versión texto para contar resultados en la terminal
sudo -u postgres perl -I /opt/pgdsat/lib /opt/pgdsat/pgdsat -D /var/lib/postgresql/14/main -V 14 --no-pg-version-check -f text -o /tmp/pgdsat-antes.txt
# Copia ambos reportes a tus evidencias
sudo cp /tmp/pgdsat-antes.html /tmp/pgdsat-antes.txt /home/brian/evidencias/
# Te devuelve la propiedad de los archivos copiados
sudo chown brian:brian /home/brian/evidencias/pgdsat-antes.*
# Cuenta controles aprobados y fallidos
grep -c "=> SUCCESS" /home/brian/evidencias/pgdsat-antes.txt ; grep -c "=> FAILURE" /home/brian/evidencias/pgdsat-antes.txt
# Lista los controles fallidos
grep "=> FAILURE" /home/brian/evidencias/pgdsat-antes.txt
```

> El aviso `grep: /etc/shadow: Permission denied` es normal: pgDSAT intenta revisar si `postgres` tiene shell interactiva.

### 2.3 Redis — auditor de 10 controles

```bash
# Ejecuta el auditor de Redis (config efectiva + prueba de conexión sin clave + proceso + permisos + ufw)
sudo bash /home/brian/auditar-redis.sh | tee /home/brian/evidencias/redis-antes.txt
```

**Referencia (VM de prueba, después del sabotaje):** MySQL **0/20** · pgDSAT **34 FAIL** · Redis **3/10**.

---

## Lab 3 · Hardening (50 min)

> **Snapshot ahora** ("antes-hardening-bd"). Después de cada reinicio de servicio revisa que siga arriba;
> si no arranca, el error está en el último archivo que tocaste.

### Regla de oro de los archivos `zz-*` y `zzz-*`

MySQL lee `/etc/mysql/mysql.conf.d/*.cnf` y PostgreSQL lee `conf.d/*.conf` **en orden alfabético; el último valor gana**.
El sabotaje vive en `zz-lab-inseguro`; tu hardening irá en **`zzz-hardening`** para ganar siempre.
En Redis el orden lo dan las líneas `include` al final de `redis.conf`.

---

### 3A · MySQL (20 min)

#### 3A.1 Eliminar lo que sobra (CIS 7 · BB-LIN-SEG-02)

```bash
# El usuario anónimo deja entrar con cualquier nombre: se elimina
sudo mysql -e "DROP USER IF EXISTS ''@'%';"
# root solo debe administrar desde el propio servidor (auth_socket con sudo): se elimina root remoto
sudo mysql -e "DROP USER IF EXISTS 'root'@'%';"
# Las cuentas de personas que ya no trabajan se eliminan (en producción: primero ACCOUNT LOCK y luego DROP)
sudo mysql -e "DROP USER IF EXISTS 'exempleado'@'%';"
# La base 'test' es accesible para todos por defecto: se elimina
sudo mysql -e "DROP DATABASE IF EXISTS test;"
```

#### 3A.2 Política de contraseñas

```bash
# Instala el componente que rechaza contraseñas débiles
sudo mysql -e "INSTALL COMPONENT 'file://component_validate_password';"
# Longitud mínima 12; SET PERSIST guarda el valor en mysqld-auto.cnf y sobrevive reinicios
sudo mysql -e "SET PERSIST validate_password.length = 12;"
# MEDIUM exige mayúscula, minúscula, número y símbolo
sudo mysql -e "SET PERSIST validate_password.policy = 'MEDIUM';"
# Las contraseñas vencen a los 90 días (CIS pide 365 o menos)
sudo mysql -e "SET PERSIST default_password_lifetime = 90;"
# No se pueden repetir las últimas 5 contraseñas ni reutilizar una en 365 días
sudo mysql -e "SET PERSIST password_history = 5; SET PERSIST password_reuse_interval = 365;"
# Prueba: esta contraseña débil debe ser rechazada (ERROR 1819)
sudo mysql -e "CREATE USER 'prueba'@'localhost' IDENTIFIED BY '123456';"
```

#### 3A.3 Cuentas con mínimo privilegio

```bash
# La app ya no entra desde cualquier IP: solo desde el servidor de aplicación (Kali)
sudo mysql -e "RENAME USER 'app'@'%' TO 'app'@'IP_KALI';"
# Le quitas TODO (incluidos FILE, SUPER y GRANT OPTION)
sudo mysql -e "REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'app'@'IP_KALI';"
# Le das solo lo que la aplicación necesita y solo sobre su base
sudo mysql -e "GRANT SELECT, INSERT, UPDATE ON burgerbank.* TO 'app'@'IP_KALI';"
# Plugin moderno, clave fuerte, TLS obligatorio y bloqueo de 1 día tras 4 intentos fallidos
sudo mysql -e "ALTER USER 'app'@'IP_KALI' IDENTIFIED WITH caching_sha2_password BY 'App#Burger2026!' REQUIRE SSL FAILED_LOGIN_ATTEMPTS 4 PASSWORD_LOCK_TIME 1;"
# Reportes: mismo tratamiento (ya solo tenía SELECT sobre burgerbank)
sudo mysql -e "RENAME USER 'reportes'@'%' TO 'reportes'@'IP_KALI';"
# Le pones contraseña, TLS y bloqueo por intentos
sudo mysql -e "ALTER USER 'reportes'@'IP_KALI' IDENTIFIED BY 'Rep#Burger2026!' REQUIRE SSL FAILED_LOGIN_ATTEMPTS 4 PASSWORD_LOCK_TIME 1;"
# Verifica: la app ya no tiene privilegios globales
sudo mysql -e "SHOW GRANTS FOR 'app'@'IP_KALI';"
```

#### 3A.4 Configuración del servidor (red, TLS, archivos, logs, anti fuerza bruta)

```bash
# Crea tu archivo de hardening (reemplaza IP_UBUNTU antes de pegar)
sudo tee /etc/mysql/mysql.conf.d/zzz-hardening.cnf > /dev/null <<'EOF'
[mysqld]
# Red: solo localhost y la IP de la LAN, nunca 0.0.0.0
bind-address = 127.0.0.1,IP_UBUNTU
# Apaga el protocolo X (puerto 33060) que nadie usa
mysqlx = OFF
# Archivos: sin carga desde el cliente y FILE limitado a una carpeta dedicada
local_infile = OFF
secure_file_priv = /var/lib/mysql-files
# Cifrado: toda conexión TCP debe usar TLS 1.2 o 1.3
require_secure_transport = ON
tls_version = TLSv1.2,TLSv1.3
# Logs: sin log general ni contraseñas en claro; el error log registra accesos denegados
general_log = OFF
log_raw = OFF
log_error_verbosity = 3
# Anti fuerza bruta: desde el 3er intento fallido, cada intento espera 2 s más
plugin-load-add = connection_control.so
connection_control_failed_connections_threshold = 3
connection_control_min_connection_delay = 2000
EOF
# MySQL corre como usuario mysql: el archivo debe ser legible (644) y solo editable por root
sudo chmod 644 /etc/mysql/mysql.conf.d/zzz-hardening.cnf
# Reinicia MySQL para aplicar la configuración
sudo systemctl restart mysql
# Confirma que arrancó (si no, revisa: sudo tail -20 /var/log/mysql/error.log)
sudo systemctl is-active mysql
```

#### 3A.5 Limpieza del sistema operativo

```bash
# El log general tenía contraseñas en texto plano: se elimina
sudo rm -f /var/log/mysql/general.log
# El historial del cliente mysql guarda todo lo que escribes (incluidas claves): se anula
sudo ln -sf /dev/null /root/.mysql_history
# Lo mismo para tu usuario
ln -sf /dev/null /home/brian/.mysql_history
```

#### 3A.6 Firewall: la BD solo para quien la necesita

```bash
# Quitas las reglas abiertas a cualquier origen
sudo ufw delete allow 3306/tcp ; sudo ufw delete allow 33060/tcp
# Permites MySQL solo desde el servidor de aplicación
sudo ufw allow from IP_KALI to any port 3306 proto tcp
```

#### 3A.7 Verificación rápida

```bash
# Ya no escucha en 0.0.0.0 ni en 33060
sudo ss -ltnp | grep mysqld
# Re-ejecuta el auditor (objetivo: 20/20)
sudo mysql -t < /home/brian/auditar-mysql.sql
```

---

### 3B · PostgreSQL (20 min)

#### 3B.1 Configuración del servidor

```bash
# Trabaja desde /tmp: los comandos 'sudo -u postgres' no pueden entrar a tu home
cd /tmp
# Crea el archivo de hardening en conf.d (reemplaza IP_UBUNTU antes de pegar)
sudo tee /etc/postgresql/14/main/conf.d/zzz-hardening.conf > /dev/null <<'EOF'
# Red: solo localhost y la IP de la LAN
listen_addresses = 'localhost,IP_UBUNTU'
# Cifrado: TLS activo (Ubuntu trae un certificado autofirmado) y solo TLS 1.3
ssl = on
ssl_min_protocol_version = 'TLSv1.3'
# Contraseñas con SCRAM-SHA-256 en lugar de md5
password_encryption = 'scram-sha-256'
# Autenticación: 30 s para autenticarse y 2 s de castigo por cada intento fallido
authentication_timeout = '30s'
shared_preload_libraries = 'auth_delay,passwordcheck,pgaudit'
auth_delay.milliseconds = '2000'
# Auditoría: pgaudit registra cambios de roles y de estructura (DDL)
pgaudit.log = 'role,ddl'
# Logs: colector propio fuera de PGDATA, conexiones, desconexiones y DDL
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d.log'
log_truncate_on_rotation = on
log_connections = on
log_disconnections = on
log_line_prefix = '%m [%p] db=%d,user=%u,app=%a,client=%h '
log_statement = 'ddl'
log_error_verbosity = 'verbose'
log_timezone = 'UTC'
EOF
# PostgreSQL lee su configuración como usuario postgres
sudo chown postgres:postgres /etc/postgresql/14/main/conf.d/zzz-hardening.conf
# Permisos 644: legible por el servicio, editable solo por el dueño
sudo chmod 644 /etc/postgresql/14/main/conf.d/zzz-hardening.conf
```

#### 3B.2 pg_hba.conf: quién entra, a qué base, desde dónde y cómo

```bash
# Respaldo antes de tocar el archivo más sensible de PostgreSQL
sudo cp /etc/postgresql/14/main/pg_hba.conf /home/brian/evidencias/pg_hba.conf.antes
# Borra el bloque del sabotaje (trust y md5 desde 0.0.0.0/0)
sudo sed -i '/LAB INSEGURO/,/fin LAB INSEGURO/d' /etc/postgresql/14/main/pg_hba.conf
# Inserta al inicio: app y reportes solo desde Kali, solo con TLS y SCRAM (reemplaza IP_KALI)
sudo sed -i '1i hostssl   burgerbank  app       IP_KALI/32  scram-sha-256' /etc/postgresql/14/main/pg_hba.conf
# Segunda línea permitida, también con TLS obligatorio
sudo sed -i '2i hostssl   burgerbank  reportes  IP_KALI/32  scram-sha-256' /etc/postgresql/14/main/pg_hba.conf
# Cualquier conexión remota SIN cifrar se rechaza explícitamente
sudo sed -i '3i hostnossl all         all       0.0.0.0/0    reject' /etc/postgresql/14/main/pg_hba.conf
# Revisa cómo quedó el inicio del archivo
sudo head -5 /etc/postgresql/14/main/pg_hba.conf
# Reinicia (shared_preload_libraries y listen_addresses requieren reinicio, no basta reload)
sudo systemctl restart postgresql
# Confirma que arrancó (si no: sudo tail -20 /var/log/postgresql/postgresql-14-main.log)
sudo systemctl is-active postgresql
```

#### 3B.3 Roles y privilegios (mínimo privilegio, incluso por columna)

```bash
# app deja de ser superusuario, tiene tope de conexiones y nueva clave (ahora se guarda en SCRAM)
sudo -u postgres psql -c "ALTER ROLE app NOSUPERUSER CONNECTION LIMIT 20 PASSWORD 'App#Burger2026!';"
# reportes pierde el poder de leer archivos del servidor
sudo -u postgres psql -c "REVOKE pg_read_server_files FROM reportes;"
# reportes con tope de conexiones y clave nueva en SCRAM
sudo -u postgres psql -c "ALTER ROLE reportes CONNECTION LIMIT 5 PASSWORD 'Rep#Burger2026!';"
# La cuenta del ex empleado se elimina
sudo -u postgres psql -c "DROP ROLE IF EXISTS exempleado;"
# postgres sin contraseña: solo entra localmente con 'peer' (sudo -u postgres)
sudo -u postgres psql -c "ALTER ROLE postgres PASSWORD NULL;"
# Nadie se conecta a burgerbank por defecto...
sudo -u postgres psql -c "REVOKE ALL ON DATABASE burgerbank FROM PUBLIC;"
# ...salvo las dos cuentas que lo necesitan
sudo -u postgres psql -c "GRANT CONNECT ON DATABASE burgerbank TO app, reportes;"
# Quitas los permisos que el sabotaje dio a todos sobre la tabla
sudo -u postgres psql -d burgerbank -c "REVOKE ALL ON clientes FROM PUBLIC;"
# La app lee y escribe clientes (sin DELETE ni DROP)
sudo -u postgres psql -d burgerbank -c "GRANT SELECT, INSERT, UPDATE ON clientes TO app; GRANT USAGE ON SEQUENCE clientes_id_seq TO app;"
# Reportes ve SOLO estas columnas: nada de DNI ni tarjeta
sudo -u postgres psql -d burgerbank -c "GRANT SELECT (id, nombre, saldo) ON clientes TO reportes;"
# Activa la extensión de auditoría en la base
sudo -u postgres psql -d burgerbank -c "CREATE EXTENSION IF NOT EXISTS pgaudit;"
# Esquema public cerrado para PUBLIC en las tres bases (CIS 4.10)
for db in postgres template1 burgerbank; do sudo -u postgres psql -d $db -c "REVOKE ALL ON SCHEMA public FROM PUBLIC;"; done
# Solo app y reportes pueden usar el esquema public de burgerbank
sudo -u postgres psql -d burgerbank -c "GRANT USAGE ON SCHEMA public TO app, reportes;"
```

#### 3B.4 Firewall y verificación

```bash
# Quitas la regla abierta y permites PostgreSQL solo desde Kali
sudo ufw delete allow 5432/tcp ; sudo ufw allow from IP_KALI to any port 5432 proto tcp
# Ya no escucha en 0.0.0.0
sudo ss -ltnp | grep 5432
# Confirma valores clave en caliente
sudo -u postgres psql -c "SHOW ssl;" -c "SHOW password_encryption;" -c "SHOW auth_delay.milliseconds;"
# Todas las claves deben empezar con SCRAM-SHA-256
sudo -u postgres psql -c "SELECT rolname, left(rolpassword,13) AS formato FROM pg_authid WHERE rolpassword IS NOT NULL;"
```

---

### 3C · Redis (10 min)

#### 3C.1 Generar hashes de contraseñas (no guardarlas en claro)

```bash
# Calcula el SHA-256 de la clave del administrador (copia el resultado)
echo -n 'Admin#Redis2026!' | sha256sum
# Calcula el SHA-256 de la clave de la aplicación (copia el resultado)
echo -n 'App#Redis2026!' | sha256sum
```

#### 3C.2 Configuración de hardening

```bash
# Crea el archivo (reemplaza IP_UBUNTU, HASH_ADMIN y HASH_APP antes de pegar)
sudo tee /etc/redis/zzz-hardening.conf > /dev/null <<'EOF'
# Red: solo localhost y la IP de la LAN; modo protegido activo
bind 127.0.0.1 IP_UBUNTU
protected-mode yes
# Comandos destructivos anulados y CONFIG renombrado (solo el admin conoce el nombre)
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command DEBUG ""
rename-command CONFIG "CONFIG_bb2026"
# ACL: 'default' apagado; admin con todo; app solo lee/escribe sesiones
user default off
user admin on #HASH_ADMIN ~* +@all
user app on #HASH_APP ~sesion:* -@all +get +set +del +expire +ttl +@connection
EOF
# Redis corre como usuario redis: debe poder leer el archivo, pero nadie más
sudo chown redis:redis /etc/redis/zzz-hardening.conf
# 640: dueño lee/escribe, grupo lee, otros nada
sudo chmod 640 /etc/redis/zzz-hardening.conf
# Agrega el include al final de redis.conf (va después del sabotaje, así que gana)
echo 'include /etc/redis/zzz-hardening.conf' | sudo tee -a /etc/redis/redis.conf
# Reinicia Redis
sudo systemctl restart redis-server
# Confirma que arrancó (si no: sudo tail -20 /var/log/redis/redis-server.log)
sudo systemctl is-active redis-server
```

#### 3C.3 Firewall y verificación

```bash
# Quitas la regla abierta y permites Redis solo desde Kali
sudo ufw delete allow 6379/tcp ; sudo ufw allow from IP_KALI to any port 6379 proto tcp
# Sin credenciales: debe responder NOAUTH
redis-cli PING
# Con la cuenta app (--askpass pide la clave sin dejarla en el historial)
redis-cli --user app --askpass GET sesion:ana
# La app NO debe poder leer llaves fuera de sesion:* (NOPERM)
redis-cli --user app --askpass GET config:api_pagos
# FLUSHALL ya no existe (ERR unknown command)
redis-cli --user admin --askpass FLUSHALL
```

---

## Lab 4 · Medir DESPUÉS y comparar (10 min)

```bash
# MySQL después
sudo mysql -t < /home/brian/auditar-mysql.sql | tee /home/brian/evidencias/mysql-despues.txt
# Redis después
sudo bash /home/brian/auditar-redis.sh | tee /home/brian/evidencias/redis-despues.txt
# Te ubicas en /tmp para ejecutar pgDSAT como postgres
cd /tmp
# PostgreSQL después (HTML para leer, texto para contar)
sudo -u postgres perl -I /opt/pgdsat/lib /opt/pgdsat/pgdsat -D /var/lib/postgresql/14/main -V 14 --no-pg-version-check -f html -o /tmp/pgdsat-despues.html
# Versión texto del reporte "después"
sudo -u postgres perl -I /opt/pgdsat/lib /opt/pgdsat/pgdsat -D /var/lib/postgresql/14/main -V 14 --no-pg-version-check -f text -o /tmp/pgdsat-despues.txt
# Copia los reportes a tus evidencias y te devuelve la propiedad
sudo cp /tmp/pgdsat-despues.* /home/brian/evidencias/ ; sudo chown brian:brian /home/brian/evidencias/pgdsat-despues.*
# Cuenta fallidos antes y después
grep -c "=> FAILURE" /home/brian/evidencias/pgdsat-antes.txt /home/brian/evidencias/pgdsat-despues.txt
# Muestra qué controles cambiaron de estado entre antes y después
diff <(grep "=> " /home/brian/evidencias/pgdsat-antes.txt) <(grep "=> " /home/brian/evidencias/pgdsat-despues.txt)
```

**Referencia (VM de prueba):**

| Motor | Herramienta | Antes | Después |
|---|---|---|---|
| MySQL 8.0 | auditar-mysql.sql (20) | 0 % | **100 %** |
| PostgreSQL 14 | pgDSAT (FAIL) | 34 | **20** |
| Redis 6.0 | auditar-redis.sh (10) | 30 % | **100 %** (90 % si ufw está inactivo) |

### ¿Por qué pgDSAT sigue con ~20 FAIL? (para discutir)

| Control | Por qué sigue en FAIL | Qué haría una empresa |
|---|---|---|
| 1.1.1 PGDG · 1.5 versión | Usamos el paquete de Ubuntu, no el del proyecto PostgreSQL | Decisión documentada: Ubuntu da parches de seguridad |
| 1.4.3 checksums · 1.4.4 WAL en otra partición | Se definen al crear el clúster / al diseñar discos | `pg_checksums --enable` con el servicio detenido; diseño de particiones |
| 2.1 umask | Mide el umask del usuario que ejecuta pgDSAT | Ajustar el entorno del usuario postgres |
| 5.7 auth delay | **Falso positivo**: la herramienta consulta también `credcheck` y falla la consulta | Evidencia: `SHOW auth_delay.milliseconds;` = 2s |
| 5.9 rango 0.0.0.0/0 | **Falso positivo**: es nuestra regla `reject` | Documentar la excepción |
| 6.8 passphrase del certificado | El certificado autofirmado no tiene frase | Certificado de la CA interna + `ssl_passphrase_command` |
| 7.x replicación · 8.2 pgBackRest | No hay réplica ni respaldo configurado en el lab | Fuera del alcance de hoy (Clase 7: nube y respaldos) |

> **Lección:** una herramienta de cumplimiento no reemplaza el criterio. Cada FAIL se **corrige, se acepta como riesgo** o se **marca como falso positivo con evidencia**.

---

## Lab 5 · Vista desde Kali DESPUÉS (10 min)

```bash
# 🐉 En Kali: ¿qué puertos siguen visibles? (33060 debe desaparecer)
nmap -sV -p 3306,33060,5432,6379 IP_UBUNTU
# El usuario anónimo ya no existe
mysql -h IP_UBUNTU -u cualquiera --skip-ssl -e "SELECT 1;"
# Sin TLS la app es rechazada (require_secure_transport)
mysql -h IP_UBUNTU -u app -p --skip-ssl -e "SELECT 1;"
# Con TLS sí entra (si tu cliente valida el certificado autofirmado, agrega --skip-ssl-verify-server-cert)
mysql -h IP_UBUNTU -u app -p --ssl -e "SELECT nombre FROM burgerbank.clientes LIMIT 1; SHOW STATUS LIKE 'Ssl_version';"
# FILE ya no existe para la app: LOAD_FILE devuelve NULL o error
mysql -h IP_UBUNTU -u app -p --ssl -e "SELECT LOAD_FILE('/etc/passwd');"
# postgres remoto sin contraseña: rechazado por pg_hba
psql "host=IP_UBUNTU user=postgres dbname=burgerbank" -c "SELECT 1;"
# app sin TLS: rechazado por la regla hostnossl ... reject
psql "host=IP_UBUNTU user=app dbname=burgerbank sslmode=disable" -c "SELECT 1;"
# reportes con TLS: ve nombres y saldos...
psql "host=IP_UBUNTU user=reportes dbname=burgerbank sslmode=require" -c "SELECT id, nombre, saldo FROM clientes;"
# ...pero NO la tarjeta (permission denied: privilegio por columna)
psql "host=IP_UBUNTU user=reportes dbname=burgerbank sslmode=require" -c "SELECT tarjeta FROM clientes;"
# Redis sin credenciales: NOAUTH
redis-cli -h IP_UBUNTU KEYS '*'
# Enumera las versiones TLS y cifrados que ofrece MySQL (nmap negocia el STARTTLS de MySQL)
nmap -p 3306 --script ssl-enum-ciphers IP_UBUNTU
```

> Si `ssl-enum-ciphers` no muestra nada en 3306, no te preocupes: MySQL negocia TLS **dentro** de su propio protocolo y algunas versiones de nmap no lo manejan.
> La prueba definitiva de TLS es `SHOW STATUS LIKE 'Ssl_version'` (MySQL) o la vista `pg_stat_ssl` (PostgreSQL).

---

## Entrega (5 min)

Sube a tu fork del repositorio, carpeta `entregas/clase-04/<tu-apellido>/`:

1. `evidencias/mysql-antes.txt` y `mysql-despues.txt`
2. `evidencias/pgdsat-antes.html` y `pgdsat-despues.html`
3. `evidencias/redis-antes.txt` y `redis-despues.txt`
4. `respuestas.md` con:
   - Tabla resumen antes/después de los tres motores.
   - Tres FAIL de pgDSAT que **no** corregiste y por qué (corregir / aceptar riesgo / falso positivo).
   - Respuestas a las preguntas de reflexión.

### Preguntas de reflexión

1. ¿Qué tienen en común los hallazgos de MySQL, PostgreSQL y Redis aunque los comandos sean distintos?
2. ¿Por qué `FILE` en MySQL, `pg_read_server_files` en PostgreSQL y `CONFIG SET dir` en Redis son "puentes" hacia el sistema operativo?
3. Si la app necesita leer solo nombre y saldo, ¿cómo lo resolviste en PostgreSQL? ¿Cómo lo harías en MySQL? (pista: `GRANT SELECT (col1, col2)` o una vista)
4. ¿Qué gana la empresa al poner TLS **y** firewall por IP de origen si ya tiene contraseñas fuertes?
5. ¿Qué FAIL de pgDSAT aceptarías como riesgo en BurgerBank y quién debería firmar esa excepción?

---

## Lab 6 · OPCIONAL / TAREA — Base de datos vectorial: Qdrant (20 min)

**Contexto:** BurgerBank lanzó un chatbot con IA. Para "recordar" conversaciones usa una **base vectorial**:
cada texto se convierte en un vector (embedding) y se guarda **junto con el texto original** (payload).
Muchos tutoriales la despliegan **como root, escuchando en 0.0.0.0, sin API key y con telemetría activa**. Hagamos eso y luego arreglémoslo.

### 6.1 Despliegue "de tutorial" (inseguro)

```bash
# Descarga el paquete oficial de Qdrant desde GitHub (salida 443 permitida en tu ufw)
curl -LO https://github.com/qdrant/qdrant/releases/download/v1.20.0/qdrant_1.20.0-1_amd64.deb
# Instala el paquete local (binario en /usr/bin/qdrant, config en /etc/qdrant)
sudo apt install -y ./qdrant_1.20.0-1_amd64.deb
# Crea un servicio systemd que corre como root (el error típico de los tutoriales)
sudo tee /etc/systemd/system/qdrant.service > /dev/null <<'EOF'
[Unit]
Description=Qdrant (despliegue inseguro de tutorial)
After=network.target
[Service]
WorkingDirectory=/var/lib/qdrant
ExecStart=/usr/bin/qdrant --config-path /etc/qdrant/config.yaml
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
# Recarga systemd, habilita y arranca el servicio
sudo systemctl daemon-reload ; sudo systemctl enable --now qdrant
# Abre el puerto a todo el mundo (otro error típico)
sudo ufw allow 6333/tcp
# Carga las "conversaciones" del chatbot
bash /home/brian/cargar-vectores.sh
# Observa: corre como root y escucha en todas las interfaces (6333 HTTP, 6334 gRPC)
ps -o user,cmd -C qdrant ; sudo ss -ltnp | grep qdrant
```

```bash
# 🐉 En Kali: lista las colecciones sin credenciales
curl -s http://IP_UBUNTU:6333/collections
# Lee el contenido completo: DNI, tarjetas, correos... (el payload viaja con el vector)
curl -s -X POST http://IP_UBUNTU:6333/collections/soporte_chatbot/points/scroll -H 'Content-Type: application/json' -d '{"limit":10,"with_payload":true}'
# Cualquiera podría borrar la memoria del chatbot (NO lo ejecutes, solo léelo):
# curl -X DELETE http://IP_UBUNTU:6333/collections/soporte_chatbot
```

> También puedes abrir `http://IP_UBUNTU:6333/dashboard` en el navegador de Kali: consola web completa, sin login.

### 6.2 Hardening de Qdrant

```bash
# Usuario de sistema dedicado, sin shell ni login
sudo useradd --system --home-dir /var/lib/qdrant --shell /usr/sbin/nologin qdrant
# Los datos pasan a ser del usuario qdrant
sudo chown -R qdrant:qdrant /var/lib/qdrant
# Configuración segura (reemplaza IP_UBUNTU; en la vida real las claves van en un gestor de secretos)
sudo tee /etc/qdrant/config.yaml > /dev/null <<'EOF'
storage:
  storage_path: /var/lib/qdrant/storage
  snapshots_path: /var/lib/qdrant/snapshots
service:
  static_content_dir: /var/lib/qdrant/static
  # Escucha solo en la IP de la LAN (aplica a HTTP 6333 y gRPC 6334)
  host: IP_UBUNTU
  # Clave de administración (lectura y escritura)
  api_key: Admin-Qdrant-BB-2026
  # Clave de solo lectura para el chatbot
  read_only_api_key: Lectura-Qdrant-BB-2026
# Los datos de uso no salen de la empresa
telemetry_disabled: true
EOF
# La config contiene claves: root es dueño, el grupo qdrant solo lee, otros nada
sudo chown root:qdrant /etc/qdrant/config.yaml ; sudo chmod 640 /etc/qdrant/config.yaml
# Servicio endurecido: usuario propio, sin escalar privilegios, sistema de archivos de solo lectura
sudo tee /etc/systemd/system/qdrant.service > /dev/null <<'EOF'
[Unit]
Description=Qdrant (endurecido)
After=network.target
[Service]
User=qdrant
Group=qdrant
WorkingDirectory=/var/lib/qdrant
ExecStart=/usr/bin/qdrant --config-path /etc/qdrant/config.yaml
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/qdrant
[Install]
WantedBy=multi-user.target
EOF
# Aplica el nuevo servicio
sudo systemctl daemon-reload ; sudo systemctl restart qdrant ; sudo systemctl is-active qdrant
# Firewall: solo Kali (el servidor de la app) llega a Qdrant
sudo ufw delete allow 6333/tcp ; sudo ufw allow from IP_KALI to any port 6333 proto tcp
# Verifica: usuario qdrant y escucha solo en IP_UBUNTU
ps -o user,cmd -C qdrant ; sudo ss -ltnp | grep qdrant
# systemd califica qué tan aislado quedó el servicio (menor = mejor; compáralo con mysql.service)
systemd-analyze security qdrant.service | tail -1
```

```bash
# 🐉 En Kali: sin clave → 401 Unauthorized
curl -s -o /dev/null -w "%{http_code}\n" http://IP_UBUNTU:6333/collections
# Con la clave de solo lectura sí lista...
curl -s -H 'api-key: Lectura-Qdrant-BB-2026' http://IP_UBUNTU:6333/collections
# ...pero no puede borrar (403 Forbidden)
curl -s -X DELETE -H 'api-key: Lectura-Qdrant-BB-2026' http://IP_UBUNTU:6333/collections/soporte_chatbot
```

### 6.3 Para reflexionar (bases vectoriales)

- El vector "no es el dato"... pero el **payload sí lo es**. ¿Qué datos personales del chatbot no deberían guardarse? (Ley 29733)
- Un embedding puede **invertirse** parcialmente para reconstruir el texto original: trátalo como dato sensible.
- **Envenenamiento:** si alguien puede escribir en la colección, puede meter "respuestas" falsas que el chatbot repetirá.
- ¿Qué gana BurgerBank separando claves de lectura (chatbot) y de escritura (proceso de carga)?

---

## Errores comunes

| Síntoma | Causa | Solución |
|---|---|---|
| MySQL no arranca tras 3A.4 | Error de tipeo en `zzz-hardening.cnf` o IP inexistente en `bind-address` | `sudo tail -20 /var/log/mysql/error.log`; corrige y reinicia |
| `ERROR 1819` al cambiar claves | validate_password rechaza la clave | Usa 12+ caracteres con mayúscula, número y símbolo |
| `ERROR 3159 ... insecure transport` o `ERROR 2061 ... requires secure connection` desde Kali | `require_secure_transport = ON` / cuenta con `REQUIRE SSL` | Conéctate con `--ssl` (MariaDB) o `--ssl-mode=REQUIRED` (cliente MySQL) |
| Kali: `self-signed certificate` / `TLS/SSL error` | El cliente MariaDB nuevo valida el certificado autofirmado de MySQL | Agrega `--skip-ssl-verify-server-cert` |
| `ERROR 3955 ... locked` / cuenta bloqueada | 4 intentos fallidos con FAILED_LOGIN_ATTEMPTS | `sudo mysql -e "ALTER USER 'app'@'IP_KALI' ACCOUNT UNLOCK;"` |
| Login MySQL muy lento tras varios errores | connection_control agrega 2 s por intento | Es lo esperado: anti fuerza bruta |
| PostgreSQL no arranca tras 3B | Falta `postgresql-14-pgaudit` o error en el `.conf` | `sudo apt install -y postgresql-14-pgaudit`; revisa `/var/log/postgresql/` |
| `pg_hba.conf rejects connection ... no encryption` | Regla `hostnossl ... reject` | Usa `sslmode=require` en psql |
| `no pg_hba.conf entry for host` | Kali tiene otra IP o la regla está mal escrita | `ip -4 addr` en Kali; corrige la línea `hostssl` y `sudo systemctl reload postgresql` |
| `could not change directory to "/home/brian"` | El usuario postgres no puede entrar a tu home (750) | Haz `cd /tmp` antes de `sudo -u postgres ...` |
| pgDSAT: `Can't locate PGDSAT.pm` | Clonaste en /home/brian o falta el `chown` | Clónalo en `/opt/pgdsat` y `sudo chown -R postgres:postgres /opt/pgdsat` |
| Redis no arranca tras 3C | No reemplazaste `HASH_*` o el archivo no es legible para redis | Revisa `/var/log/redis/redis-server.log`, `chown redis:redis`, `chmod 640` |
| `redis-cli` dice NOAUTH en todo | Es lo esperado: `user default off` | Usa `--user admin --askpass` |
| `ERR unknown command CONFIG` | CONFIG fue renombrado | Usa `CONFIG_bb2026` con el usuario admin |
| Después de tocar archivos, el servicio no los lee | La VM de C3 tiene `umask 027`: los archivos nuevos quedan `root:root 640` | Siempre `chown`/`chmod` después de crear configs (ya está en los comandos) |
| Qdrant no arranca como usuario qdrant | Faltó `chown -R qdrant:qdrant /var/lib/qdrant` o la config no es legible | Repite el `chown`; `sudo journalctl -u qdrant -n 20` |
| Perdí el acceso / rompí todo | — | Vuelve al snapshot "antes-hardening-bd" |

---

### Referencias

- CIS Benchmarks: Oracle MySQL Community Server 8.0 y PostgreSQL (cisecurity.org/cis-benchmarks).
- pgDSAT — HexaCluster: github.com/HexaCluster/pgdsat
- Redis — Security y ACL: redis.io/docs/latest/operate/oss_and_stack/management/security/
- Qdrant — Security: qdrant.tech/documentation/guides/security/
- Lineamiento interno **BB-LIN-SEG-02 Bases de Datos** (plantillas BurgerBank del curso).
