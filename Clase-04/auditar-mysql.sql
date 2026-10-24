-- =============================================================================
--  SENATI · Módulo 04 · Clase 4 — auditar-mysql.sql
--  Auditor de SOLO LECTURA para MySQL 8.0: 20 controles inspirados en el
--  CIS MySQL 8.0 Benchmark (secciones 4 General, 5 Permisos, 6 Logs,
--  7 Autenticación, 8 Red) y en el lineamiento BB-LIN-SEG-02 de BurgerBank.
--
--  Uso:  sudo mysql -t < /home/brian/auditar-mysql.sql
--  No modifica nada: solo consulta tablas del sistema y variables.
-- =============================================================================

-- Las cuentas de sistema (root, debian-sys-maint, mysql.*) no se evalúan en
-- MY-06 y MY-07: root ya se controla en MY-02 y las demás vienen bloqueadas.

SELECT id AS ID, control AS Control, actual AS Actual, esperado AS Esperado,
       IF(ok, 'PASS', 'FAIL') AS Resultado
FROM (
  -- ---------------- CUENTAS (CIS 7 / 5) ----------------
  SELECT 'MY-01' id, 'Usuarios anonimos' control,
         CAST(COUNT(*) AS CHAR) actual, '0' esperado, COUNT(*)=0 ok
  FROM mysql.user WHERE user=''
  UNION ALL
  SELECT 'MY-02','root accesible desde otro host',
         CAST(COUNT(*) AS CHAR),'0', COUNT(*)=0
  FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')
  UNION ALL
  SELECT 'MY-03','Cuentas sin contrasena',
         CAST(COUNT(*) AS CHAR),'0', COUNT(*)=0
  FROM mysql.user WHERE authentication_string='' AND plugin NOT IN ('auth_socket')
       AND account_locked='N'
  UNION ALL
  SELECT 'MY-04','Cuentas con plugin debil mysql_native_password',
         CAST(COUNT(*) AS CHAR),'0', COUNT(*)=0
  FROM mysql.user WHERE plugin='mysql_native_password' AND account_locked='N'
  UNION ALL
  SELECT 'MY-05','Cuentas con host comodin %',
         CAST(COUNT(*) AS CHAR),'0', COUNT(*)=0
  FROM mysql.user WHERE host='%'
  UNION ALL
  SELECT 'MY-06','Cuentas no-root con FILE/SUPER/PROCESS/SHUTDOWN/CREATE USER/GRANT',
         IFNULL(GROUP_CONCAT(CONCAT(user,'@',host) SEPARATOR ' '),'ninguna'),'ninguna', COUNT(*)=0
  FROM mysql.user
  WHERE user NOT IN ('root','debian-sys-maint','mysql.sys','mysql.session','mysql.infoschema')
    AND (File_priv='Y' OR Super_priv='Y' OR Process_priv='Y' OR Shutdown_priv='Y'
         OR Create_user_priv='Y' OR Grant_priv='Y')
  UNION ALL
  SELECT 'MY-07','Cuentas sin bloqueo por intentos fallidos',
         IFNULL(GROUP_CONCAT(CONCAT(user,'@',host) SEPARATOR ' '),'ninguna'),'ninguna', COUNT(*)=0
  FROM mysql.user
  WHERE user NOT IN ('root','debian-sys-maint','mysql.sys','mysql.session','mysql.infoschema')
    AND account_locked='N'
    AND IFNULL(JSON_EXTRACT(User_attributes,'$.Password_locking.failed_login_attempts'),0) = 0
  UNION ALL
  SELECT 'MY-08','Base de datos de prueba "test"',
         CAST(COUNT(*) AS CHAR),'0', COUNT(*)=0
  FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='test'
  -- ---------------- CONTRASEÑAS (CIS 7) ----------------
  UNION ALL
  SELECT 'MY-09','Componente validate_password instalado',
         IF(COUNT(*)>0,'si','no'),'si', COUNT(*)>0
  FROM mysql.component WHERE component_urn LIKE '%validate_password%'
  UNION ALL
  SELECT 'MY-10','validate_password.length',
         IFNULL(MAX(VARIABLE_VALUE),'(no instalado)'),'>= 12',
         IFNULL(MAX(VARIABLE_VALUE)+0,0) >= 12
  FROM performance_schema.global_variables WHERE VARIABLE_NAME='validate_password.length'
  UNION ALL
  SELECT 'MY-11','default_password_lifetime (dias)',
         MAX(VARIABLE_VALUE),'1 a 365', MAX(VARIABLE_VALUE)+0 BETWEEN 1 AND 365
  FROM performance_schema.global_variables WHERE VARIABLE_NAME='default_password_lifetime'
  UNION ALL
  SELECT 'MY-12','password_history',
         MAX(VARIABLE_VALUE),'>= 5', MAX(VARIABLE_VALUE)+0 >= 5
  FROM performance_schema.global_variables WHERE VARIABLE_NAME='password_history'
  UNION ALL
  SELECT 'MY-13','Plugin connection_control (retardo anti fuerza bruta)',
         IFNULL(MAX(PLUGIN_STATUS),'no cargado'),'ACTIVE', IFNULL(MAX(PLUGIN_STATUS),'')='ACTIVE'
  FROM information_schema.PLUGINS WHERE PLUGIN_NAME='CONNECTION_CONTROL'
  -- ---------------- RED Y CIFRADO (CIS 8) ----------------
  UNION ALL
  SELECT 'MY-14','bind_address',
         MAX(VARIABLE_VALUE),'no 0.0.0.0 ni *', MAX(VARIABLE_VALUE) NOT IN ('0.0.0.0','*','::')
  FROM performance_schema.global_variables WHERE VARIABLE_NAME='bind_address'
  UNION ALL
  SELECT 'MY-15','Protocolo X (puerto 33060)',
         IFNULL(MAX(PLUGIN_STATUS),'no existe'),'DISABLED', IFNULL(MAX(PLUGIN_STATUS),'DISABLED')<>'ACTIVE'
  FROM information_schema.PLUGINS WHERE PLUGIN_NAME='mysqlx'
  UNION ALL
  SELECT 'MY-16','require_secure_transport (TLS obligatorio)',
         MAX(VARIABLE_VALUE),'ON', MAX(VARIABLE_VALUE)='ON'
  FROM performance_schema.global_variables WHERE VARIABLE_NAME='require_secure_transport'
  -- ---------------- ARCHIVOS DEL SERVIDOR (CIS 4) ----------------
  UNION ALL
  SELECT 'MY-17','local_infile',
         MAX(VARIABLE_VALUE),'OFF', MAX(VARIABLE_VALUE)='OFF'
  FROM performance_schema.global_variables WHERE VARIABLE_NAME='local_infile'
  UNION ALL
  SELECT 'MY-18','secure_file_priv',
         IF(MAX(VARIABLE_VALUE)='','(vacio = cualquier carpeta)',IFNULL(MAX(VARIABLE_VALUE),'NULL')),
         'carpeta dedicada o NULL', IFNULL(MAX(VARIABLE_VALUE),'NULL')<>''
  FROM performance_schema.global_variables WHERE VARIABLE_NAME='secure_file_priv'
  -- ---------------- LOGS (CIS 6) ----------------
  UNION ALL
  SELECT 'MY-19','log_raw (contrasenas en texto plano en logs)',
         MAX(VARIABLE_VALUE),'OFF', MAX(VARIABLE_VALUE)='OFF'
  FROM performance_schema.global_variables WHERE VARIABLE_NAME='log_raw'
  UNION ALL
  SELECT 'MY-20','log_error_verbosity (registra accesos denegados)',
         MAX(VARIABLE_VALUE),'3', MAX(VARIABLE_VALUE)+0 >= 3
  FROM performance_schema.global_variables WHERE VARIABLE_NAME='log_error_verbosity'
) AS auditoria
ORDER BY id;

SELECT SUM(ok) AS PASS, SUM(NOT ok) AS FAIL, COUNT(*) AS Total,
       CONCAT(ROUND(100*SUM(ok)/COUNT(*)),'%') AS Cumplimiento
FROM (
  SELECT COUNT(*)=0 ok FROM mysql.user WHERE user=''
  UNION ALL SELECT COUNT(*)=0 FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')
  UNION ALL SELECT COUNT(*)=0 FROM mysql.user WHERE authentication_string='' AND plugin NOT IN ('auth_socket') AND account_locked='N'
  UNION ALL SELECT COUNT(*)=0 FROM mysql.user WHERE plugin='mysql_native_password' AND account_locked='N'
  UNION ALL SELECT COUNT(*)=0 FROM mysql.user WHERE host='%'
  UNION ALL SELECT COUNT(*)=0 FROM mysql.user
     WHERE user NOT IN ('root','debian-sys-maint','mysql.sys','mysql.session','mysql.infoschema')
       AND (File_priv='Y' OR Super_priv='Y' OR Process_priv='Y' OR Shutdown_priv='Y' OR Create_user_priv='Y' OR Grant_priv='Y')
  UNION ALL SELECT COUNT(*)=0 FROM mysql.user
     WHERE user NOT IN ('root','debian-sys-maint','mysql.sys','mysql.session','mysql.infoschema') AND account_locked='N'
       AND IFNULL(JSON_EXTRACT(User_attributes,'$.Password_locking.failed_login_attempts'),0) = 0
  UNION ALL SELECT COUNT(*)=0 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='test'
  UNION ALL SELECT COUNT(*)>0 FROM mysql.component WHERE component_urn LIKE '%validate_password%'
  UNION ALL SELECT IFNULL(MAX(VARIABLE_VALUE)+0,0) >= 12 FROM performance_schema.global_variables WHERE VARIABLE_NAME='validate_password.length'
  UNION ALL SELECT MAX(VARIABLE_VALUE)+0 BETWEEN 1 AND 365 FROM performance_schema.global_variables WHERE VARIABLE_NAME='default_password_lifetime'
  UNION ALL SELECT MAX(VARIABLE_VALUE)+0 >= 5 FROM performance_schema.global_variables WHERE VARIABLE_NAME='password_history'
  UNION ALL SELECT IFNULL(MAX(PLUGIN_STATUS),'')='ACTIVE' FROM information_schema.PLUGINS WHERE PLUGIN_NAME='CONNECTION_CONTROL'
  UNION ALL SELECT MAX(VARIABLE_VALUE) NOT IN ('0.0.0.0','*','::') FROM performance_schema.global_variables WHERE VARIABLE_NAME='bind_address'
  UNION ALL SELECT IFNULL(MAX(PLUGIN_STATUS),'DISABLED')<>'ACTIVE' FROM information_schema.PLUGINS WHERE PLUGIN_NAME='mysqlx'
  UNION ALL SELECT MAX(VARIABLE_VALUE)='ON' FROM performance_schema.global_variables WHERE VARIABLE_NAME='require_secure_transport'
  UNION ALL SELECT MAX(VARIABLE_VALUE)='OFF' FROM performance_schema.global_variables WHERE VARIABLE_NAME='local_infile'
  UNION ALL SELECT IFNULL(MAX(VARIABLE_VALUE),'NULL')<>'' FROM performance_schema.global_variables WHERE VARIABLE_NAME='secure_file_priv'
  UNION ALL SELECT MAX(VARIABLE_VALUE)='OFF' FROM performance_schema.global_variables WHERE VARIABLE_NAME='log_raw'
  UNION ALL SELECT MAX(VARIABLE_VALUE)+0 >= 3 FROM performance_schema.global_variables WHERE VARIABLE_NAME='log_error_verbosity'
) AS r;
