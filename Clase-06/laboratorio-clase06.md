# Clase 6 · Laboratorio — Hardening de servicios web: Apache, Nginx, microservicios, APIs y web services

**SENATI · Diplomado Gestión de la Ciberseguridad · Módulo 04 "Aseguramiento de los Sistemas"**
**Docente:** Ademir Cuadros · **Fecha:** martes 03/11 · **Práctica en clase:** 2 horas · **Laboratorio completo:** ~3 h (lo que no alcance queda como tarea)

> Ciclo de siempre: **medir → enumerar riesgos → endurecer → re-medir → mirar desde afuera.**
> Hoy lo aplicamos a **todo lo que sirve web** en la misma VM **Ubuntu Server 22.04** de las clases 3 y 4:
>
> - **Parte A · Servidores web clásicos en el host:** Apache y Nginx instalados con `apt`.
> - **Parte B · Microservicios en Docker:** proxy nginx, una **API REST**, un **web service SOAP** y Redis.
>
> Todo pasa en ese único host: los servicios, los escáneres y las pruebas.

---

## Antes de empezar (leer 2 minutos)

- **Una sola máquina:** la VM Ubuntu 22.04 (usuario `brian`). No se usa Kali ni pfSense.
  Si tu usuario no es `brian`, reemplaza `/home/brian/` por tu carpeta en todos los comandos.
- **Snapshot obligatorio** antes del Lab 0: VirtualBox → tu VM → *Instantánea* → `antes-clase06`.
- **Puertos del laboratorio:** Apache **8081/8441**, Nginx **8082/8442**, app Docker **80/443**.
  Así las tres conviven sin chocar.
- **No hay reglas de firewall en este laboratorio.** La protección se hace en los servidores, en Docker y en el código.
- **Todos los comandos de Docker van con `sudo`.** No agregues tu usuario al grupo `docker` (en B3 verás por qué).
- **Memoria:** la VM necesita **2 GB de RAM** o más. Si va lenta, apaga los servicios de la Clase 4:
  `sudo systemctl stop mysql postgresql redis-server` (al final los vuelves a encender con `start`).
- Resultados en **`/home/brian/c6/antes/`** y **`/home/brian/c6/despues/`**.

### Tarea previa (en casa, 20 min, muy recomendada)

Las descargas pesan unos **700 MB**. Haz los pasos **0.3 a 0.6** del Lab 0 antes de clase.

---

## Agenda

| Bloque | En clase (min) | Qué haces | Si vas corto → tarea |
|--------|----------------|-----------|----------------------|
| Lab 0 · Preparación | 10 | Materiales, Docker, Trivy, imágenes | (tarea previa) |
| **Parte A** · Apache y Nginx en el host | 40 | Instalar, medir, endurecer los dos, re-medir | A4 (Nginx) |
| **Parte B** · B1–B2 Levantar y reconocer (web, API REST, SOAP) | 15 | 5 contenedores y pruebas tipo OWASP API | — |
| B3 · Puentes al host | — | Por qué un contenedor mal configurado compromete la VM | todo (tarea) |
| B4 · Medir | 10 | 3 auditores + Trivy | Trivy de imágenes y Docker Bench |
| B5 · Endurecer | 30 | Demonio, imágenes, secretos, código de API/SOAP, nginx, compose | B5.4 (lectura) |
| B6 · Re-medir | 10 | Mismas herramientas y tabla de aceptados | Docker Bench |
| B7 · Cierre y entrega | 5 | Prueba como cliente legítimo, limpieza, PR | — |
| Lab 6 · Opcional | — | WAF ModSecurity, Trivy en CI, SBOM, digest | todo |

---

## Mapa del laboratorio

```
VM Ubuntu 22.04
│
├── PARTE A (servicios del sistema, instalados con apt)
│     Apache  :8081 → :8441 (HTTPS)      /var/www/html
│     Nginx   :8082 → :8442 (HTTPS)      /var/www/nginx-lab
│
└── PARTE B (Docker, proyecto "burgerbank")
      web (nginx) :80/:443 ──/api/──▶ pedidos     (API REST, Flask)  ──▶ cache (Redis)
                          └──/ws/───▶ facturacion (web service SOAP)
      monitor (contenedor "de utilidades" con el socket de Docker)   ← solo en la versión insegura
```

| Servicio | Versión insegura | Versión endurecida |
|----------|------------------|--------------------|
| Apache (host) | Página por defecto, versión visible, listado, `.env`, `/server-status`, solo HTTP | TLS 1.2/1.3, cabeceras, sin listado ni estado, métodos y tamaño limitados, mod_evasive |
| Nginx (host) | Igual + `/nginx_status` | Igual que Apache, con `limit_req` |
| `web` (Docker) | nginx 1.21 como root, solo HTTP | nginx sin privilegios, HTTPS, rate limit, `/ws/` limitado a 16 KB |
| `pedidos` (API REST) | Sin autenticación, BOLA, asignación masiva, CORS `*`, `/api/v0`, `/api/info`, debug | Clave de API por cliente, solo sus pedidos, campos permitidos, tarjeta enmascarada |
| `facturacion` (SOAP) | WSDL público, XXE, sin límites, debug | Clave obligatoria, `defusedxml`, validación, 16 KB máx. |
| `cache` (Redis) | Redis 6.0 sin clave, publicado en 16379 | Redis 7.4 con ACL, red interna |

---

## Teoría mínima de comandos

| Comando | Qué hace |
|---------|----------|
| `curl -I URL` | Muestra solo las cabeceras de la respuesta |
| `curl -k` | Acepta certificados autofirmados (solo laboratorio) |
| `apache2ctl configtest` / `nginx -t` | Revisa la sintaxis antes de reiniciar (nunca reinicies sin esto) |
| `a2enmod` / `a2dismod` / `a2ensite` / `a2dissite` | Activa o desactiva módulos y sitios de Apache |
| `nmap -sV -p PUERTOS localhost` | Identifica qué servicio y versión responde en cada puerto |
| `docker compose up -d --build` | Construye las imágenes y levanta los contenedores |
| `docker inspect <c>` | Muestra la configuración real de un contenedor |
| `trivy image / config / fs` | Escanea imágenes (CVE), Dockerfiles (configuración) y archivos (secretos) |

---

## Lab 0 · Preparación (10 min)

### 0.1 Carpetas de resultados

```bash
# Crea las carpetas para guardar las mediciones de antes y después
mkdir -p /home/brian/c6/antes /home/brian/c6/despues
```

### 0.2 Copiar los materiales de la clase

```bash
# Actualiza tu copia del repositorio del curso
cd /home/brian/senati-m4-aseguramiento && git pull
# Copia la carpeta de la clase a tu home
cp -r /home/brian/senati-m4-aseguramiento/clase-06-servicios-web /home/brian/
# En caso de no aplicar el git pull y hacer el procedimiento manual descargarse la carpeta de github y llevarlo a tu directorio de trabajo (e.g /home/brian/clase6/
# La umask 027 de la Clase 3 deja los archivos sin lectura para "otros"; los servidores web
# (www-data, nginx dentro de Docker) necesitan leerlos: damos lectura, nunca escritura
chmod -R o+rX /home/brian/clase-06-servicios-web
# Revisa la estructura: parte-a-host, parte-b-docker y scripts
ls /home/brian/clase-06-servicios-web /home/brian/clase-06-servicios-web/*/
```

> Sin repositorio: descomprime el zip de la clase en `/home/brian/` y ejecuta el mismo `chmod`.

### 0.3 Instalar Docker desde los repositorios de Ubuntu

```bash
# Actualiza la lista de paquetes
sudo apt update
# Motor de Docker, plugin "docker compose" v2 y buildx (constructor moderno), desde los repositorios de Ubuntu
sudo apt install -y docker.io docker-compose-v2 docker-buildx
# Deja Docker activo y con arranque automático
sudo systemctl enable --now docker
# Versión del cliente y del servidor (deben verse ambas)
sudo docker version --format 'Cliente {{.Client.Version}} · Servidor {{.Server.Version}}'
```

> **Conflicto con la Clase 3:** el hardening dejó `net.ipv4.ip_forward=0` y Docker lo cambia a `1` porque lo necesita.
> Compruébalo con `sysctl net.ipv4.ip_forward`. Se documenta como **excepción aceptada** en B6.

### 0.4 Instalar Trivy (repositorio oficial de Aqua Security)

```bash
# Llave pública del repositorio en el formato de apt
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
# Repositorio de Trivy, verificado con esa llave
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
# La umask 027 deja estos archivos sin lectura para apt: les damos lectura
sudo chmod 644 /usr/share/keyrings/trivy.gpg /etc/apt/sources.list.d/trivy.list
# Instala Trivy y muestra la versión
sudo apt update && sudo apt install -y trivy && trivy --version
```

> **Cadena de suministro, caso real:** en marzo de 2026 se publicaron versiones **maliciosas** de Trivy
> (**v0.69.4**, e imágenes de Docker Hub **v0.69.5 y v0.69.6**) que robaban credenciales (CVE-2026-33634).
> Si tienes una de esas, **detente y avisa al docente**.

### 0.5 Base de datos de Trivy

```bash
# Descarga la base de vulnerabilidades (~80 MB; se guarda en /root/.cache/trivy)
sudo trivy image --download-db-only
```

### 0.6 Imágenes base de la Parte B

```bash
# Versión insegura (viejas a propósito)
sudo docker pull python:3.9-slim-bookworm
sudo docker pull nginx:1.21
sudo docker pull redis:6.0
# Versión endurecida (actuales y mínimas)
sudo docker pull python:3.12-slim
sudo docker pull nginxinc/nginx-unprivileged:stable-alpine
sudo docker pull redis:7.4-alpine
# Compara tamaños
sudo docker images --format 'table {{.Repository}}:{{.Tag}}\t{{.Size}}'
```

**Checkpoint 0:** materiales en `/home/brian/clase-06-servicios-web`, Docker y Trivy funcionando, 6 imágenes.

---

# PARTE A · Servidores web clásicos: Apache y Nginx en el host (40 min)

### A1 · Instalar "como vienen" (5 min)

```bash
# Lee el script: qué instala y qué errores deja a propósito
less /home/brian/clase-06-servicios-web/parte-a-host/preparar-web-host.sh
# Instala Apache (8081) y Nginx (8082) con contenido inseguro
sudo bash /home/brian/clase-06-servicios-web/parte-a-host/preparar-web-host.sh
# Puertos que escuchan ahora
sudo ss -tlnp | grep -E ':(8081|8082) '
```

### A2 · Reconocer y medir "antes" (8 min)

```bash
# Cabeceras: producto y versión exacta de cada servidor
curl -sI http://localhost:8081/ | grep -i '^server'
curl -sI http://localhost:8082/ | grep -i '^server'
# Página por defecto: dice qué software es y que nadie configuró el sitio
curl -s http://localhost:8081/ | grep -o '<title>.*</title>'
curl -s http://localhost:8082/ | grep -o '<title>.*</title>'
# Listado de directorios y un respaldo con claves (A02:2025 Security Misconfiguration)
curl -s http://localhost:8081/descargas/ | grep -o 'href="[^"?]*"'
curl -s http://localhost:8081/descargas/backup-config-2026.txt
# Archivo .env servido como si fuera una página
curl -s http://localhost:8082/.env
# Páginas de estado internas (procesos, conexiones, peticiones en curso)
curl -s http://localhost:8081/server-status | grep -iE 'server version|uptime' | head -3
curl -s http://localhost:8082/nginx_status
# Las páginas de error también revelan la versión
curl -s http://localhost:8081/no-existe | grep -i address
```

```bash
# nmap: qué software y versión responde en cada puerto (lo mismo que ve un escáner externo)
nmap -sV -p 8081,8082 localhost
```

```bash
# Auditor web: 20 controles; guarda la línea base de cada servidor
cd /home/brian/clase-06-servicios-web/scripts
bash auditar-web.sh -p 8081 -s 8441 -o /home/brian/c6/antes/apache.md
bash auditar-web.sh -p 8082 -s 8442 -o /home/brian/c6/antes/nginx.md
```

Referencia del entorno de prueba del docente: **Apache 5 %** · **Nginx 5 %**.

### A3 · Endurecer Apache (15 min)

```bash
# 1) Ocultar versión y firma, y desactivar TRACE (método de depuración)
sudo sed -i 's/^ServerTokens .*/ServerTokens Prod/; s/^ServerSignature .*/ServerSignature Off/; s/^TraceEnable .*/TraceEnable Off/' /etc/apache2/conf-available/security.conf
# Verifica los tres valores
grep -E '^(ServerTokens|ServerSignature|TraceEnable)' /etc/apache2/conf-available/security.conf
# 2) Tiempo de espera de 300 s a 60 s: menos conexiones "colgadas" (ataques lentos tipo Slowloris)
sudo sed -i 's/^Timeout 300/Timeout 60/' /etc/apache2/apache2.conf
```

```bash
# 3) Quitar módulos que no se usan: páginas de estado y listado automático de carpetas
sudo a2dismod -f status autoindex
# 4) Activar los que sí necesitamos: TLS, cabeceras, redirecciones y límite de peticiones
sudo a2enmod ssl headers rewrite evasive
# Lista los módulos cargados (revisa que status y autoindex ya no estén)
sudo apache2ctl -M | sort | head -40
```

```bash
# 5) Configuración de mod_evasive: más de 5 pedidos de la misma página en 1 s → bloqueo de 10 s (403)
sudo cp /home/brian/clase-06-servicios-web/parte-a-host/apache/evasive.conf /etc/apache2/mods-available/evasive.conf
# Carpeta de registros de mod_evasive, propiedad del usuario de Apache
sudo mkdir -p /var/log/apache2/evasive && sudo chown www-data:www-data /var/log/apache2/evasive
```

```bash
# 6) Sitio endurecido: lee el archivo y fíjate en cada bloque (TLS, cabeceras, Directory, FilesMatch)
less /home/brian/clase-06-servicios-web/parte-a-host/apache/burgerbank-ssl.conf
# Instálalo, desactiva el sitio por defecto y activa el nuevo
sudo cp /home/brian/clase-06-servicios-web/parte-a-host/apache/burgerbank-ssl.conf /etc/apache2/sites-available/
sudo a2dissite 000-default
sudo a2ensite burgerbank-ssl
# 7) Reemplaza la página por defecto por la del sitio
sudo cp /home/brian/clase-06-servicios-web/parte-a-host/sitio/index.html /var/www/html/index.html
# 8) SIEMPRE revisar la sintaxis antes de reiniciar
sudo apache2ctl configtest
sudo systemctl restart apache2
```

| Línea de `burgerbank-ssl.conf` | Control |
|-------------------------------|---------|
| `RewriteRule ^ https://%1:8441...` | Todo HTTP redirige a HTTPS |
| `SSLProtocol -all +TLSv1.2 +TLSv1.3` | Fuera SSL, TLS 1.0 y 1.1 |
| `Header always set ...` | HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy |
| `Options -Indexes -FollowSymLinks` | Sin listado de carpetas ni enlaces simbólicos fuera del sitio |
| `<LimitExcept GET POST HEAD>` | Solo los métodos que el sitio usa |
| `<FilesMatch "^\.">` / `<DirectoryMatch "/\.">` | Nunca sirve `.env`, `.git`, `.htpasswd` |
| `LimitRequestBody 102400` | Peticiones de máximo 100 KB |

```bash
# Comprueba: redirección, cabeceras sin versión y archivos protegidos
curl -sI http://localhost:8081/ | grep -iE '^(HTTP|location)'
curl -skI https://localhost:8441/ | grep -iE '^(server|strict|x-frame|content-security)'
curl -sk -o /dev/null -w '.env → %{http_code}\n' https://localhost:8441/.env
curl -sk -o /dev/null -w 'descargas → %{http_code}\n' https://localhost:8441/descargas/
```

> El respaldo y el `.env` siguen en el disco: la configuración los bloquea. Lo correcto además es
> **sacarlos de la raíz web** (`sudo mv /var/www/html/.env /root/`). Defensa en profundidad.

### A4 · Endurecer Nginx (10 min)

```bash
# 1) Ocultar la versión en todo el servidor (la línea viene comentada en Ubuntu)
sudo sed -i 's/# server_tokens off;/server_tokens off;/' /etc/nginx/nginx.conf
grep -n 'server_tokens' /etc/nginx/nginx.conf
# 2) Sitio endurecido: compáralo con el bloque de Apache, hace lo mismo con otra sintaxis
less /home/brian/clase-06-servicios-web/parte-a-host/nginx/burgerbank-nginx.conf
# 3) Instálalo y desactiva el sitio inseguro (que tenía autoindex y stub_status)
sudo cp /home/brian/clase-06-servicios-web/parte-a-host/nginx/burgerbank-nginx.conf /etc/nginx/sites-available/burgerbank
sudo rm /etc/nginx/sites-enabled/lab-inseguro
sudo ln -s /etc/nginx/sites-available/burgerbank /etc/nginx/sites-enabled/burgerbank
# 4) Página del sitio
sudo cp /home/brian/clase-06-servicios-web/parte-a-host/sitio/index.html /var/www/nginx-lab/index.html
# 5) Revisar sintaxis y recargar (reload no corta las conexiones abiertas)
sudo nginx -t && sudo systemctl reload nginx
```

### A5 · Re-medir y comparar (2 min)

```bash
# Mismo auditor, ahora contra HTTPS
cd /home/brian/clase-06-servicios-web/scripts
bash auditar-web.sh -p 8081 -s 8441 -o /home/brian/c6/despues/apache.md
# Espera 10 s: mod_evasive de Apache pudo bloquear tu IP en la prueba de rate limit
sleep 10
bash auditar-web.sh -p 8082 -s 8442 -o /home/brian/c6/despues/nginx.md
# nmap ahora solo ve "Apache" y "nginx", sin versión; y solo TLS 1.2/1.3
nmap -sV -p 8441,8442 localhost
nmap -p 8441 --script ssl-enum-ciphers localhost | grep -E 'TLSv|least strength'
```

Referencia: **Apache 5 % → 100 %** · **Nginx 5 % → 100 %**.

### Apache y Nginx: misma idea, otra sintaxis

| Control | Apache | Nginx |
|---------|--------|-------|
| Ocultar versión | `ServerTokens Prod` + `ServerSignature Off` | `server_tokens off;` |
| Sin listado | `Options -Indexes` (o `a2dismod autoindex`) | `autoindex off;` |
| Solo TLS 1.2/1.3 | `SSLProtocol -all +TLSv1.2 +TLSv1.3` | `ssl_protocols TLSv1.2 TLSv1.3;` |
| Cabeceras | `Header always set ...` | `add_header ... always;` |
| Métodos | `<LimitExcept GET POST HEAD>` | `if ($request_method !~ ...) { return 405; }` |
| Archivos ocultos | `<FilesMatch "^\.">` | `location ~ /\. { deny all; }` |
| Tamaño máximo | `LimitRequestBody` | `client_max_body_size` |
| Rate limit | `mod_evasive` (403) | `limit_req` (429) |
| Páginas de estado | `a2dismod status` | quitar `stub_status` |
| Revisar antes de aplicar | `apache2ctl configtest` | `nginx -t` |

**Checkpoint A:** los dos servidores al 100 %, solo HTTPS, sin versión. Puedes dejarlos encendidos:
no chocan con la Parte B (usan otros puertos).

---

# PARTE B · Microservicios, API REST y web service SOAP en Docker (70 min)

### B1 · Levantar la aplicación insegura (5 min)

```bash
# Entra a la versión insegura y lee el compose: ports, privileged, environment, docker.sock
cd /home/brian/clase-06-servicios-web/parte-b-docker/inseguro
cat docker-compose.yml
# Construye las imágenes de pedidos y facturacion y levanta los 5 contenedores
sudo docker compose up -d --build
# Estado y puertos publicados
sudo docker compose ps
```

### B2 · Reconocer la web, la API y el web service como lo haría un atacante (10 min)

**Superficie expuesta**

```bash
# Puertos publicados: 80, 5000 (API directa), 5001 (SOAP directo) y 16379 (Redis)
sudo ss -tlnp | grep -E ':(80|443|5000|5001|16379) '
# Redis sin clave: cualquiera lee los datos
redis-cli -p 16379 keys '*'
# Docker publica puertos con sus propias reglas de NAT, ANTES que ufw (solo observa, no hay reglas que crear)
sudo ufw status | head -5
sudo iptables -t nat -S DOCKER | grep -E 'dport (80|5000|5001|16379)'
```

**API REST — OWASP API Security Top 10 (2023)**

```bash
# API2 · Sin autenticación: cualquiera lista los pedidos
curl -s http://localhost/api/v1/pedidos
# API1 · BOLA: basta cambiar el número para ver el pedido de otro cliente
curl -s http://localhost/api/v1/pedidos/2
# API3 · Exposición de datos: tarjeta completa y costo interno en la respuesta (míralo arriba)
# API3 · Asignación masiva: el cliente decide el estado y el precio de su pedido
curl -s -X POST http://localhost/api/v1/pedidos -H 'Content-Type: application/json' -d '{"producto":"Combo","cantidad":1,"estado":"pagado","precio":0}'
# API8 · CORS abierto: cualquier sitio web puede leer la API desde el navegador de la víctima
curl -sI -H 'Origin: https://sitio-malicioso.example' http://localhost/api/v1/pedidos | grep -i access-control
# API9 · Inventario: la versión vieja sigue publicada y hay un endpoint de depuración
curl -s -o /dev/null -w 'v0 → %{http_code}\n' http://localhost/api/v0/pedidos
curl -s http://localhost/api/info | head -c 300; echo
# Errores con la traza completa del servidor (A10:2025)
curl -s -X POST http://localhost/api/v1/pedidos -H 'Content-Type: application/json' -d '[1]' | grep -m3 -iE 'traceback|error'
```

**Web service SOAP**

```bash
# El WSDL describe todas las operaciones, incluida "anularFactura", a cualquiera
curl -s 'http://localhost/ws/facturacion?wsdl' | grep -o 'operation name="[a-zA-Z]*"'
# Consulta normal de una factura
curl -s -X POST http://localhost/ws/facturacion -H 'Content-Type: text/xml' --data-binary '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><consultarFactura xmlns="urn:burgerbank:facturacion"><numero>1001</numero></consultarFactura></soap:Body></soap:Envelope>'
# Prueba de control XXE: si el parser resuelve entidades externas, devuelve el contenido de /etc/hostname
curl -s -X POST http://localhost/ws/facturacion -H 'Content-Type: text/xml' --data-binary '<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/hostname">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><consultarFactura xmlns="urn:burgerbank:facturacion"><numero>&x;</numero></consultarFactura></soap:Body></soap:Envelope>' | grep -o '<numero>[^<]*'
```

> Si en `<numero>` aparece un código de 12 caracteres (el nombre del contenedor), el parser **leyó un archivo
> del servidor** por pedido del cliente. Con otra ruta podría leer claves o configuración. Es el riesgo XXE
> (*XML External Entities*), clásico en web services SOAP y en cualquier API que acepte XML.

**Checkpoint B2:** viste 4 puertos publicados, BOLA, asignación masiva, CORS `*`, WSDL público y XXE.

### B3 · Puentes al host (tarea, 10 min)

Igual que en la Clase 3 (escalada de privilegios): ¿qué gana un atacante **si entra a un contenedor**?

```bash
# Contenedor privilegiado: casi todas las capacidades del kernel (CapEff lleno de f)
sudo docker exec pedidos grep CapEff /proc/self/status
# "monitor" monta el socket de Docker: desde adentro controla TODO Docker del host
sudo docker exec monitor curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | python3 -c "import sys,json;[print(c['Names'][0], c['Image']) for c in json.load(sys.stdin)]"
# El grupo docker equivale a root: un contenedor que monta "/" lee /etc/shadow de la VM
sudo docker run --rm -v /:/host redis:6.0 head -3 /host/etc/shadow
# Secretos horneados en la imagen: el historial de capas y el .env copiado con el código
sudo docker history --no-trunc --format '{{.CreatedBy}}' burgerbank/pedidos:1.0 | grep -E 'ENV|COPY'
sudo docker exec pedidos cat /app/.env
# El depurador de Flask imprime su PIN en los logs: quien los lea abre una consola Python en el servidor
sudo docker logs pedidos 2>&1 | grep -i 'debugger pin'
```

### B4 · Medir: la línea base "antes" (10 min)

```bash
cd /home/brian/clase-06-servicios-web/scripts
# 1) Contenedores (20 controles: demonio, contenedores, red)
sudo bash auditar-contenedores.sh -o /home/brian/c6/antes/contenedores.md
# 2) Web del proxy Docker (20 controles)
bash auditar-web.sh -p 80 -s 443 -a /api/v1/pedidos -o /home/brian/c6/antes/web-docker.md
# 3) API REST y SOAP (12 controles OWASP API)
bash auditar-api.sh -o /home/brian/c6/antes/api.md
# 4) Trivy: malas configuraciones en los Dockerfile y secretos en los archivos
trivy config /home/brian/clase-06-servicios-web/parte-b-docker/inseguro | tee /home/brian/c6/antes/trivy-config.txt
trivy fs --scanners secret /home/brian/clase-06-servicios-web/parte-b-docker/inseguro | tee /home/brian/c6/antes/trivy-secretos.txt
```

Referencia del docente: **contenedores 10 %** · **web Docker 20 %** · **API 0 %** · `trivy config` **7** fallas · secretos **2**.

**Tarea (si vas corto):** CVE de las imágenes y Docker Bench.

```bash
# CVE altos y críticos de las 4 imágenes (el informe completo queda en cada archivo)
for i in burgerbank/pedidos:1.0 burgerbank/facturacion:1.0 nginx:1.21 redis:6.0; do sudo trivy image --severity HIGH,CRITICAL -o /home/brian/c6/antes/trivy-$(echo $i | tr '/:' '__').txt $i; done
grep -H 'Total:' /home/brian/c6/antes/trivy-*_*.txt
# Librerías de Python vulnerables (Werkzeug, Flask, lxml)
grep -ihE 'werkzeug|flask|lxml' /home/brian/c6/antes/trivy-burgerbank_*.txt | head
# CIS Docker Benchmark con la herramienta oficial de Docker (3 secciones)
git clone --depth 1 https://github.com/docker/docker-bench-security.git /home/brian/docker-bench
cd /home/brian/docker-bench && sudo sh docker-bench-security.sh -c docker_daemon_configuration,container_images,container_runtime -l /home/brian/c6/antes/docker-bench.log
grep -E 'Checks:|Score:' /home/brian/c6/antes/docker-bench.log
```

Referencia: **Docker Bench Score −4**.

### B5 · Endurecer (30 min)

Orden importante: **primero el demonio** (B5.1), porque reiniciar Docker detiene los contenedores que no tienen `restart: always`.

#### B5.1 · Demonio de Docker (5 min)

```bash
# Valores seguros por defecto para TODO contenedor del host
sudo tee /etc/docker/daemon.json > /dev/null <<'EOF'
{
  "icc": false,
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
EOF
# JSON válido (si hay error, Docker no arranca)
python3 -m json.tool /etc/docker/daemon.json
# Aplica (los contenedores inseguros vuelven solos: tienen restart: always)
sudo systemctl restart docker
sudo docker info --format 'live-restore={{.LiveRestoreEnabled}} · {{.SecurityOptions}}'
# Tu usuario NO debe estar en el grupo docker; el socket debe ser 660 root:docker
id brian; ls -l /var/run/docker.sock
```

| Clave | Qué hace |
|-------|----------|
| `icc: false` | En la red por defecto, los contenedores no se hablan entre sí salvo que se permita |
| `no-new-privileges` | Ningún proceso gana privilegios (setuid, sudo) dentro de un contenedor |
| `live-restore` | Los contenedores siguen corriendo si el demonio se reinicia o actualiza |
| `userland-proxy: false` | iptables en vez de un proceso proxy por cada puerto publicado |
| `log-opts` | Rota los logs: máximo 3 archivos de 10 MB por contenedor |

#### B5.2 · Imágenes: Dockerfile endurecido (8 min)

```bash
cd /home/brian/clase-06-servicios-web/parte-b-docker/endurecido
# Compara el Dockerfile inseguro con el endurecido (el de facturacion es igual)
diff -y --width=160 ../inseguro/pedidos/Dockerfile pedidos/Dockerfile | less
# Trivy revisa los Dockerfile ANTES de construir: deben salir 0 problemas
trivy config .
# Construye las dos imágenes nuevas
sudo docker build -t burgerbank/pedidos:2.0 pedidos/
sudo docker build -t burgerbank/facturacion:2.0 facturacion/
# Tamaños y usuario de las imágenes
sudo docker images 'burgerbank/*' --format 'table {{.Repository}}:{{.Tag}}\t{{.Size}}'
sudo docker inspect --format '{{.RepoTags}} usuario={{.Config.User}}' burgerbank/pedidos:2.0 burgerbank/facturacion:2.0
```

| Antes | Después | Riesgo que corta |
|-------|---------|------------------|
| `python:3.9-slim-bookworm` (sin soporte) | `python:3.12-slim` | CVE del sistema y del intérprete |
| `ENV REDIS_PASSWORD=...` | Secretos en `/run/secrets` | Secretos en el historial de capas |
| `COPY . /app` sin `.dockerignore` | `.dockerignore` + solo `app.py` | `.env` dentro de la imagen |
| Root | `USER 10001` | Root dentro del contenedor |
| Flask debug / servidor de desarrollo | gunicorn | Consola del depurador |
| Una etapa | Dos etapas (`AS build`) | Compiladores y caché en la imagen final |
| Sin HEALTHCHECK | `HEALTHCHECK` | Contenedores "vivos" pero rotos |
| Werkzeug 2.0.3, lxml 4.6.5 | Flask 3.1.3, defusedxml | CVE de librerías (A03:2025) |

> **En producción** se fija la imagen base por *digest* (`python:3.12-slim@sha256:...`): la etiqueta se puede
> mover, el digest no. Es la lección del caso Trivy (Lab 6.3).

#### B5.3 · Secretos, claves de API y certificado (3 min)

```bash
# Lee el script: clave de Redis, ACL con hash, claves de API de ana y luis, certificado
less preparar-secretos.sh
# Ejecútalo y COPIA las dos líneas CLAVE_ANA y CLAVE_LUIS que muestra al final
sudo bash preparar-secretos.sh
# Guarda las claves en variables para las pruebas (pega los valores que te mostró)
CLAVE_ANA=pega_aqui_la_clave_de_ana
CLAVE_LUIS=pega_aqui_la_clave_de_luis
# El ACL de Redis guarda la clave como hash SHA-256 y prohíbe comandos peligrosos
sudo cat secrets/redis_users.acl
```

| Archivo | Lo lee | Dueño | Permisos |
|---------|--------|-------|----------|
| `secrets/redis_password.txt` | pedidos | 10001 | 400 |
| `secrets/api_keys.json` | pedidos y facturacion | 10001 | 400 |
| `secrets/redis_users.acl` | cache | 999 | 400 |
| `certs/web.key` | web (nginx) | 101 | 400 |

#### B5.4 · El código: cómo se corrigen las fallas de la API y del SOAP (5 min, lectura)

```bash
# Compara la API insegura con la endurecida
diff -y --width=170 ../inseguro/pedidos/app.py pedidos/app.py | less
# Compara el web service SOAP
diff -y --width=170 ../inseguro/facturacion/app.py facturacion/app.py | less
```

| OWASP API 2023 | Falla en la versión insegura | Corrección en el código endurecido |
|----------------|------------------------------|------------------------------------|
| API1 BOLA | `GET /pedidos/2` devuelve cualquier pedido | Compara el dueño del pedido con el cliente de la clave; si no coincide, 404 |
| API2 Autenticación | No hay | `X-API-Key` obligatoria en `/api/` y `/ws/` (`before_request`) |
| API3 Propiedades | Devuelve tarjeta y costo; acepta `estado` y `precio` | `publico()` devuelve solo campos permitidos; `crear()` toma solo producto y cantidad |
| API4 Consumo | Sin límites | `MAX_CONTENT_LENGTH` + `limit_req` en nginx |
| API8 Configuración | CORS `*`, debug, errores con traza | CORS solo para `https://burgerbank.lab`, gunicorn, errores genéricos |
| API9 Inventario | `/api/v0` y `/api/info` publicados | Eliminados |
| XXE (SOAP) | `XMLParser(resolve_entities=True, load_dtd=True)` | `defusedxml` con `forbid_dtd=True` + validación del número |

#### B5.5 · nginx del proxy (2 min)

```bash
# Configuración del proxy endurecido: HTTPS, cabeceras, rate limit, /api/ y /ws/
less web/default.conf
```

> Igual que en la Parte A (ahora dentro de un contenedor sin privilegios que escucha en 8080/8443),
> más dos bloques `location`: `/api/` y `/ws/` (este con `client_max_body_size 16k`).

#### B5.6 · Compose endurecido y cambio de versión (5 min)

```bash
# Compara los dos compose
diff -y --width=170 ../inseguro/docker-compose.yml docker-compose.yml | less
# Detén la versión insegura (las imágenes quedan para comparar)
cd ../inseguro && sudo docker compose down
# Levanta la versión endurecida
cd ../endurecido && sudo docker compose up -d
# Espera ~45 s: los 4 contenedores deben quedar "healthy"
sleep 45; sudo docker compose ps
```

| Control | En el compose |
|---------|---------------|
| Solo `web` publica puertos (80 y 443) | `ports:` solo en `web` |
| API, SOAP y Redis en una red sin salida | `networks: backend: internal: true` |
| Sin privilegios | `cap_drop: ["ALL"]`, `no-new-privileges:true`, sin `privileged` |
| Disco de solo lectura | `read_only: true` + `tmpfs` |
| Límites | `mem_limit`, `cpus`, `pids_limit` |
| Salud y orden de arranque | `healthcheck` + `depends_on: condition: service_healthy` |
| Reinicio acotado | `restart: on-failure:5` |
| Secretos como archivos | `secrets:` → `/run/secrets/...` |
| Sin socket de Docker | se elimina `monitor` |

#### B5.7 · Comprobar (5 min)

```bash
# Usuario, solo lectura, privilegios, capacidades, memoria y procesos de cada contenedor
for c in web pedidos facturacion cache; do sudo docker inspect --format '{{.Name}} user={{.Config.User}} ro={{.HostConfig.ReadonlyRootfs}} priv={{.HostConfig.Privileged}} capdrop={{.HostConfig.CapDrop}} mem={{.HostConfig.Memory}}' $c; done
# Capacidades efectivas en cero
sudo docker exec pedidos grep CapEff /proc/self/status
# La red backend no tiene salida a internet
sudo docker exec pedidos python -c "import urllib.request; urllib.request.urlopen('http://1.1.1.1', timeout=3)"
# Redis: sin usuario rechaza; con el usuario pedidos, FLUSHALL prohibido
sudo docker exec cache redis-cli ping
sudo docker exec cache redis-cli --no-auth-warning --user pedidos --pass "$(sudo cat secrets/redis_password.txt)" flushall
```

```bash
# La API sin clave → 401; con la clave de ana solo ve sus pedidos y la tarjeta enmascarada
curl -sk -o /dev/null -w 'sin clave → %{http_code}\n' https://localhost/api/v1/pedidos
curl -sk -H "X-API-Key: $CLAVE_ANA" https://localhost/api/v1/pedidos; echo
# BOLA corregido: ana pide el pedido 2 (de luis) → 404
curl -sk -o /dev/null -w 'ana pide el pedido de luis → %{http_code}\n' -H "X-API-Key: $CLAVE_ANA" https://localhost/api/v1/pedidos/2
# Luis sí puede ver su propio pedido
curl -sk -H "X-API-Key: $CLAVE_LUIS" https://localhost/api/v1/pedidos/2; echo
# XXE bloqueado: SOAP Fault "XML no válido"
curl -sk -H "X-API-Key: $CLAVE_ANA" -X POST https://localhost/ws/facturacion -H 'Content-Type: text/xml' --data-binary '<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/hostname">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><consultarFactura xmlns="urn:burgerbank:facturacion"><numero>&x;</numero></consultarFactura></soap:Body></soap:Envelope>' | grep -o '<faultstring>[^<]*'
```

**Checkpoint B5:** 4 contenedores `healthy`, CapEff en cero, sin internet en backend, FLUSHALL con `NOPERM`,
401 sin clave, 404 en el pedido ajeno y SOAP Fault ante XXE.

### B6 · Re-medir: "después" (10 min)

```bash
cd /home/brian/clase-06-servicios-web/scripts
sudo bash auditar-contenedores.sh -o /home/brian/c6/despues/contenedores.md
bash auditar-web.sh -p 80 -s 443 -a /api/v1/pedidos -o /home/brian/c6/despues/web-docker.md
# El auditor de API necesita las claves (con sudo, porque el archivo es 400 del uid 10001)
sudo bash auditar-api.sh -k /home/brian/clase-06-servicios-web/parte-b-docker/endurecido/secrets/api_keys.json -o /home/brian/c6/despues/api.md
trivy config /home/brian/clase-06-servicios-web/parte-b-docker/endurecido | tee /home/brian/c6/despues/trivy-config.txt
trivy fs --scanners secret /home/brian/clase-06-servicios-web/parte-b-docker/endurecido/pedidos | tee /home/brian/c6/despues/trivy-secretos.txt
```

**Tarea:** CVE de las imágenes nuevas y Docker Bench.

```bash
for i in burgerbank/pedidos:2.0 burgerbank/facturacion:2.0 nginxinc/nginx-unprivileged:stable-alpine redis:7.4-alpine; do sudo trivy image --severity HIGH,CRITICAL -o /home/brian/c6/despues/trivy-$(echo $i | tr '/:' '__').txt $i; done
grep -H 'Total:' /home/brian/c6/despues/trivy-*_*.txt
cd /home/brian/docker-bench && sudo sh docker-bench-security.sh -c docker_daemon_configuration,container_images,container_runtime -l /home/brian/c6/despues/docker-bench.log
grep -E 'Checks:|Score:' /home/brian/c6/despues/docker-bench.log
```

### Tabla de resultados (cópiala en tu entrega)

| Medición | Antes | Después | Referencia docente |
|----------|-------|---------|--------------------|
| Auditor web · Apache (host) | __ % | __ % | 5 % → 100 % |
| Auditor web · Nginx (host) | __ % | __ % | 5 % → 100 % |
| Auditor web · proxy Docker | __ % | __ % | 20 % → 100 % |
| Auditor de APIs (REST + SOAP) | __ % | __ % | 0 % → 100 % |
| Auditor de contenedores | __ % | __ % | 10 % → 100 % |
| `trivy config` (fallas en Dockerfile) | __ | __ | 7 → 0 |
| `trivy fs` secretos | __ | __ | 2 → 0 |
| Trivy CVE HIGH+CRITICAL (suma de las 4 imágenes) | __ | __ | (anota el tuyo) |
| Docker Bench Score | __ | __ | −4 → 22 |

### Advertencias aceptadas o falsos positivos (explícalas, no las "arregles a ciegas")

| Hallazgo | Por qué queda | Decisión |
|----------|---------------|----------|
| `ip_forward=1` (CIS Linux de la C3) | Docker lo necesita | Excepción documentada |
| Certificados autofirmados | Laboratorio sin dominio público | En producción: Let's Encrypt o CA interna |
| HSTS de 300 s | Con un certificado autofirmado, un HSTS largo deja el sitio inaccesible si falla | En producción: 1 año |
| Docker Bench 2.2 (icc en redes de compose) | `icc:false` aplica a la red por defecto; separamos con `frontend`/`backend` | Aceptado |
| Docker Bench 5.8 / 5.9 / 5.14 (80/443 en 0.0.0.0) | Es el servicio web: tiene que publicarse | Aceptado |
| Docker Bench 4.6 (HEALTHCHECK en imágenes oficiales) | Definido en el compose | Aceptado |
| Docker Bench 2.9 (userns-remap) | Rompe permisos de volúmenes; Lab 6.5 | Pendiente |
| CVE "sin parche" en Trivy | No hay versión corregida | Revisar con `--ignore-unfixed` y re-escanear |
| Claves de API simples | En producción: OAuth 2.0 / JWT con expiración y un API gateway | Aceptado en laboratorio |

### B7 · Cierre (5 min)

```bash
# Prueba final como cliente legítimo: luis crea un pedido y solo ve los suyos
curl -sk -H "X-API-Key: $CLAVE_LUIS" -X POST https://localhost/api/v1/pedidos -H 'Content-Type: application/json' -d '{"producto":"Combo familiar","cantidad":2}'; echo
curl -sk -H "X-API-Key: $CLAVE_LUIS" https://localhost/api/v1/pedidos; echo
# Apaga la app Docker (Redis no guarda datos en esta versión: se pierden al apagar)
cd /home/brian/clase-06-servicios-web/parte-b-docker/endurecido && sudo docker compose down
# Si quieres liberar RAM, apaga Apache y Nginx de la Parte A
sudo systemctl stop apache2 nginx
# Si apagaste los servicios de la Clase 4, vuelve a encenderlos
sudo systemctl start mysql postgresql redis-server
```

---

## Entrega (Pull Request)

Crea `clase-06/entregas/<tu-usuario>.md` en tu fork con:

1. La **tabla de resultados** de B6 completa.
2. Los archivos `.md` de los auditores de **antes** y **después** (o pégalos en tu entrega).
3. La tabla **Apache vs Nginx** de A5 con una fila extra que tú agregues (otro control que encuentres en el CIS Benchmark).
4. Respuestas a las preguntas:
   - **P1.** ¿Por qué `ufw` no protegió los puertos 5000, 5001 y 16379? ¿Qué lo hizo en la versión endurecida?
   - **P2.** La API endurecida devuelve 404 (y no 403) cuando ana pide el pedido de luis. ¿Por qué es mejor?
   - **P3.** ¿Qué diferencia hay entre un secreto en `ENV` y uno en `/run/secrets`? ¿Dónde lo ve un atacante en cada caso?
   - **P4.** Un banco tiene un web service SOAP de 2010 que no se puede reescribir. Con lo visto hoy, ¿qué 3 controles le pondrías delante sin tocar su código?
   - **P5.** Si la app tuviera un chatbot con IA y una base vectorial (Clase 4), ¿en qué red pondrías esos contenedores y por qué?

### Tarea para el jueves (Clase 7 · Azure)

1. Crear tu **cuenta gratuita de Azure** (azure.microsoft.com/free) e ingresar una vez a portal.azure.com.
2. En el Ubuntu, hacer los pasos **0.2 y 0.3** del laboratorio de la Clase 7 (Azure CLI y Prowler).

---

## Lab 6 · Opcional / tarea

**6.1 WAF con ModSecurity + OWASP CRS en Apache:** un firewall de aplicaciones web delante del sitio.
```bash
# Instala ModSecurity y el conjunto de reglas OWASP Core Rule Set
sudo apt install -y libapache2-mod-security2 modsecurity-crs
# Usa la configuración recomendada y pasa de "solo detectar" a "bloquear"
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo sed -i 's/^SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
sudo apache2ctl configtest && sudo systemctl restart apache2
# Tráfico normal (200) vs. intento de inyección SQL y de XSS (403). Espera 10 s si mod_evasive te bloqueó
sleep 10
curl -sk -o /dev/null -w 'normal → %{http_code}\n' https://localhost:8441/
curl -sk -o /dev/null -w 'inyección → %{http_code}\n' "https://localhost:8441/?id=1%27%20OR%20%271%27=%271"
curl -sk -o /dev/null -w 'XSS → %{http_code}\n' "https://localhost:8441/?q=%3Cscript%3Ealert(1)%3C/script%3E"
# Qué regla bloqueó la petición
sudo grep -oE 'id "[0-9]+"|msg "[^"]+"' /var/log/apache2/modsec_audit.log | tail -4
```

**6.2 Trivy como puerta de calidad (CI/CD):** la construcción "falla" si hay críticos con parche.
```bash
sudo trivy image --severity CRITICAL --ignore-unfixed --exit-code 1 burgerbank/pedidos:1.0; echo "Código de salida: $?"
sudo trivy image --severity CRITICAL --ignore-unfixed --exit-code 1 burgerbank/pedidos:2.0; echo "Código de salida: $?"
```

**6.3 SBOM y digest:**
```bash
# Lista de materiales del software (CycloneDX) y re-escaneo sin bajar la imagen
sudo trivy image --format cyclonedx -o /home/brian/c6/sbom-pedidos-2.0.json burgerbank/pedidos:2.0
trivy sbom /home/brian/c6/sbom-pedidos-2.0.json --severity HIGH,CRITICAL | grep 'Total:'
# Digest exacto de la imagen base (para fijarla en el FROM)
sudo docker inspect --format '{{index .RepoDigests 0}}' python:3.12-slim
```

**6.4 AppArmor:** `for c in web pedidos facturacion cache; do sudo docker inspect --format '{{.Name}} {{.AppArmorProfile}}' $c; done` (debe decir `docker-default`).

**6.5 userns-remap (avanzado):** agrega `"userns-remap": "default"` a `daemon.json`, reinicia Docker y observa qué
se rompe (pista: los dueños por uid de B5.3). Documenta por qué muchas empresas usan Podman sin root o Kubernetes.

**6.6 Documentar la API con OpenAPI:** escribe un `openapi.yaml` mínimo para `/api/v1/pedidos`
(GET lista, GET por id, POST) con el esquema de seguridad `apiKey` en la cabecera `X-API-Key`.
Un inventario documentado es lo que evita el API9 (versiones olvidadas).

---

## Errores comunes

| Síntoma | Causa | Solución |
|---------|-------|----------|
| `apache2ctl configtest` muestra `AH00558 ... ServerName` | Solo un aviso | Se ignora, o agrega `ServerName localhost` en `apache2.conf` |
| Apache no arranca tras A3 | Error de sintaxis o módulo faltante | `sudo apache2ctl configtest` y `sudo journalctl -u apache2 -n 20` |
| `Invalid command 'Header'` o `'SSLEngine'` | No se activó `headers` o `ssl` | `sudo a2enmod ssl headers rewrite` |
| El auditor de Nginx sale con varios 403 justo después del de Apache | mod_evasive bloqueó tu IP 10 s | Espera 10 s (`sleep 10`) y repite |
| `nginx: [emerg] unknown directive "http2"` | Sintaxis de nginx 1.25+ en el nginx 1.18 de Ubuntu | En el host usa `listen 8442 ssl http2;` (así viene el archivo) |
| `permission denied ... docker.sock` | `docker` sin `sudo` | `sudo docker ...` |
| `apt update` falla con `NO_PUBKEY` (Trivy) | La umask 027 dejó la llave sin lectura | `sudo chmod 644 /usr/share/keyrings/trivy.gpg /etc/apt/sources.list.d/trivy.list` |
| `web` inseguro de Docker responde 403 en `/` | Archivos sin lectura para "otros" | `chmod -R o+rX /home/brian/clase-06-servicios-web` |
| `web` endurecido se reinicia en bucle | nginx (uid 101) no lee `web.key` o `default.conf` | Repite `sudo bash preparar-secretos.sh` y el `chmod` del 0.2 |
| `pedidos` o `facturacion` quedan `unhealthy` | No leen `/run/secrets/...` o Redis rechaza al usuario | `sudo docker logs pedidos`; repite B5.3 y `sudo docker compose up -d --force-recreate` |
| La API responde 401 con tu clave | Variable vacía (terminal nueva) | Vuelve a definir `CLAVE_ANA` / `CLAVE_LUIS` |
| `bind: address already in use` en 80/443 | Otro servicio usa el puerto | `sudo ss -tlnp | grep -E ':80 |:443 '` (Apache/Nginx del host deben estar en 8081/8082) |
| Docker no arranca tras `daemon.json` | JSON inválido | `python3 -m json.tool /etc/docker/daemon.json` y `sudo journalctl -u docker -n 20` |
| Tras reiniciar Docker los contenedores endurecidos no vuelven | `on-failure` no reinicia si se detuvieron limpio | `sudo docker compose up -d` en `endurecido/` |
| `toomanyrequests` al hacer `pull` | Límite de descargas anónimas de Docker Hub | Espera o `sudo docker login` con una cuenta gratuita |

---

## Referencias

- CIS Apache HTTP Server 2.4 Benchmark · CIS NGINX Benchmark · CIS Docker Benchmark
- NIST SP 800-190 *Application Container Security Guide* · NIST SP 800-95 *Guide to Secure Web Services*
- OWASP Top 10:2025 · OWASP API Security Top 10 (2023) · OWASP Secure Headers Project
- OWASP Cheat Sheets: XML External Entity Prevention, REST Security, Docker Security
- Trivy (trivy.dev) · Aviso CVE-2026-33634 · ModSecurity + OWASP Core Rule Set (coreruleset.org)
