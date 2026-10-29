# Clase 5 · Laboratorio — Firewalls: del host al perímetro

**SENATI · Diplomado Gestión de la Ciberseguridad · Módulo 04 "Aseguramiento de los Sistemas"**
**Docente:** Ademir Cuadros · **Duración de la práctica:** 2 horas (+ B5 Suricata opcional / tarea)

> Mismo ciclo de siempre: **medir → endurecer → re-medir → mirar desde afuera**, ahora en dos niveles:
> - **Parte A · Firewall de host:** el propio Ubuntu se defiende con **iptables** y luego con **firewalld**.
> - **Parte B · Firewall perimetral:** **pfSense** protege redes enteras, y además hay que protegerlo a él. Un firewall mal configurado no solo deja pasar ataques: **es** el blanco. Los incidentes de 2024–2025 en Fortinet, Palo Alto e Ivanti empezaron por la interfaz de administración o la VPN expuestas.
>
> **Hilo conductor:** una sola **batería de pruebas desde Kali** (`pruebas-firewall.sh`) que se ejecuta **5 veces**: sin firewall → iptables → firewalld → pfSense antes → pfSense después. Al final, una tabla compara las 5 columnas.

---

## Antes de empezar (leer 1 minuto)

- **Tarea previa:** tener pfSense CE 2.8.x instalado (ver **Anexo A**). Si no lo hiciste, instálalo mientras los demás hacen la Parte A (no la necesita).
- Usamos **3 VMs** (≈ 6 GB de RAM): **pfSense** (1 GB; 2 GB si harás B5), **Ubuntu** de las clases 3 y 4 (2 GB) y **Kali** (2–3 GB). En la Parte A, pfSense puede estar apagado.
- El **PC físico** (tu Windows/Linux) es el **PC del administrador**: desde él entras por SSH al Ubuntu y manejas la GUI de pfSense. **No administres desde Kali:** Kali es el atacante.
- Reemplaza **`IP_UBUNTU`** (Parte A), **`IP_WAN_PF`** (IP WAN que pfSense recibe por DHCP) e **`IP_KALI`** por tus valores.
- **Snapshots:** Ubuntu → `antes-calentamiento-fw` (A0) · pfSense → `pfsense-limpio` (B0.3) y `antes-hardening` (inicio de B2).
- **Regla de oro anti-bloqueo** (vale para los tres firewalls): antes de quitar lo que te permite entrar, crea lo que lo reemplaza y **pruébalo en otra ventana**.
- Bloques `# 🐉 En Kali` → Kali. `# 🐧 En Ubuntu` → Ubuntu. `# 💻 En el PC` → tu PC. Las instrucciones `GUI ›` son clics en pfSense. Los bloques sin marca en la Parte A van en el Ubuntu.
- Rutas en `/home/brian/`: cámbialas si tu usuario es otro.

### Topología

**Parte A** (pfSense apagado): el Ubuntu sigue en la red NAT junto a Kali.

```
   Red NAT "LabSENATI" (10.0.2.0/24)
   ┌──────────────┐              ┌───────────────────────┐
   │ Kali         │ ──escanea──▶ │ Ubuntu 22.04 (C3/C4)  │ ◀── SSH desde el PC admin
   │ IP_KALI      │              │ IP_UBUNTU             │
   └──────────────┘              │ iptables / firewalld  │
                                 └───────────────────────┘
```

**Parte B:** el Ubuntu se muda a la DMZ detrás de pfSense.

```
                    Red NAT "LabSENATI" (10.0.2.0/24) = "Internet" del lab
                 ┌──────────────┐
                 │ Kali         │  atacante externo
                 │ IP_KALI      │
                 └──────┬───────┘
                        │ WAN (em0, DHCP → IP_WAN_PF)
                 ┌──────┴───────┐
   PC admin ─────┤   pfSense    ├────── DMZ (em2) 172.16.20.0/24
 192.168.56.1    │  CE 2.8.x    │       red interna "dmz-senati"
   LAN (em1)     └──────────────┘       │
 Host-Only 192.168.56.0/24              ┌┴──────────────────────────┐
 pfSense = 192.168.56.10                │ Ubuntu 22.04 (C3/C4)      │
                                        │ 172.16.20.10  SSH, BD,     │
                                        │ syslog central             │
                                        └───────────────────────────┘
```

| Segmento | Adaptador VirtualBox | Red | pfSense | Equipos |
|---|---|---|---|---|
| WAN | Adaptador 1: Red NAT `LabSENATI` | 10.0.2.0/24 (DHCP) | `IP_WAN_PF` | Kali (`IP_KALI`) |
| LAN | Adaptador 2: Solo-anfitrión (Host-Only), **sin DHCP de VirtualBox** | 192.168.56.0/24 | 192.168.56.10 | PC admin 192.168.56.1 |
| DMZ | Adaptador 3: Red interna `dmz-senati` | 172.16.20.0/24 | 172.16.20.1 | Ubuntu 172.16.20.10 |

### Agenda (120 min)

| Parte | Bloque | Qué haces | Min | Si vas corto de tiempo → tarea |
|---|---|---|---|---|
| A | A0 | Snapshot, desactivar ufw, **batería 1: sin firewall** | 8 | — |
| A | A1 | iptables a mano + **batería 2** | 15 | A1.8 (IPv6) |
| A | A2 | firewalld con zonas y políticas + **batería 3** | 12 | A2.5 |
| B | B0 | Topología, Ubuntu a la DMZ, "errores típicos" | 20 | — |
| B | B1 | Medir ANTES: **batería 4** + vista desde la DMZ | 10 | B1.1–B1.2 (auditor) |
| B | B2 | Hardening del **equipo** pfSense | 25 | B2.2 (certificado), B2.7 (syslog) |
| B | B3 | Hardening de las **reglas**: alias, LAN, DMZ, publicación mínima | 25 | — |
| B | B4 | **Batería 5** + tabla comparativa | 5 | B4.1 (auditor), B4.3 (syslog) |
| — | Entrega | Evidencias al repositorio | tarea | — |
| — | B5 | **Opcional / tarea:** Suricata (IDS) | 20 | — |

---

## Teoría mínima (para leer en 3 minutos)

| Concepto | En una línea |
|---|---|
| **Netfilter** | El motor de firewall del kernel Linux; iptables, nftables, ufw y firewalld son solo formas de darle órdenes. |
| **Cadenas** | `INPUT` = lo que entra al servidor · `OUTPUT` = lo que sale del servidor · `FORWARD` = lo que solo pasa a través (router/firewall). |
| **Política por defecto** | Qué pasa con un paquete que no coincide con ninguna regla (`ACCEPT` o `DROP`). Lo seguro es `DROP`. |
| **Primera coincidencia** | Las reglas se evalúan de arriba hacia abajo y la primera que coincide decide. El orden importa. |
| **Con estado (conntrack)** | El kernel recuerda las conexiones. Basta con permitir el paquete `NEW` y las respuestas pasan como `ESTABLISHED`. |
| **DROP vs REJECT** | `DROP` no responde (el atacante espera hasta el timeout). `REJECT` responde "prohibido" (es más rápido de diagnosticar, pero confirma que hay un firewall). |
| **iptables en 22.04** | En Ubuntu 22.04, el comando `iptables` es en realidad **iptables-nft**: escribe reglas nftables con la sintaxis antigua. |
| **firewalld** | Trabaja por **zonas** (niveles de confianza) asignadas por interfaz o por **origen**. Distingue configuración *runtime* de *permanent*. |

**Equivalencias que veremos hoy:**

| Idea | iptables | firewalld | pfSense |
|---|---|---|---|
| "Esta red es de confianza" | `-s RED -j ACCEPT` | zona por origen (`--add-source`) | interfaz LAN / alias |
| Bloquear el resto | `-P INPUT DROP` | target de la zona (reject por defecto) | regla implícita *Default deny* |
| Limitar fuerza bruta SSH | `-m recent` | rich rule con `limit` | sshguard |
| Controlar la salida | `OUTPUT` + `-m owner` | política `HOST → ANY` | reglas en la interfaz LAN/DMZ |
| Ver lo bloqueado | `-j LOG` + `journalctl -k` | `--set-log-denied` | Status → System Logs → Firewall |

---

# PARTE A · Firewall de host en el Ubuntu (35 min)

## A0 · Preparación y línea base (8 min)

**Requisitos:**
- La VM Ubuntu 22.04 de las clases 3/4, **todavía en la red NAT LabSENATI** junto con Kali. La Parte A se hace **antes** de la Parte B, porque en B0.2 el Ubuntu se muda a la DMZ.
- pfSense puede quedar apagado durante toda la Parte A.
- Conéctate por SSH **desde tu PC anfitrión, no desde Kali**. Kali es el "atacante" y debe quedar fuera de las excepciones. Si no tienes SSH desde el anfitrión, usa la consola de VirtualBox.

### A0.1 En VirtualBox

1. Toma un snapshot del Ubuntu llamado **`antes-calentamiento-fw`**. Al final volveremos a él.

### A0.2 En el Ubuntu

```bash
# Ver la IP y la red del Ubuntu (anota la IP y el /24 de la interfaz de la red NAT)
ip -brief address

# Ver desde qué IP estás conectado por SSH (primer campo = IP del administrador)
echo $SSH_CLIENT
```

Define tres variables con **tus** valores. Solo viven en esta terminal: si abres otra, vuelve a definirlas.

```bash
# Red del laboratorio (donde están Ubuntu y Kali)
RED_LAB=10.0.2.0/24
# IP desde donde administras (el primer campo de $SSH_CLIENT)
IP_ADMIN=10.0.2.2
# IP de Kali
IP_KALI=10.0.2.4
```

```bash
# Ver el estado del firewall que dejamos en la clase 3 (ufw con salida restringida)
sudo ufw status verbose

# Desactivar ufw: hoy construimos el firewall a mano y no deben convivir dos gestores
sudo ufw disable

# Confirmar que las políticas quedaron en ACCEPT (las 3 primeras líneas deben decir -P ... ACCEPT)
sudo iptables -S | head -3

# Lo mismo para IPv6 (iptables NO cubre IPv6, es otra tabla)
sudo ip6tables -S | head -3

# Servicio web de demostración en el puerto 8080 (simula un servicio que NO debería verse desde fuera)
nohup python3 -m http.server 8080 --directory /tmp > /dev/null 2>&1 &

# Confirmar qué escucha el servidor
sudo ss -tlnp
```

### A0.3 En Kali

Copia `kali/pruebas-firewall.sh` a Kali (con `scp`, una carpeta compartida o pegándolo en `nano`). Es la **misma batería** que usarás 5 veces en la clase.

```bash
# Primera corrida: línea base sin firewall (reemplaza IP_UBUNTU por la IP del Ubuntu)
sudo bash pruebas-firewall.sh IP_UBUNTU sin-firewall
```

Cuando el script llegue a **[P5]**, mostrará un comando. Ejecútalo **en el Ubuntu** dentro de los siguientes 60 s:

```bash
# Simula una "reverse shell": el usuario del servidor web intenta abrir una conexión hacia Kali
echo SALIDA-www-data | sudo -u www-data nc -w 3 $IP_KALI 4444
```

**Qué hace cada prueba:**

| Prueba | Qué mide |
|---|---|
| P1 `nmap -sS --reason` | Qué puertos TCP se ven y **por qué** (respuesta del host o silencio) |
| P2 `nmap -sA` | Si el firewall es **con estado**: `unfiltered` significa que un ACK suelto llega al host |
| P3 `nmap -sU` | Servicios UDP (DNS, NTP, SNMP) |
| P4 ping | Si el servidor responde ICMP |
| P5 salida | Si `www-data` puede abrir una conexión hacia afuera (control de **egress**) |
| P6 10 conexiones SSH | Si hay límite contra fuerza bruta |

---

## A1 · iptables (15 min)

### A1.1 Red de seguridad (para no perder la sesión SSH)

```bash
# Carpeta de trabajo
mkdir -p /home/brian/fw

# Respaldo del estado actual (sin reglas, todo ACCEPT)
sudo iptables-save > /home/brian/fw/backup-antes.v4

# Temporizador: si en 15 min no lo cancelas, restaura el respaldo automáticamente (sobrevive aunque se corte el SSH)
sudo systemd-run --on-active=15min --unit=fw-rollback /usr/sbin/iptables-restore /home/brian/fw/backup-antes.v4

# Ver que el temporizador está armado
systemctl list-timers fw-rollback.timer
```

### A1.2 Mirar antes de tocar

```bash
# Las 3 cadenas de la tabla filter, con contadores (-v), sin resolver nombres (-n) y numeradas
sudo iptables -L -v -n --line-numbers
```

### A1.3 Construir las reglas de entrada, **en este orden**

```bash
# 1) Todo lo que viene de la propia máquina (loopback) se permite: muchos servicios hablan entre sí por 127.0.0.1
sudo iptables -A INPUT -i lo -j ACCEPT

# 2) Respuestas a conexiones ya aceptadas: esta regla hace al firewall "con estado"
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 3) Paquetes que no encajan en ninguna conexión válida: se descartan
sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# 4) Una conexión "nueva" que no empieza con SYN es anómala (típico de escaneos ACK/FIN): se descarta
sudo iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# 5) Ping permitido, pero limitado a 2 por segundo (diagnóstico sí, inundación no)
sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 2/second -j ACCEPT

# 6) El administrador entra por SSH sin límite (va ANTES del límite, por eso el orden importa)
sudo iptables -A INPUT -p tcp --dport 22 -s $IP_ADMIN -j ACCEPT

# 7) Anotar cada conexión SSH nueva desde la red del lab en la lista "SSH" (por IP de origen)
sudo iptables -A INPUT -p tcp --dport 22 -s $RED_LAB -m conntrack --ctstate NEW -m recent --name SSH --set

# 8) Si esa IP ya hizo 5 intentos en 60 s, dejar constancia en el log...
sudo iptables -A INPUT -p tcp --dport 22 -s $RED_LAB -m conntrack --ctstate NEW -m recent --name SSH --update --seconds 60 --hitcount 5 -j LOG --log-prefix "FW-IPT-SSH-RATE: "

# 9) ...y descartarla
sudo iptables -A INPUT -p tcp --dport 22 -s $RED_LAB -m conntrack --ctstate NEW -m recent --name SSH --update --seconds 60 --hitcount 5 -j DROP

# 10) Si no superó el límite, se permite SSH desde la red del lab
sudo iptables -A INPUT -p tcp --dport 22 -s $RED_LAB -m conntrack --ctstate NEW -j ACCEPT

# 11) Registrar lo que se va a bloquear (máximo 5 líneas por minuto para no llenar el disco)
sudo iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "FW-IPT-IN: "
```

### A1.4 Cerrar la puerta (recién ahora)

```bash
# Política por defecto: lo que no coincidió con ninguna regla se descarta
sudo iptables -P INPUT DROP
```

> ⚠️ **No cierres esta ventana.** Abre **otra** ventana y conéctate por SSH. Si entra, todo está bien. Si no entra, espera al temporizador o usa la consola de VirtualBox.

```bash
# Ya comprobaste que el SSH nuevo funciona: cancela el temporizador para que no borre tus reglas a mitad de la prueba
sudo systemctl stop fw-rollback.timer
```

### A1.5 Control de salida (egress) por usuario

```bash
# Registrar cuando el usuario del servidor web (www-data) intenta abrir una conexión NUEVA hacia afuera
sudo iptables -A OUTPUT -m owner --uid-owner www-data -m conntrack --ctstate NEW -j LOG --log-prefix "FW-IPT-OUT-WWW: "

# Y rechazarla: si comprometen la web, no podrán abrir una reverse shell (las respuestas a visitantes siguen funcionando porque son ESTABLISHED)
sudo iptables -A OUTPUT -m owner --uid-owner www-data -m conntrack --ctstate NEW -j REJECT
```

### A1.6 Ver el resultado

```bash
# Reglas en formato de comando (fácil de copiar y comparar)
sudo iptables -S

# Reglas numeradas con contadores de paquetes: deben subir cuando Kali escanee
sudo iptables -L INPUT -v -n --line-numbers
```

### A1.7 Experimento: el orden importa

```bash
# Insertar (-I) en la posición 1 una regla que bloquea a Kali: queda ANTES de todas las demás
sudo iptables -I INPUT 1 -s $IP_KALI -j DROP
```

En **Kali**:

```bash
# Debe fallar: la regla 1 gana aunque más abajo haya un ACCEPT para SSH
nc -zv -w 2 IP_UBUNTU 22
```

En el **Ubuntu**:

```bash
# Borrar la regla número 1
sudo iptables -D INPUT 1
```

### A1.8 IPv6: la puerta trasera que se olvida

```bash
# Loopback IPv6 permitido
sudo ip6tables -A INPUT -i lo -j ACCEPT

# Respuestas a conexiones propias
sudo ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ICMPv6 es obligatorio en IPv6 (descubrimiento de vecinos, equivalente a ARP): si se bloquea, la red IPv6 deja de funcionar
sudo ip6tables -A INPUT -p ipv6-icmp -j ACCEPT

# Todo lo demás por IPv6, descartado
sudo ip6tables -P INPUT DROP
```

### A1.9 Re-medir desde Kali

```bash
sudo bash pruebas-firewall.sh IP_UBUNTU iptables
```

En [P5], ejecuta de nuevo en el Ubuntu el `echo SALIDA-www-data | sudo -u www-data nc ...`.

### A1.10 El lado del defensor: logs

```bash
# Mensajes del kernel con nuestros prefijos (escaneo de Kali, límite SSH, salida de www-data)
sudo journalctl -k --since "15 min ago" | grep FW-IPT

# Ver la lista de IPs que el módulo recent está vigilando para SSH
sudo cat /proc/net/xt_recent/SSH
```

### A1.11 Guardar y limpiar

```bash
# Guardar las reglas en un archivo (es la "foto" que se entrega)
sudo iptables-save > /home/brian/fw/reglas-iptables.v4

# OJO: en Ubuntu, instalar iptables-persistent DESINSTALA ufw. Hoy no lo instalamos: volveremos al snapshot.

# Opcional: ver cómo iptables-nft tradujo tus reglas a nftables (si falta: sudo apt install -y nftables, sin habilitar su servicio)
sudo nft list ruleset | less

# Limpiar para pasar a firewalld: primero abrir la política, luego borrar las reglas (al revés te quedas fuera)
sudo iptables -P INPUT ACCEPT
sudo iptables -F
sudo ip6tables -P INPUT ACCEPT
sudo ip6tables -F

# Confirmar que no queda nada
sudo iptables -S
```

---

## A2 · firewalld (12 min)

> No deben convivir reglas de iptables y de firewalld: un paquete tendría que pasar **ambas**, y nadie entendería por qué algo se bloquea. Por eso limpiamos antes.

### A2.1 Instalar y mirar

```bash
# Instalar firewalld (en Ubuntu se habilita y arranca solo; su zona por defecto permite SSH, así que no se corta la sesión)
sudo apt install -y firewalld

# ¿Está corriendo?
sudo firewall-cmd --state

# Red de seguridad: si en 15 min no lo cancelas, detiene firewalld (y con eso se quitan todas sus reglas)
sudo systemd-run --on-active=15min --unit=fwd-rollback /usr/bin/systemctl stop firewalld

# Zona por defecto: la que se aplica a todo lo que no tiene zona asignada
sudo firewall-cmd --get-default-zone

# Qué permite la zona public de fábrica
sudo firewall-cmd --zone=public --list-all

# Zonas que vienen de fábrica (cada una es un nivel de confianza)
sudo firewall-cmd --get-zones
```

### A2.2 Zonas por origen (en pfSense esto serán las interfaces)

```bash
# Todo lo que venga de la red del lab cae en la zona "internal"
sudo firewall-cmd --permanent --zone=internal --add-source=$RED_LAB

# El administrador también cae en "internal" (si ya está dentro de RED_LAB no pasa nada, la /32 es más específica)
sudo firewall-cmd --permanent --zone=internal --add-source=$IP_ADMIN/32

# Ver qué servicios trae "internal" de fábrica (vienen demasiados)
sudo firewall-cmd --permanent --zone=internal --list-services
```

```bash
# Quitar los servicios de fábrica de internal (se ponen uno por uno: este for es solo para no repetir 4 líneas)
for s in ssh mdns samba-client dhcpv6-client; do sudo firewall-cmd --permanent --zone=internal --remove-service=$s; done

# El administrador entra por SSH sin límite
sudo firewall-cmd --permanent --zone=internal --add-rich-rule="rule family=\"ipv4\" source address=\"$IP_ADMIN\" service name=\"ssh\" accept"

# El resto de la red del lab entra por SSH con límite: 3 por minuto (ráfaga de 5). El límite va DESPUÉS de accept
sudo firewall-cmd --permanent --zone=internal --add-rich-rule='rule service name="ssh" accept limit value="3/m"'

# La zona public (el resto del mundo) ya no ofrece SSH
sudo firewall-cmd --permanent --zone=public --remove-service=ssh
sudo firewall-cmd --permanent --zone=public --remove-service=dhcpv6-client

# Registrar en el log todo lo rechazado (esta opción es permanente por sí sola, no lleva --permanent)
sudo firewall-cmd --set-log-denied=unicast

# Aplicar la configuración permanente
sudo firewall-cmd --reload

# Ver qué zonas están activas y con qué orígenes
sudo firewall-cmd --get-active-zones

# Ver la zona internal completa
sudo firewall-cmd --zone=internal --list-all
```

> ⚠️ Abre **otra** ventana SSH. Si entra:

```bash
# Cancelar la red de seguridad
sudo systemctl stop fwd-rollback.timer
```

> **Ojo con el `limit` en rich rules:** si lo escribes junto a `log` (`log ... limit value=...`), limita **cuántas líneas se registran**, no las conexiones. Para limitar conexiones, el `limit` va **después de `accept`**.

### A2.3 Experimento: runtime vs permanent

```bash
# Abrir el 8080 SIN --permanent: aplica al instante, pero solo en memoria
sudo firewall-cmd --zone=internal --add-port=8080/tcp
```

En **Kali**: `sudo nmap -sS -Pn -p 8080 IP_UBUNTU` → **open**.

```bash
# Recargar: se vuelve a leer la configuración permanente y lo que estaba solo en memoria desaparece
sudo firewall-cmd --reload
```

En **Kali**: repite el nmap → **filtered**.
(Si un cambio en runtime te sirvió y quieres conservarlo: `sudo firewall-cmd --runtime-to-permanent`.)

### A2.4 Control de salida con una política

firewalld no filtra por usuario como `-m owner`. Lo que hace es controlar **qué puede salir del servidor (HOST) hacia cualquier zona (ANY)**: la misma idea de la clase 3 con ufw (`deny outgoing`).

```bash
# Crear una política para el tráfico que SALE del propio servidor
sudo firewall-cmd --permanent --new-policy=salida-host

# Origen: el propio host
sudo firewall-cmd --permanent --policy=salida-host --add-ingress-zone=HOST

# Destino: cualquier zona
sudo firewall-cmd --permanent --policy=salida-host --add-egress-zone=ANY

# Lo que no esté permitido explícitamente, se rechaza
sudo firewall-cmd --permanent --policy=salida-host --set-target=REJECT

# Permitir solo lo necesario para operar: DNS, actualizaciones (http/https) y hora (ntp)
for s in dns http https ntp; do sudo firewall-cmd --permanent --policy=salida-host --add-service=$s; done

# Aplicar
sudo firewall-cmd --reload

# Ver la política
sudo firewall-cmd --info-policy=salida-host

# Comprobar que las actualizaciones siguen funcionando (usa http/https)
sudo apt update
```

### A2.5 Mirar debajo del capó

```bash
# firewalld NO usa iptables: debe salir vacío (solo políticas ACCEPT)
sudo iptables -S

# Usa su propia tabla nftables (busca la regla del puerto 22 con su límite)
sudo nft list table inet firewalld | grep -E "dport 22|limit"
```

### A2.6 Re-medir desde Kali

```bash
sudo bash pruebas-firewall.sh IP_UBUNTU firewalld
```

En [P5], ejecuta de nuevo en el Ubuntu el comando de salida. Prueba también **como root** (`echo SALIDA-root | nc -w 3 $IP_KALI 4444`, con Kali escuchando con `nc -lvnp 4444`) y compara con lo que pasaba en iptables.

```bash
# Logs de lo rechazado por firewalld (prefijo automático tipo filter_IN_public_REJECT)
sudo journalctl -k --since "15 min ago" | grep -E "REJECT|DROP"
```

### A2.7 Cierre de la Parte A

```bash
# Guardar la configuración de firewalld como evidencia (zonas y política de salida)
sudo firewall-cmd --list-all-zones > /home/brian/fw/firewalld-zonas.txt
sudo firewall-cmd --info-policy=salida-host > /home/brian/fw/firewalld-politica-salida.txt
```

```bash
# 💻 En el PC: llévate la carpeta de evidencias ANTES de restaurar el snapshot (el snapshot la borra)
# (si entras por un puerto reenviado, agrega -P <puerto>)
scp -r brian@IP_UBUNTU:/home/brian/fw .
```

```bash
# 🐧 En Ubuntu: detener firewalld y que no arranque en el próximo boot
sudo systemctl disable --now firewalld
```

En VirtualBox: **restaura el snapshot `antes-calentamiento-fw`** del Ubuntu. Vuelve con ufw y el endurecimiento de las clases 3 y 4, listo para mudarse a la DMZ en B0.2.

En Kali, mira cómo va tu tabla (le faltan las columnas de pfSense):

```bash
sudo bash pruebas-firewall.sh comparar
```

> **Puente a pfSense:** lo que hiciste con `-s RED`, zonas por origen y políticas de salida, en pfSense se hace **por interfaz** (LAN, DMZ, WAN). Lo que cambia es la posición: antes protegías **un servidor**; ahora proteges **redes enteras** desde el perímetro.

---

# PARTE B · Firewall perimetral con pfSense (85 min)

## B0 · Topología (20 min)

### B0.1 Asignar interfaces y direcciones (consola de pfSense)

En la consola de la VM pfSense:

1. Opción **1) Assign Interfaces** → VLANs: `n` → WAN: `em0` → LAN: `em1` → Optional 1: `em2` → confirmar `y`.
2. Opción **2) Set interface(s) IP address** → `2` (LAN) → IPv4 `192.168.56.10`, máscara `24`, sin gateway, sin IPv6, **DHCP server: `n`**, revert to HTTP: `n`.
3. Opción **2** otra vez → `3` (OPT1) → IPv4 `172.16.20.1`, máscara `24`, sin gateway, sin IPv6, DHCP: `n`.
4. Anota la IP que muestra la WAN: esa es tu **`IP_WAN_PF`**.

```bash
# 💻 En el PC: comprueba que llegas a la LAN de pfSense (tu PC es 192.168.56.1 en el adaptador Host-Only)
ping 192.168.56.10
```

Abre `https://192.168.56.10` en el navegador del PC → acepta el certificado → usuario `admin`, clave `pfsense`.
Completa el asistente: hostname `fw-senati`, dominio `burgerbank.lab`, zona horaria `America/Lima`, WAN por DHCP,
**desmarca** "Block RFC1918 Private Networks" (la WAN del lab es 10.0.2.0/24; lo discutimos en B4). En el paso de la clave de `admin`, déjala en blanco si el asistente lo permite; si te obliga, escribe `pfsense` otra vez: queremos reproducir el error de fábrica.

`GUI › Interfaces › OPT1` → marca **Enable**, en **Description** escribe `DMZ` → **Save** → **Apply Changes**.

### B0.2 Mover la Ubuntu a la DMZ

> Si vienes de la Parte A, confirma que ya restauraste el snapshot `antes-calentamiento-fw` del Ubuntu.

En VirtualBox, con la Ubuntu **apagada** o en caliente: **Configuración › Red › Adaptador 1 → Red interna `dmz-senati`**. Luego, desde la **consola** de VirtualBox (no por SSH):

```bash
# 🐧 En Ubuntu: identifica el nombre de tu interfaz de red (ej. enp0s3)
ip -br link
# Respaldo de la configuración de red actual
sudo cp /etc/netplan/00-installer-config.yaml /home/brian/00-installer-config.yaml.bak
# IP fija en la DMZ: gateway y DNS = pfSense (reemplaza enp0s3 si tu interfaz se llama distinto)
sudo tee /etc/netplan/00-installer-config.yaml > /dev/null <<'EOF'
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
      addresses: [172.16.20.10/24]
      routes:
        - to: default
          via: 172.16.20.1
      nameservers:
        addresses: [172.16.20.1]
EOF
# netplan exige que el archivo no sea legible por otros
sudo chmod 600 /etc/netplan/00-installer-config.yaml
# 'try' aplica y, si pierdes la red, revierte solo en 120 s (pulsa Enter para confirmar)
sudo netplan try
# Comprueba gateway, DNS y salida a Internet a través de pfSense
ping -c 2 172.16.20.1 ; resolvectl query ubuntu.com ; sudo apt update
```

```bash
# 💻 En el PC: entra por SSH a la Ubuntu de la DMZ a través de pfSense (por ahora la LAN permite todo)
ssh brian@172.16.20.10
```

### B0.3 Snapshot

Toma el snapshot **"pfsense-limpio"** de la VM pfSense.

### B0.4 "Errores típicos" (dejamos el firewall como en muchas empresas)

Hazlos **tal cual**; son errores reales que aparecen en auditorías:

| # | En la GUI | Qué haces | Por qué se hace en la vida real |
|---|---|---|---|
| 1 | `System › Advanced › Admin Access` | Marca **Enable Secure Shell**, SSHd Key Only = **Password or Public Key** → Save | "Para entrar rápido por consola" |
| 2 | `Services › UPnP IGD & NAT-PMP` | Marca **Enable UPnP IGD & NAT-PMP** e **Allow UPnP Port Mapping**, interfaz LAN → Save | "Para que funcione la consola de juegos / la cámara" |
| 3 | `Services › SNMP` | Marca **Enable**, comunidad `public` → Save | "El monitoreo lo pidió" |
| 4 | `Firewall › Rules › WAN › Add` | Pass · TCP · Source **any** · Destination **WAN address** · puerto **HTTPS (443)** · Descripción `GUI desde casa` → Save → Apply | "Para administrar desde casa" |
| 5 | `Firewall › NAT › Port Forward › Add` | Interface WAN · TCP · Source **any** · Destination **WAN address** · puerto **2222** · Redirect target IP **172.16.20.10** · puerto **22** · Descripción `SSH a la DMZ` → Save → Apply | "El proveedor necesita entrar" |
| 6 | `Firewall › Rules › DMZ › Add` | Pass · Protocol **Any** · Source **any** · Destination **any** · sin descripción → Save → Apply | "Para que la DMZ no dé problemas" |

> La clave de `admin` sigue siendo `pfsense`, la regla anti-bloqueo deja entrar a la GUI a toda la LAN y la LAN tiene "permitir todo": son los valores de fábrica.

---

## B1 · Medir ANTES (10 min · B1.1–B1.2 pasan a tarea si vas corto)

### B1.1 Exportar el config.xml

`GUI › Diagnostics › Backup & Restore` → Backup area **All** → **NO** marques "Encrypt this configuration file" → **Download configuration as XML**.
Renómbralo a `config-antes.xml`.

> Ese archivo tiene **toda** la configuración y los **hashes de las contraseñas**. Es confidencial: lo usamos para auditar y luego se borra.

### B1.2 Ejecutar el auditor (en la Ubuntu de la DMZ)

```bash
# 💻 En el PC: copia el auditor y el config.xml a la Ubuntu (Windows trae scp desde Windows 10)
scp auditar-pfsense.py config-antes.xml brian@172.16.20.10:/home/brian/
```

```bash
# 🐧 En Ubuntu: instala bcrypt para que el auditor detecte la clave de fábrica de admin
sudo apt install -y python3-bcrypt
# Carpeta de evidencias de la clase
mkdir -p /home/brian/evidencias-c5
# Audita el config.xml (26 controles) y guarda el reporte en Markdown
python3 /home/brian/auditar-pfsense.py /home/brian/config-antes.xml --lab -o /home/brian/evidencias-c5/pfsense-antes.md
```

> `--lab` marca como **EXC** (excepción documentada) el bloqueo de redes privadas en WAN, porque nuestra "Internet" es 10.0.2.0/24.
> Si tu PC tiene Python, también puedes ejecutar el auditor en el PC.

### B1.3 Vista desde afuera (Kali, en la WAN)

```bash
# 🐉 En Kali: ¿qué publica el firewall hacia "Internet"?
nmap -Pn -sV -p 22,53,80,443,2222 IP_WAN_PF
# La GUI de administración responde desde la WAN (error 4 de la tabla)
curl -sk -o /dev/null -w "GUI desde WAN: HTTP %{http_code}\n" https://IP_WAN_PF/
# El SSH de la DMZ está publicado para cualquiera (error 5)
nc -zv IP_WAN_PF 2222
```

Y la batería de siempre (4.ª corrida). Contra pfSense el SSH publicado es el **2222**, por eso el tercer parámetro.

> **Antes de P5:** el Ubuntu volvió con el ufw de la clase 3, que solo deja salir 53, 80, 443 y 123. Si lo dejas así, P5 mide **al ufw**, no a pfSense. Para medir solo a pfSense, abre ese puerto **temporalmente** (lo cerrarás en B4.2):
>
> ```bash
> # 🐧 En Ubuntu: excepción temporal de salida hacia Kali:4444 (solo para la prueba)
> sudo ufw allow out to IP_KALI port 4444 proto tcp
> ```

```bash
# 🐉 En Kali: batería contra la WAN de pfSense ANTES del hardening
sudo bash pruebas-firewall.sh IP_WAN_PF pfsense-antes 2222
```

En [P5], ejecuta en la **Ubuntu de la DMZ** el comando que muestra el script (`echo SALIDA-www-data | sudo -u www-data nc -w 3 IP_KALI 4444`).

### B1.4 Vista desde la DMZ (¿qué alcanza un servidor comprometido?)

```bash
# 🐧 En Ubuntu: un servidor de la DMZ llega a la GUI del firewall...
curl -sk -o /dev/null -w "GUI desde la DMZ: HTTP %{http_code}\n" https://172.16.20.1/
# ...y a la red de administración (LAN): esto es movimiento lateral
nmap -Pn -p 22,80,443,3389 192.168.56.1 192.168.56.10
# SNMP con la comunidad 'public' responde (error 3): nombre del equipo, interfaces, rutas
sudo nmap -sU -p 161 --script snmp-info,snmp-interfaces 172.16.20.1
```

**Referencia (config de ejemplo `ejemplos/config-ejemplo-inseguro.xml`):** 5 PASS · 21 FAIL (15 obligatorios) · **19 %**.

---

## B2 · Hardening del equipo (25 min · B2.2 y B2.7 pasan a tarea si vas corto)

> **Snapshot "antes-hardening"** ahora. Trabaja con **dos pestañas** de la GUI abiertas: si una se cierra, la otra te salva.

### B2.1 Cuentas: nominal para el día a día, `admin` como cuenta de emergencia (ADM-01, ADM-02)

1. `GUI › System › User Manager › Users › Add`: Username `brian` (tu nombre), contraseña larga, Full name, **Group membership: admins** (muévelo a "Member of") → Save.
2. **Cierra sesión y entra como `brian`.** Si funciona, sigue.
3. `Users › admin › Edit`: cambia la clave por una de 20+ caracteres (en la vida real va a la **bóveda de contraseñas** como "break-glass") → Save.

> No deshabilitamos `admin`: es la cuenta de emergencia y la que usa la consola. Lo que cambia es que **nadie la usa a diario**.

### B2.2 Certificado propio para la GUI (ADM-04)

1. `System › Cert Manager › CAs › Add`: Descriptive name `CA-Interna-BurgerBank`, Method **Create an internal Certificate Authority**, Key RSA 2048+ / SHA256, Common Name `CA-Interna-BurgerBank` → Save.
2. `Certificates › Add/Sign`: Method **Create an internal Certificate**, Descriptive name `GUI fw-senati`, CA `CA-Interna-BurgerBank`, Type **Server Certificate**, Common Name `fw-senati.burgerbank.lab`, Alternative Names: **IP address 192.168.56.10** → Save.
3. `System › Advanced › Admin Access` → **SSL/TLS Certificate: GUI fw-senati** → Save. (Opcional: descarga la CA e impórtala en tu navegador para quitar el aviso.)

### B2.3 Acceso a la GUI: solo desde el PC admin (ADM-05, ADM-08, ADM-09)

Primero **creas** la regla que te deja entrar, **después** quitas la anti-bloqueo:

1. `Firewall › Aliases › IP › Add`: Name `ADMIN_PC`, Type **Host(s)**, IP `192.168.56.1`, descripción `PC del administrador` → Save → Apply.
2. `Firewall › Rules › LAN › Add` (flecha hacia **arriba**, para que quede primera): Pass · TCP · Source **Address or Alias `ADMIN_PC`** · Destination **This Firewall (self)** · puerto **HTTPS (443)** · descripción `GUI solo desde el PC admin` → Save → Apply.
3. `System › Advanced › Admin Access`:
   - Marca **Anti-lockout: Disable webConfigurator anti-lockout rule**.
   - Deja **activados** DNS Rebind Check y Browser HTTP_REFERER enforcement; deja HSTS habilitado.
   - **Login Autocomplete**: desmarcado.
   → Save. **Recarga la GUI en la otra pestaña**: debe seguir funcionando.

### B2.4 Sesión y protección de login (ADM-07, ADM-10)

- `System › User Manager › Settings` → **Session timeout: 15** (minutos) → Save.
- `System › Advanced › Admin Access › Login Protection` → **Threshold: 10**, **Blocktime: 600**, **Detection time: 1800** → Save.

> Login Protection bloquea la IP tras varios fallos en la GUI o SSH. Si te bloqueas: espera 10 min o usa la consola.

### B2.5 SSH y consola (ADM-11, ADM-12)

- `System › Advanced › Admin Access › Secure Shell` → **desmarca Enable Secure Shell** (deshaz el error 1). Si tu empresa lo necesita: **SSHd Key Only: Public Key Only** y solo desde `ADMIN_PC`.
- `System › Advanced › Admin Access › Console Options` → marca **Password protect the console menu** → Save.

### B2.6 Servicios que sobran (SRV-01, SRV-02, SRV-03)

- `Services › UPnP IGD & NAT-PMP` → **desmarca Enable** → Save (deshaz el error 2).
- `Services › SNMP` → **desmarca Enable** → Save (deshaz el error 3). Si se necesita monitoreo: SNMPv3 o comunidad larga y solo hacia la IP del NMS.
- `Services › DNS Resolver › General Settings` → **Network Interfaces: LAN, DMZ, Localhost** (Ctrl+clic; nunca WAN ni All) → Save → Apply.

### B2.7 Logs centralizados en la Ubuntu (LOG-01, LOG-02)

```bash
# 🐧 En Ubuntu: rsyslog recibirá los logs de pfSense por UDP 514 y los guardará aparte
sudo tee /etc/rsyslog.d/10-pfsense.conf > /dev/null <<'EOF'
# Recibe los logs de pfSense por UDP 514 y los guarda aparte
module(load="imudp")
input(type="imudp" port="514")
if $fromhost-ip == "172.16.20.1" then {
    action(type="omfile" file="/var/log/pfsense.log")
    stop
}
EOF
# Permisos de lectura para el servicio (la VM tiene umask 027 desde la Clase 3)
sudo chmod 644 /etc/rsyslog.d/10-pfsense.conf
# Valida la sintaxis antes de reiniciar
sudo rsyslogd -N1
# Aplica la configuración
sudo systemctl restart rsyslog
# ufw de la Clase 3: acepta syslog SOLO desde el firewall
sudo ufw allow from 172.16.20.1 to any port 514 proto udp
```

`GUI › Status › System Logs › Settings`:
- Verifica que **Log firewall default blocks › Log packets matched from the default block rules** esté **marcado** (los bloqueos por defecto deben registrarse).
- **Remote Logging Options:** marca **Enable Remote Logging**, Source Address **DMZ**, IP Protocol IPv4, Remote log servers `172.16.20.10:514`, Remote Syslog Contents **Everything** → Save.

```bash
# 🐧 En Ubuntu: deben empezar a llegar líneas de filterlog, nginx (GUI), sshguard...
sudo tail -f /var/log/pfsense.log
```

### B2.8 Hora, actualizaciones y respaldo (SRV-04 + controles manuales)

- `System › General Setup` → Time servers: `0.pe.pool.ntp.org 1.pe.pool.ntp.org` → Save.
- `System › Update` → confirma que estás en la última versión de la rama estable; `System › Package Manager` → desinstala lo que no uses.
- `Diagnostics › Backup & Restore` → marca **Encrypt this configuration file**, contraseña fuerte → descarga `respaldo-cifrado.xml`. **Así se guardan los respaldos** (el `config-antes.xml` en claro solo existe para auditar).

---

## B3 · Hardening de las reglas (25 min)

### B3.1 Alias (REG-08)

`Firewall › Aliases`:

| Pestaña | Name | Type | Contenido | Descripción |
|---|---|---|---|---|
| IP | `SRV_DMZ` | Host(s) | `172.16.20.10` | Ubuntu de las clases 3 y 4 |
| IP | `KALI_EXTERNO` | Host(s) | `IP_KALI` | Proveedor externo autorizado (simulado) |
| IP | `RED_PRIVADA` | Network(s) | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 |
| Ports | `PUERTOS_WEB` | Port(s) | `80`, `443` | HTTP y HTTPS |

### B3.2 WAN: nada de GUI, publicación mínima (ADM-06, REG-05)

1. `Firewall › Rules › WAN` → **borra** la regla `GUI desde casa` → Apply.
2. `Firewall › NAT › Port Forward` → edita `SSH a la DMZ` → **Source: Address or Alias `KALI_EXTERNO`** (despliega "Display Advanced" si no ves Source) → Redirect target IP: **`SRV_DMZ`** → descripción `SSH a la DMZ solo desde KALI_EXTERNO` → Save → Apply.
3. `Firewall › Rules › WAN` → abre la regla asociada al NAT → marca **Log packets** → Save → Apply.

> En producción no se publica SSH: se usa una **VPN con MFA**. Aquí sirve para ver cómo se restringe un servicio publicado.

### B3.3 LAN: filtrado de salida (REG-03)

`Firewall › Rules › LAN`, debajo de `GUI solo desde el PC admin` agrega (en este orden):

| # | Acción | Proto | Origen | Destino | Puerto | Descripción | Log |
|---|---|---|---|---|---|---|---|
| 2 | Pass | TCP/UDP | LAN net | This Firewall (self) | 53 (DNS) | DNS hacia pfSense | — |
| 3 | Pass | TCP | LAN net | any | `PUERTOS_WEB` | Navegación web | — |
| 4 | Pass | ICMP (echo request) | LAN net | any | — | Ping de diagnóstico | — |
| 5 | Pass | TCP | `ADMIN_PC` | `SRV_DMZ` | 22 (SSH) | SSH del admin a los servidores de la DMZ | — |
| 6 | Block | Any | LAN net | any | — | Bloquear y registrar el resto de la LAN | ✅ |

Luego **deshabilita** (no borres todavía) las dos reglas `Default allow LAN to any rule` (IPv4 e IPv6) → Apply.
Prueba que navegas y que tu SSH a la Ubuntu sigue vivo; si todo va bien, bórralas.

### B3.4 DMZ: aislada de las redes internas (REG-04, REG-06, REG-07)

`Firewall › Rules › DMZ` → **borra** la regla "permitir todo" sin descripción (error 6) y crea, en este orden:

| # | Acción | Proto | Origen | Destino | Puerto | Descripción | Log |
|---|---|---|---|---|---|---|---|
| 1 | Pass | TCP/UDP | DMZ net | This Firewall (self) | 53 (DNS) | DNS hacia pfSense | — |
| 2 | Pass | UDP | DMZ net | This Firewall (self) | 123 (NTP) | NTP hacia pfSense | — |
| 3 | Block | Any | DMZ net | `RED_PRIVADA` | — | La DMZ no inicia conexiones hacia redes internas | ✅ |
| 4 | Pass | TCP | DMZ net | any | `PUERTOS_WEB` | Actualizaciones de los servidores | — |
| 5 | Block | Any | DMZ net | any | — | Bloquear y registrar el resto de la DMZ | ✅ |

> Ubuntu sincroniza la hora con `ntp.ubuntu.com`, que la regla 5 bloquea. Haz que use pfSense:
> `sudo sed -i 's/^#\?NTP=.*/NTP=172.16.20.1/' /etc/systemd/timesyncd.conf && sudo systemctl restart systemd-timesyncd && timedatectl timesync-status`

> **Orden:** las reglas 1 y 2 van antes que la 3 porque 172.16.20.1 (pfSense) también es una IP privada.
> Las **respuestas** a conexiones permitidas (tu SSH desde la LAN, el NAT desde Kali) siempre vuelven: pf es *stateful*.

---

## B4 · Medir DESPUÉS y mirar desde afuera (5 min · B4.1 y B4.3 pasan a tarea si vas corto)

### B4.1 Auditor

Exporta de nuevo (`Diagnostics › Backup & Restore`, sin cifrar) como `config-despues.xml` y cópialo a la Ubuntu.

```bash
# 🐧 En Ubuntu: auditoría después del hardening
python3 /home/brian/auditar-pfsense.py /home/brian/config-despues.xml --lab -o /home/brian/evidencias-c5/pfsense-despues.md
# Compara antes y después solo en las columnas ID y Resultado
diff <(cut -d'|' -f2,5 /home/brian/evidencias-c5/pfsense-antes.md) <(cut -d'|' -f2,5 /home/brian/evidencias-c5/pfsense-despues.md)
# Borra los config.xml en claro: ya cumplieron su función
shred -u /home/brian/config-antes.xml /home/brian/config-despues.xml
```

**Referencia (config de ejemplo `ejemplos/config-ejemplo-endurecido.xml`):** 25 PASS · 0 FAIL · 1 EXC · **100 %**.

### B4.2 Desde Kali (WAN)

```bash
# 🐉 En Kali: la GUI ya no responde desde la WAN (timeout = filtrado)
curl -sk -m 5 -o /dev/null -w "GUI desde WAN: HTTP %{http_code}\n" https://IP_WAN_PF/
# Solo 2222 abierto (y solo para Kali); el resto filtrado
nmap -Pn -p 22,53,80,443,2222 IP_WAN_PF
# El servicio publicado funciona para el origen autorizado
ssh -p 2222 brian@IP_WAN_PF
```

```bash
# 🐉 En Kali: la batería por 5.ª y última vez
sudo bash pruebas-firewall.sh IP_WAN_PF pfsense-despues 2222
# La tabla final: sin firewall → iptables → firewalld → pfSense antes → pfSense después
sudo bash pruebas-firewall.sh comparar | tee ~/comparacion-firewalls.md
```

```bash
# 🐧 En Ubuntu: terminada la batería 5, cierra la excepción temporal de B1.3 (el ufw vuelve a ser tu segunda capa)
sudo ufw delete allow out to IP_KALI port 4444 proto tcp
```

> Prueba de restricción por origen: cambia temporalmente el alias `KALI_EXTERNO` a otra IP (ej. `10.0.2.99`), Apply, y repite el `ssh -p 2222`: debe quedarse colgado. Luego regrésalo a `IP_KALI`.

### B4.3 Desde la DMZ

```bash
# 🐧 En Ubuntu: la GUI del firewall ya no es alcanzable desde la DMZ
curl -sk -m 5 -o /dev/null -w "GUI desde la DMZ: HTTP %{http_code}\n" https://172.16.20.1/
# La LAN de administración ya no es alcanzable (filtered)
nmap -Pn -p 22,80,443,3389 192.168.56.1 192.168.56.10
# Pero DNS, NTP y actualizaciones siguen funcionando
resolvectl query ubuntu.com ; sudo apt update
# Y cada intento bloqueado quedó registrado en tu syslog central (solo si hiciste B2.7)
sudo grep -c "block" /var/log/pfsense.log ; sudo grep "172.16.20.10" /var/log/pfsense.log | tail -3
```

`GUI › Status › System Logs › Firewall`: busca los bloqueos con la descripción `La DMZ no inicia conexiones hacia redes internas`.

### B4.4 Discusión: lo que el auditor no ve

| Tema | Por qué el auditor no lo mide | Cómo se evidencia |
|---|---|---|
| Versión y parches | No está en el config.xml | Captura de `System › Update` |
| Respaldo cifrado y probado | Ocurre fuera del equipo | Archivo cifrado + prueba de restauración en una VM |
| Bloqueo de redes privadas en WAN (EXC) | La WAN del lab es privada | En producción: activarlo siempre |
| Acceso físico / consola de la VM | Depende del hipervisor | Permisos en VirtualBox / vCenter |
| Revisión periódica de reglas | Es un proceso | Acta trimestral, reglas con fecha y dueño en la descripción |

---

## Resultados de referencia: la tabla de 5 columnas

Así debería verse `pruebas-firewall.sh comparar` (filas principales). Las columnas **sin-firewall, iptables y firewalld** se midieron con Ubuntu 22.04 (iptables 1.8.7 nf_tables, firewalld 1.1.1) y nmap 7.94. Las de **pfSense** son el resultado **esperado** según las reglas del laboratorio: confírmalas con tu propia corrida.

| Prueba | sin-firewall | iptables | firewalld | pfsense-antes *(esperado)* | pfsense-despues *(esperado)* |
|---|---|---|---|---|---|
| P1 SSH (22 / 2222) | open | open | open | 2222 open (cualquiera) | 2222 open (solo `KALI_EXTERNO`) |
| P1 443/tcp | closed (reset) | filtered (no-response) | filtered (admin-prohibited) | **open** (GUI desde la WAN) | filtered (no-response) |
| P1 8080, 3306, 6379… | 8080 **open**, resto closed | filtered (no-response) | filtered (admin-prohibited) | filtered (no-response) | filtered (no-response) |
| P2 ACK al SSH | unfiltered | **filtered** | unfiltered | filtered | filtered |
| P4 ping | responde | responde (limitado) | responde | no responde | no responde |
| P5 salida hacia Kali:4444 † | **LLEGÓ** | no llegó (`-m owner`) | no llegó (política HOST→ANY) | **LLEGÓ** (DMZ "permitir todo") | no llegó (DMZ → `RED_PRIVADA` bloqueado) |
| P6 límite SSH | sin límite | bloquea desde ~5 (por IP) | bloquea desde ~6 (global) | sin límite* | **sin límite*** |

\* Salvo que el ufw de tu clase 3 use `ufw limit` para SSH: en ese caso el límite lo pone **el propio Ubuntu**, no pfSense.

† Con la excepción temporal de ufw de B1.3. Sin ella, ambas columnas de pfSense dirían "no llegó" porque el ufw del Ubuntu lo detiene **aunque pfSense lo permita**. Eso es defensa en profundidad (ver la pregunta de cierre).

> **Lectura de la última fila:** en pfSense, *Login Protection* (sshguard) protege al **propio firewall** (su GUI y su SSH), no a los servidores publicados por NAT. Por eso el 2222 sigue sin límite.
>
> **Reto (opcional, no probado en el laboratorio de referencia):** `Firewall › Rules › WAN` → edita la regla asociada al NAT `SSH a la DMZ` → **Display Advanced** → **Max. src. conn. Rate** `4` y **Max. src. conn. Rates** `60` (4 conexiones nuevas por IP cada 60 s) → Save → Apply. Repite solo la batería 5 con la etiqueta `pfsense-reto` y compara la fila P6 con la de iptables.

---

## Entrega (tarea)

Sube a tu fork, carpeta `entregas/clase-05/<tu-apellido>/`:

1. `comparacion-firewalls.md`: la tabla de 5 columnas (`sudo bash pruebas-firewall.sh comparar` en Kali).
2. Carpeta `fw/` de la Parte A: `reglas-iptables.v4`, `firewalld-zonas.txt`, `firewalld-politica-salida.txt`.
3. Si hiciste el auditor: `pfsense-antes.md` y `pfsense-despues.md`.
4. Capturas de pfSense: reglas LAN, reglas DMZ, NAT, Admin Access y, si hiciste B2.7, el `tail` de `/var/log/pfsense.log`.
5. `respuestas.md` con las preguntas de las dos partes.

### Preguntas · Parte A (firewall de host)

1. ¿Por qué el 8080 sale `no-response` con iptables y `admin-prohibited` con firewalld? ¿Cuál prefieres para un servidor expuesto a internet y por qué?
2. En P2, iptables marca el 22 como `filtered` y firewalld como `unfiltered`. ¿Qué regla de iptables causa esa diferencia?
3. El límite SSH de iptables (`recent`) es **por IP**; el de firewalld (`limit`) es **global**. Si un atacante agota el límite de firewalld, ¿quién más queda afectado? ¿Por qué el administrador no?
4. En iptables, root sí podía conectarse a Kali:4444 y www-data no. En firewalld, ninguno. ¿Qué enfoque es más estricto y cuál es más fácil de mantener?
5. ¿Qué pasaba con IPv6 en iptables si no ejecutabas A1.8?

### Preguntas · Parte B (pfSense)

1. ¿Por qué crear `brian` y guardar `admin` en una bóveda es mejor que solo cambiar la clave de `admin`?
2. La regla anti-bloqueo existe para que no te quedes fuera. ¿Qué riesgo introduce y cómo lo resolviste?
3. ¿Qué hubiera pasado en 2024 con un FortiGate o un Palo Alto que tuviera la interfaz de administración o el portal VPN publicados como en el error 4?
4. Si la Ubuntu de la DMZ es comprometida, ¿qué puede hacer el atacante **antes** y **después** de B3?
5. ¿Por qué el filtrado de **salida** (LAN y DMZ) ayuda contra ransomware y exfiltración?

### Pregunta de cierre

¿Por qué una empresa necesita **las dos capas**: firewall perimetral (pfSense) y firewall en cada servidor (iptables/firewalld)? Usa como argumento lo que viste en P5: ¿qué capa detuvo la "reverse shell" en cada caso, y qué pasaría si un atacante ya estuviera **dentro** de la DMZ?

---

## B5 · OPCIONAL / TAREA — Suricata (IDS) en la WAN (20 min)

> Dale **2 GB de RAM** a pfSense para este lab.

1. `System › Package Manager › Available Packages` → busca **suricata** → Install → Confirm.
2. `Services › Suricata › Global Settings` → marca **Install ETOpen Emerging Threats rules** → Update Interval 12 horas → Save.
3. `Services › Suricata › Updates` → **Update** (espera a que descargue las reglas).
4. `Services › Suricata › Interfaces › Add` → Interface **WAN**, Enable, **Block Offenders: desmarcado** (primero solo detectar) → Save.
5. `Interfaces › WAN › WAN Categories` → marca `emerging-scan.rules` y `emerging-policy.rules` → Save → en `Interfaces` pulsa ▶ para iniciar.

```bash
# 🐉 En Kali: escaneo ruidoso contra la WAN para generar alertas
sudo nmap -sS -T4 -p 1-2000 IP_WAN_PF
# Un user-agent de escáner conocido también dispara firmas
curl -sk -A "Nikto" https://IP_WAN_PF:2222/ -m 3
```

`Services › Suricata › Alerts` → deberías ver alertas `ET SCAN ...`. Reflexiona: ¿qué pasaría si activas **Block Offenders** y el "atacante" fuera tu propio monitoreo? (falsos positivos y listas de paso).

---

## Más allá de pfSense: el mismo checklist sirve para cualquier equipo de seguridad

| Control de hoy | FortiGate | Palo Alto | VPN SSL (Ivanti, Fortinet, GlobalProtect) | Consola EDR / SIEM |
|---|---|---|---|---|
| Admin solo desde red de gestión | *Trusted hosts*, administración fuera de la WAN | Interfaz de gestión dedicada / *permitted IPs* | Portal de administración nunca en Internet | Acceso por VPN o ZTNA |
| Cuentas nominales + MFA | Admin profiles + FortiToken | Admin roles + SAML/MFA | MFA obligatorio | SSO + MFA |
| Servicios mínimos | Apagar HTTP/Telnet/SSH en interfaces que no lo necesitan | Apagar servicios del *management profile* | Apagar el portal web si solo se usa el cliente | Deshabilitar APIs y tokens sin uso |
| Parches críticos en días, no meses | Sigue los avisos de FortiGuard PSIRT | Sigue los avisos de Palo Alto PSIRT | **Catálogo KEV de CISA** como prioridad | Actualizaciones del fabricante |
| Logs fuera del equipo | Syslog / FortiAnalyzer | Syslog / Panorama | Syslog al SIEM | Exportación al SIEM |
| Respaldo cifrado y probado | Backup cifrado | Export de configuración cifrado | Backup de configuración | Backup de políticas |

---

## Errores comunes

### Parte A · iptables y firewalld

| Síntoma | Causa | Solución |
|---|---|---|
| Te quedaste sin SSH al poner `-P INPUT DROP` | Política DROP antes de permitir SSH, o `$IP_ADMIN` vacío (abriste otra terminal) | Espera al temporizador `fw-rollback` (15 min) o usa la consola de VirtualBox. Revisa con `echo $IP_ADMIN`. |
| Las reglas desaparecen solas a los 15 min | No cancelaste el temporizador | `sudo systemctl stop fw-rollback.timer` (o `fwd-rollback.timer`) |
| `iptables: Bad argument` en la regla 6 o 7 | Variable vacía: el comando quedó `-s  -j ACCEPT` | Vuelve a definir `RED_LAB`, `IP_ADMIN` e `IP_KALI` |
| P6 dice "sin límite" con iptables | Estás conectado por SSH **desde Kali**, así que Kali es `$IP_ADMIN` y está exento | Administra desde el anfitrión o la consola |
| El límite SSH de firewalld no bloquea nada | Escribiste `log ... limit value=...` (limita el log, no la conexión) | Usa `accept limit value="3/m"` |
| Cambios de firewalld que "desaparecen" | Hechos sin `--permanent` y luego `--reload` | Repite con `--permanent` o usa `--runtime-to-permanent` |
| `Can't use stand-alone options with other options` | `--set-log-denied` con `--permanent` | Ejecútalo solo: `sudo firewall-cmd --set-log-denied=unicast` |
| Algo se bloquea y no aparece en ninguna regla | Quedaron reglas de iptables y además está firewalld (o ufw) | `sudo iptables -S`, `sudo ufw status`, `sudo firewall-cmd --state`: solo uno a la vez |
| `nft: command not found` | El paquete nftables no viene por defecto | `sudo apt install -y nftables` (**no** habilites `nftables.service`: al arrancar ejecuta `flush ruleset` y borra todo) |
| P3 (UDP) da resultados distintos entre corridas | Linux limita la cantidad de ICMP que envía por segundo y nmap interpreta el silencio como `open|filtered` | Es normal: UDP es ambiguo; la conclusión sale de comparar con la línea base |
| ufw desaparece al instalar `iptables-persistent` | Son paquetes incompatibles en Ubuntu | Hoy no se instala: se vuelve al snapshot |

### Parte B · pfSense

| Síntoma | Causa | Solución |
|---|---|---|
| Al arrancar el ISO: `CPU doesn't support long mode` y prompt `OK` | La VM está en **32 bits**; pfSense solo funciona en 64 | Tipo **BSD**, versión **FreeBSD (64-bit)** y **PAE/NX** activado. Si no aparecen versiones de 64 bits: VT-x/AMD-V en la BIOS; en Windows desactiva *Integridad de memoria* y ejecuta `bcdedit /set hypervisorlaunchtype off` (PowerShell admin) y reinicia |
| El PC no llega a 192.168.56.10 | El adaptador Host-Only tiene DHCP de VirtualBox o tu PC no es .1 | Herramientas › Red › Host-Only: desactiva DHCP; revisa la IP del adaptador en el PC |
| Me quedé fuera de la GUI al desactivar la anti-bloqueo | La regla `GUI solo desde el PC admin` no estaba primero o el alias tiene otra IP | Consola › opción **8 (Shell)** → `pfctl -d` (apaga el filtrado temporalmente), corrige la regla y luego `pfctl -e`. O restaura el snapshot |
| La GUI dice "Login protection: blocked" | Superaste el umbral de 10 intentos | Espera 10 min o en la consola: opción 8 (Shell) → `pfctl -t sshguard -T flush` |
| La consola pide usuario y clave | Activaste "Password protect the console menu" | Usa `admin` con su nueva clave (por eso es la cuenta de emergencia) |
| Ubuntu sin Internet tras moverla a la DMZ | Reglas DMZ incompletas o DNS mal | Verifica reglas 1, 2 y 4 de la DMZ y `nameservers: 172.16.20.1` en netplan |
| `netplan try` revierte la configuración | La interfaz no se llama `enp0s3` | `ip -br link` y corrige el nombre en el YAML |
| No llegan logs a `/var/log/pfsense.log` | Falta la regla ufw, la Source Address o el reinicio de rsyslog | `sudo ufw status`, `sudo ss -ulnp \| grep 514`, revisa Status › System Logs › Settings |
| `ssh -p 2222` desde Kali no responde | El alias `KALI_EXTERNO` no coincide con `IP_KALI` o falta la regla WAN asociada | Revisa el alias y `Firewall › Rules › WAN` |
| El auditor dice `no es un XML válido` | Exportaste el respaldo cifrado | Exporta sin cifrar solo para auditar y bórralo con `shred` |
| ADM-01 sale **N/V** | Falta `python3-bcrypt` | `sudo apt install -y python3-bcrypt` |
| Suricata no arranca | Poca RAM o reglas sin descargar | 2 GB de RAM y `Services › Suricata › Updates › Update` |

---

## Anexo A · Instalación de pfSense CE 2.8.x (tarea previa, 15 min)

1. Descarga el instalador desde `https://www.pfsense.org/download/` (Netgate pide crear una cuenta gratuita y "comprar" la edición CE a $0). El archivo `netgate-installer-v1.2-RELEASE-amd64.iso.gz` es el **instalador en línea**: descomprímelo (7-Zip en Windows, `gunzip` en Linux) y ten en cuenta que descarga pfSense CE durante la instalación, así que la WAN (red NAT) necesita salida a internet.
2. VirtualBox › Nueva: tipo **BSD**, versión **FreeBSD (64-bit)** (si eliges 32 bits verás `CPU doesn't support long mode`), 1 GB RAM, disco 16 GB, 1 CPU, y en Sistema › Procesador marca **PAE/NX**.
3. Red: Adaptador 1 **Red NAT `LabSENATI`**, Adaptador 2 **Solo-anfitrión**, Adaptador 3 **Red interna `dmz-senati`** (los tres tipo Intel PRO/1000 → `em0`, `em1`, `em2`).
4. Arranca el ISO → acepta → **Install CE** → WAN `em0` (DHCP), LAN `em1` → ZFS por defecto → reinicia y quita el ISO.
5. En la consola verás el menú con las opciones 0–16. Sigue con el **B0.1**.

### Referencias

- Netgate — pfSense Hardening y documentación: docs.netgate.com/pfsense
- pfSense CE 2.8.x release notes: docs.netgate.com/pfsense/en/latest/releases/
- CISA — Known Exploited Vulnerabilities Catalog: cisa.gov/known-exploited-vulnerabilities-catalog
- NIST SP 800-41 Rev. 1 — Guidelines on Firewalls and Firewall Policy
- Lineamiento interno **BB-LIN-SEG-04 Firewall** (plantillas BurgerBank del curso).
