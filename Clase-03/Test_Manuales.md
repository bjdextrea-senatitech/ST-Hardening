# Guía de comprobación manual de hardening en Linux

**Módulo 04 · Aseguramiento de los Sistemas · SENATI**
**Sistema:** Ubuntu Server 22.04 LTS · **Complementa:** laboratorio de la Clase 3

---

## Cómo usar esta guía

Lynis y OpenSCAP automatizan la revisión, pero un auditor tiene que saber **qué hay detrás** de cada resultado y poder comprobarlo a mano. Esta guía recorre las áreas de hardening en el mismo orden que el benchmark CIS. Cada comprobación tiene:

- un **ID** (por ejemplo `SSH-3`), para anotarlo en el checklist del final;
- la **pregunta** que responde;
- una **teoría** corta: por qué importa y qué resultado es normal;
- el **comando**, que **solo lee** el sistema: ninguno cambia nada.

> Todos los comandos se probaron en Ubuntu Server 22.04.5. Ejecútalos como tu usuario normal; los que necesitan privilegios ya llevan `sudo`.

| Área | IDs | Comprobaciones |
| --- | --- | --- |
| 1. Arranque | ARR-1 a ARR-6 | 6 |
| 2. Sistema de archivos | FS-1 a FS-6 | 6 |
| 3. Software y parches | SW-1 a SW-6 | 6 |
| 4. Integridad | INT-1 a INT-3 | 3 |
| 5. Kernel y procesos | KRN-1 a KRN-7 | 7 |
| 6. AppArmor | MAC-1 a MAC-3 | 3 |
| 7. Servicios | SRV-1 a SRV-7 | 7 |
| 8. Red | RED-1 a RED-8 | 8 |
| 9. Firewall | FW-1 a FW-4 | 4 |
| 10. SSH | SSH-1 a SSH-6 | 6 |
| 11. Autenticación y contraseñas | AUT-1 a AUT-11 | 11 |
| 12. Usuarios y grupos | USR-1 a USR-9 | 9 |
| 13. Archivos y permisos | ARC-1 a ARC-6 | 6 |
| 14. Registros y auditoría | LOG-1 a LOG-10 | 10 |
| | **Total** | **92** |

---

## 1. Arranque

**ARR-1. ¿Quién puede leer la configuración del cargador de arranque?**
`grub.cfg` define cómo arranca el sistema. Si un usuario normal lo lee, ve si hay contraseña de GRUB y los parámetros del kernel. CIS pide que solo root pueda leerlo: `400` o `600`, dueño `root`.
```bash
sudo stat -c '%a %U:%G %n' /boot/grub/grub.cfg 2>/dev/null || echo "No existe /boot/grub/grub.cfg"
```

**ARR-2. ¿GRUB pide contraseña para editar el arranque?**
Sin contraseña de GRUB, cualquiera con acceso a la consola puede editar la línea del kernel al arrancar y entrar como root (por ejemplo, agregando `init=/bin/bash`). Si no sale nada, no hay contraseña.
```bash
sudo grep -E '^\s*(set superusers|password)' /boot/grub/grub.cfg 2>/dev/null || echo "GRUB sin contraseña"
```

**ARR-3. ¿El modo de recuperación pide contraseña de root?**
En Ubuntu, root viene **bloqueado** (`!` o `*` en `/etc/shadow`). Eso evita que alguien entre como root, pero el modo de recuperación de GRUB puede abrir una consola de root **sin pedir nada**. CIS pide que root tenga contraseña para que ese modo la exija.
```bash
sudo awk -F: '$1=="root" {print "root:", substr($2,1,3)}' /etc/shadow
```

**ARR-4. ¿Está activo Secure Boot?**
Secure Boot solo deja arrancar cargadores y kernels firmados, lo que bloquea bootkits. Solo existe con arranque **UEFI**. Una VM de VirtualBox con BIOS clásica arranca sin Secure Boot: es esperado en el laboratorio.
```bash
[ -d /sys/firmware/efi ] && echo "Arranque UEFI" || echo "Arranque BIOS clásico: sin Secure Boot"
mokutil --sb-state 2>/dev/null || echo "mokutil no instalado"
```

**ARR-5. ¿Con qué parámetros arrancó el kernel?**
Aquí se ve si se activaron protecciones desde el arranque, como `apparmor=1`, `audit=1` o `lockdown=`. También delata parámetros peligrosos, como `init=/bin/bash`.
```bash
cat /proc/cmdline
```

**ARR-6. ¿El kernel está en modo lockdown?**
El modo *lockdown* impide que incluso root modifique el kernel en ejecución (cargar módulos sin firmar, leer su memoria). El modo activo aparece entre corchetes.
```bash
cat /sys/kernel/security/lockdown 2>/dev/null || echo "lockdown no disponible"
```

---

## 2. Sistema de archivos

**FS-1. ¿Se pueden cargar sistemas de archivos que nadie usa?**
Cada módulo del kernel que se puede cargar es código que un atacante puede aprovechar, por ejemplo con un USB preparado. CIS pide deshabilitar los que no se usan. Hay cuatro salidas posibles:

| Salida | Significa |
| --- | --- |
| `insmod ...` | **Se puede** cargar: hay que deshabilitarlo |
| `install /bin/false` o `install /bin/true` | Deshabilitado: bien |
| `Module ... not found` | El kernel instalado no trae ese módulo: no se puede cargar |
| Nada | Está compilado dentro del kernel. Es el caso de `squashfs`, que además usa snap |
```bash
for m in cramfs freevxfs jffs2 hfs hfsplus squashfs udf usb-storage; do printf '%-12s ' "$m"; modprobe -n -v "$m" 2>&1 | tail -n 1; done
```

**FS-2. ¿Están cargados ahora?**
Un módulo cargado ya está en memoria y disponible, aunque luego se deshabilite su carga.
```bash
lsmod | grep -E 'cramfs|freevxfs|jffs2|hfs|squashfs|udf|usb_storage' || echo "Ninguno cargado"
```

**FS-3. ¿Qué carpetas están en particiones separadas?**
Separar `/tmp`, `/var`, `/var/log`, `/var/log/audit` y `/home` evita que llenar una (por ejemplo, con logs) tumbe todo el sistema, y permite montarlas con opciones restrictivas. Corregirlo después de instalar exige reparticionar: por eso suele quedar como riesgo aceptado.
```bash
for d in /tmp /var /var/tmp /var/log /var/log/audit /home; do if findmnt -n "$d" >/dev/null; then echo "$d: partición separada"; else echo "$d: NO separada"; fi; done
```

**FS-4. ¿Con qué opciones está montado `/dev/shm`?**
`/dev/shm` es memoria compartida a la que todos pueden escribir. CIS pide `nodev,nosuid,noexec`. Ubuntu lo monta sin `noexec`, así que un atacante podría ejecutar ahí lo que descargue.
```bash
findmnt -o TARGET,OPTIONS /dev/shm
```

**FS-5. ¿Cómo están los discos y su uso?**
Un disco lleno detiene servicios y logs, y una partición desconocida puede esconder datos. Revisa qué hay montado y cuánto espacio queda.
```bash
lsblk -f
df -h -x tmpfs -x squashfs
```

**FS-6. ¿Está activo el montaje automático?**
`autofs` monta automáticamente discos y unidades de red cuando alguien los usa, incluidas memorias USB. En un servidor no debería estar.
```bash
systemctl is-enabled autofs 2>/dev/null || echo "autofs no instalado"
```

---

## 3. Software y parches

**SW-1. ¿De dónde instala paquetes el sistema?**
Solo deberían aparecer los repositorios oficiales de Ubuntu o algunos de confianza. Un repositorio desconocido puede instalar software modificado.
```bash
grep -rhE '^\s*(deb|URIs)' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
```

**SW-2. ¿Qué llaves usa apt para confiar en los paquetes?**
apt verifica la firma de cada repositorio con estas llaves. Una llave que nadie reconoce permite instalar paquetes de un origen no autorizado.
```bash
ls -l /etc/apt/trusted.gpg.d/ /etc/apt/keyrings/ 2>/dev/null
```

**SW-3. ¿Hay paquetes congelados?**
Un paquete "retenido" (*hold*) no se actualiza nunca, ni siquiera con parches de seguridad. A veces es intencional; si nadie sabe por qué está así, es un riesgo.
```bash
apt-mark showhold
```

**SW-4. ¿Cuántas actualizaciones de seguridad faltan?**
Las de `-security` corrigen vulnerabilidades conocidas y públicas. Deberían ser cero o muy pocas.
```bash
apt list --upgradable 2>/dev/null | grep -c security
```

**SW-5. ¿Hace falta reiniciar para aplicar parches?**
Un parche del kernel o de librerías básicas no protege hasta que se reinicia el servidor.
```bash
cat /var/run/reboot-required 2>/dev/null || echo "No requiere reinicio"
```

**SW-6. ¿El kernel en uso es el más reciente instalado?**
Si hay un kernel más nuevo instalado pero el servidor no se reinició, se sigue usando el viejo, con sus vulnerabilidades.
```bash
uname -r
dpkg -l 'linux-image-[0-9]*' | awk '/^ii/ {print $2, $3}'
```

---

## 4. Integridad

**INT-1. ¿Algún archivo del sistema cambió desde que se instaló?**
`dpkg --verify` compara cada archivo de cada paquete con su suma de verificación original. Un binario modificado (por ejemplo `/usr/bin/ls`) puede indicar un rootkit. Las líneas con `c` son archivos de configuración: es normal que cambien. Tarda un par de minutos.
```bash
sudo dpkg --verify
```

**INT-2. ¿Hay un monitor de integridad instalado?**
AIDE guarda una "foto" de los archivos importantes y avisa si algo cambia. CIS lo pide en el Nivel 1. Para instalarlo sin dejar un servidor de correo abierto a la red, sigue la tarea 5.4 del laboratorio.
```bash
dpkg -l aide 2>/dev/null | grep ^ii || echo "AIDE no instalado"
```

**INT-3. ¿Hay ejecutables escondidos en carpetas temporales?**
Las carpetas temporales son el lugar favorito para dejar herramientas de ataque, porque todos pueden escribir ahí. Un ejecutable en `/tmp` o en `/dev/shm` merece una explicación.
```bash
sudo find /tmp /var/tmp /dev/shm -type f -perm /111 2>/dev/null
ls -la /tmp /var/tmp /dev/shm
```

---

## 5. Kernel y procesos

**KRN-1. ¿Están activas las protecciones de memoria y del kernel?**
Revisa varios parámetros de una vez y compáralos con la tabla siguiente.
```bash
sysctl kernel.randomize_va_space kernel.yama.ptrace_scope kernel.dmesg_restrict kernel.kptr_restrict \
       kernel.unprivileged_bpf_disabled kernel.kexec_load_disabled kernel.sysrq fs.suid_dumpable
```

| Parámetro | Valor seguro | Qué protege |
| --- | --- | --- |
| `kernel.randomize_va_space` | `2` | ASLR: ubica la memoria al azar y dificulta explotar fallas |
| `kernel.yama.ptrace_scope` | `1` o más | Un proceso no puede espiar la memoria de otro que no es su hijo |
| `kernel.dmesg_restrict` | `1` | Solo root lee los mensajes del kernel, que revelan direcciones de memoria |
| `kernel.kptr_restrict` | `1` o `2` | Oculta direcciones del kernel a usuarios normales |
| `kernel.unprivileged_bpf_disabled` | `1` o `2` | Usuarios normales no pueden cargar programas eBPF, una vía conocida de escalada |
| `kernel.kexec_load_disabled` | `1` | Impide reemplazar el kernel en caliente. Ubuntu trae `0` |
| `kernel.sysrq` | `0` o bajo | Las combinaciones SysRq del teclado pueden reiniciar o volcar memoria. Ubuntu trae `176`, que permite sincronizar discos, montar en solo lectura y reiniciar |
| `fs.suid_dumpable` | `0` | Programas SUID no generan volcados de memoria. Ubuntu trae `2` porque lo usa apport |

**KRN-2. ¿Están protegidos los enlaces y archivos en carpetas compartidas?**
Estos parámetros bloquean un ataque clásico: crear en `/tmp` un enlace que apunta a un archivo de root y esperar a que root escriba en él. Todos deberían valer `1` o `2`. Solo root puede leerlos, por eso el comando lleva `sudo`.
```bash
sudo sysctl fs.protected_symlinks fs.protected_hardlinks fs.protected_fifos fs.protected_regular
```

**KRN-3. ¿El procesador tiene activada la protección NX?**
NX (*No eXecute*) marca la memoria de datos como no ejecutable, así un atacante no puede ejecutar código inyectado en ella.
```bash
sudo journalctl -k -b | grep -i 'NX (Execute Disable)' || grep -o -m1 -w nx /proc/cpuinfo
```

**KRN-4. ¿Los programas pueden generar volcados de memoria?**
Un volcado (*core dump*) puede contener contraseñas o llaves. `ulimit -c` en `0` significa que no se generan. Busca también una línea `hard core 0`.
```bash
ulimit -c
sudo grep -rsE '^\s*\*\s+hard\s+core' /etc/security/limits.conf /etc/security/limits.d/
```

**KRN-5. ¿Hay un recolector de volcados instalado?**
`systemd-coredump` y `apport` guardan los volcados en disco para analizarlos. En producción conviene deshabilitarlos o limitarlos.
```bash
dpkg -l systemd-coredump apport 2>/dev/null | awk '/^ii/ {print $2, $3}'
systemctl is-enabled apport 2>/dev/null
```

**KRN-6. ¿Está instalado prelink?**
`prelink` modifica los binarios para que carguen más rápido, lo que rompe las verificaciones de integridad (INT-1, AIDE) y debilita ASLR. CIS pide que no esté.
```bash
dpkg -l prelink 2>/dev/null | grep ^ii || echo "prelink no instalado"
```

**KRN-7. ¿Qué módulos del kernel están cargados?**
Revisa la lista buscando algo inesperado: un módulo desconocido puede ser un rootkit.
```bash
lsmod | sort | head -n 40
```

---

## 6. AppArmor

**MAC-1. ¿AppArmor está activo desde el arranque?**
AppArmor es el control de acceso obligatorio de Ubuntu: limita lo que puede hacer cada programa aunque lo ejecute root. `Y` significa activo.
```bash
cat /sys/module/apparmor/parameters/enabled
sudo aa-status --enabled && echo "AppArmor activo"
```

**MAC-2. ¿Cuántos perfiles hay y en qué modo?**
`enforce` bloquea lo no permitido; `complain` solo lo registra. CIS acepta ambos, pero ningún perfil debería quedar sin cargar.
```bash
sudo aa-status | grep -E 'profiles are|processes are'
```

**MAC-3. ¿Qué procesos con red no están confinados?**
Un servicio que escucha en la red sin un perfil de AppArmor no tiene esa capa de protección.
```bash
sudo aa-status | sed -n '/processes are unconfined/,$p'
```

---

## 7. Servicios

**SRV-1. ¿Qué servicios de red conocidos están activos?**
Cada servicio activo que no se usa es superficie de ataque (CIS Control 4.8). Revisa una lista de los más comunes; solo debería aparecer lo que el servidor necesita.
```bash
for s in avahi-daemon cups nfs-server rpcbind snmpd smbd vsftpd apache2 nginx bind9 slapd dovecot squid isc-dhcp-server postfix exim4; do systemctl is-active --quiet "$s" && echo "$s ACTIVO"; done; echo "Revisión terminada"
```

**SRV-2. ¿Hay un servidor de correo escuchando hacia afuera?**
Si existe un servidor de correo, debe escuchar solo en `127.0.0.1`. Abierto a la red, puede usarse para enviar spam.
```bash
sudo ss -tlnp | grep -E ':(25|465|587)\s' || echo "Sin servidor de correo escuchando"
```

**SRV-3. ¿Hay entorno gráfico instalado?**
Un servidor no necesita escritorio: X11 trae mucho código adicional y servicios innecesarios.
```bash
dpkg -l 'xserver-xorg*' 2>/dev/null | grep ^ii || echo "Sin entorno gráfico"
```

**SRV-4. ¿Hay clientes de protocolos inseguros?**
`telnet`, `ftp` y `rsh` envían contraseñas en texto plano; `nis` y `talk` son servicios obsoletos. Que el cliente esté instalado facilita usarlos sin darse cuenta.
```bash
dpkg -l telnet ftp rsh-client nis talk ldap-utils 2>/dev/null | awk '/^ii/ {print $2}'
```

**SRV-5. ¿La hora está sincronizada?**
Sin la hora correcta, los logs de distintos servidores no se pueden correlacionar durante un incidente, y fallan los certificados y la autenticación. Lo esperado es `System clock synchronized: yes` y `NTP service: active`.
```bash
timedatectl
```

**SRV-6. ¿Con qué servidor se sincroniza?**
El servidor de hora debe ser uno de confianza, idealmente interno o del proveedor.
```bash
timedatectl show-timesync 2>/dev/null | grep -E 'ServerName|ServerAddress' || chronyc sources 2>/dev/null || echo "Sin servicio de hora configurado"
```

**SRV-7. ¿Qué procesos escuchan en todas las interfaces?**
Un servicio que escucha en `0.0.0.0` o `[::]` es alcanzable desde la red. Lo que solo usa el propio servidor debería escuchar en `127.0.0.1`.
```bash
sudo ss -tulnpH | awk '$5 ~ /^(0\.0\.0\.0|\*|\[::\]):/ {print $1, $5, $7}'
```

---

## 8. Red

**RED-1. ¿El servidor reenvía tráfico como un router?**
Si no es un router, el reenvío de IP debe estar en `0`. Con `1`, un atacante puede usarlo para saltar entre redes.
```bash
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
```

**RED-2. ¿Acepta rutas definidas por el emisor?**
El *source routing* deja que el paquete diga por dónde viajar, lo que permite saltarse controles de red. Debe estar en `0`.
```bash
sysctl net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route
```

**RED-3. ¿Responde a pings enviados a toda la red?**
Responder a pings de *broadcast* permite ataques de amplificación (tipo *smurf*). Debe estar en `1` (ignorar).
```bash
sysctl net.ipv4.icmp_echo_ignore_broadcasts
```

**RED-4. ¿Está activo IPv6 y acepta anuncios de router?**
Si IPv6 está activo pero nadie lo administra, es una red paralela sin vigilancia. Aceptar anuncios de router (`accept_ra = 1`) deja que cualquier equipo de la red cambie la ruta del servidor.
```bash
sysctl net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra
```

**RED-5. ¿Qué interfaces de red hay?**
Una interfaz que nadie esperaba (un puente, un túnel) puede ser una conexión escondida.
```bash
ip -br link
ip -br addr
```

**RED-6. ¿Hay interfaces inalámbricas?**
Un servidor no debería tener Wi-Fi: es una puerta de entrada que evita el firewall perimetral.
```bash
ls -d /sys/class/net/*/wireless 2>/dev/null || echo "Sin interfaces inalámbricas"
```

**RED-7. ¿Se pueden cargar protocolos de red poco usados?**
`dccp`, `sctp`, `rds` y `tipc` casi nunca se usan y han tenido vulnerabilidades graves en el kernel. CIS pide deshabilitarlos. `insmod ...` significa que se pueden cargar.
```bash
for m in dccp sctp rds tipc; do printf '%-6s ' "$m"; modprobe -n -v "$m" 2>&1 | tail -n 1; done
```

**RED-8. ¿Qué servidores DNS usa?**
Un DNS cambiado por un atacante redirige al servidor a sitios falsos sin que nadie lo note, por ejemplo al descargar actualizaciones.
```bash
resolvectl status | grep -E 'DNS Servers|Current DNS'
```

---

## 9. Firewall

**FW-1. ¿Qué reglas tiene el firewall?**
Cada regla debe tener una razón. La versión numerada sirve para borrar reglas puntuales.
```bash
sudo ufw status numbered
sudo ufw status verbose | grep -E 'Status|Default|Logging'
```

**FW-2. ¿Cada puerto abierto tiene una regla?**
Compara los puertos que escuchan con las reglas de ufw. Un puerto que escucha sin regla queda bloqueado por la política por defecto; una regla sin servicio es un hueco que nadie usa.
```bash
sudo ss -tulnH | awk '{print $1, $5}' | sort -u
```

**FW-3. ¿Qué reglas quedaron realmente en el kernel?**
ufw es una interfaz amigable; por debajo genera reglas de iptables. Aquí se ve lo que el kernel aplica de verdad.
```bash
sudo iptables -S | head -n 30
```

**FW-4. ¿El firewall registra lo que bloquea?**
Sin registro (*logging*), no sabrás quién intentó entrar. En ufw los bloqueos aparecen como `[UFW BLOCK]`.
```bash
sudo journalctl -k --since today | grep -c 'UFW BLOCK'
```

---

## 10. SSH

**SSH-1. ¿Qué criptografía ofrece el servidor?**
Debe ofrecer solo algoritmos modernos: sin `cbc`, sin `sha1` ni `md5` en los MAC, sin `diffie-hellman-group1`.
```bash
sudo sshd -T | grep -E '^(ciphers|macs|kexalgorithms|hostkeyalgorithms)'
```

**SSH-2. ¿Cómo se autentican los usuarios?**
Lo ideal en producción es autenticación por llave y contraseñas desactivadas. En el laboratorio se dejan las contraseñas para no complicar el acceso.
```bash
sudo sshd -T | grep -E '^(pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|usepam)'
```

**SSH-3. ¿Quién puede entrar por SSH?**
`AllowUsers` o `AllowGroups` limitan el acceso a una lista explícita. Si no sale nada, **cualquier** usuario con contraseña puede entrar.
```bash
sudo sshd -T | grep -E '^(allowusers|allowgroups|denyusers|denygroups)' || echo "Sin restricción de usuarios"
```

**SSH-4. ¿Qué límites tiene contra fuerza bruta?**
Estos valores frenan los ataques automáticos. Compáralos con los del bloque 3.1 del laboratorio.
```bash
sudo sshd -T | grep -E '^(maxauthtries|maxsessions|maxstartups|logingracetime|clientaliveinterval|clientalivecountmax)'
```

**SSH-5. ¿Las llaves del servidor están protegidas?**
Las llaves privadas (`*_key`) deben ser `600` y de root. Quien las copie puede hacerse pasar por el servidor.
```bash
ls -l /etc/ssh/ssh_host_*
```

**SSH-6. ¿Hay otros archivos de configuración de SSH?**
Lo que está en `sshd_config.d/` sobrescribe el archivo principal. Un atacante puede dejar ahí un archivo que reactive el login de root.
```bash
ls -l /etc/ssh/sshd_config.d/
sudo grep -h -vE '^\s*(#|$)' /etc/ssh/sshd_config.d/*.conf 2>/dev/null
```

---

## 11. Autenticación y contraseñas

**AUT-1. ¿Con qué algoritmo se guardan las contraseñas?**
El prefijo del hash indica el algoritmo: `$y$` es yescrypt (el actual de Ubuntu 22.04), `$6$` es SHA-512 (aceptable). `$1$` es MD5 y `$5$` es SHA-256: obsoletos. Solo se muestra el prefijo, nunca el hash.
```bash
sudo awk -F: '$2 ~ /^\$/ {split($2, a, "$"); print $1, "$" a[2] "$"}' /etc/shadow
grep -E '^ENCRYPT_METHOD' /etc/login.defs
```

**AUT-2. ¿Qué exige la política de complejidad?**
Muestra solo las líneas activas de `pwquality.conf`. Si el archivo no existe, no hay política de complejidad.
```bash
grep -vE '^\s*(#|$)' /etc/security/pwquality.conf 2>/dev/null || echo "pwquality sin configurar"
```

**AUT-3. ¿Qué módulos de PAM controlan las contraseñas?**
PAM es la cadena de módulos que decide si una contraseña es válida. Busca `pam_pwquality` (complejidad), `pam_pwhistory` (no repetir contraseñas) y `pam_faillock` (bloqueo por intentos). En un Ubuntu recién instalado solo aparece `pam_unix`. Ojo con `nullok`: permite entrar con contraseña vacía si la cuenta no tiene una.
```bash
grep -E '^[^#]*pam_(pwquality|pwhistory|faillock|unix)' /etc/pam.d/common-password /etc/pam.d/common-auth
```

**AUT-4. ¿Hay alguna cuenta bloqueada por intentos fallidos?**
Si faillock está activo, aquí ves los intentos fallidos recientes de una cuenta. Si no muestra nada, no hay intentos registrados o faillock no está configurado (revisa AUT-3).
```bash
sudo faillock --user "$USER" 2>/dev/null || echo "faillock no configurado"
```

**AUT-5. ¿Cuál es la política de vencimiento para cuentas nuevas?**
CIS pide un máximo de 365 días, un mínimo de 1 y aviso 7 días antes.
```bash
grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|UMASK)' /etc/login.defs
```

**AUT-6. ¿Se bloquean las cuentas inactivas?**
`INACTIVE` define cuántos días después de vencer la contraseña se bloquea la cuenta. `-1` significa nunca. CIS pide 30 días o menos.
```bash
useradd -D | grep INACTIVE
```

**AUT-7. ¿Alguna contraseña tiene fecha de cambio en el futuro?**
Una fecha futura en `/etc/shadow` suele indicar manipulación o un reloj mal configurado, y rompe la política de vencimiento. No debería salir nada.
```bash
sudo awk -F: -v hoy="$(( $(date +%s) / 86400 ))" '$3 > hoy {print $1}' /etc/shadow
```

**AUT-8. ¿Hay un cierre automático de sesión por inactividad?**
`TMOUT` cierra la terminal tras un tiempo sin uso (CIS Control 4.3). Si no sale nada, una sesión abandonada queda abierta para siempre.
```bash
grep -rs TMOUT /etc/profile /etc/profile.d/ /etc/bash.bashrc || echo "TMOUT no definido"
```

**AUT-9. ¿Qué permisos reciben los archivos nuevos?**
`umask` resta permisos a los archivos nuevos. `0022` los deja legibles para todos; CIS pide `027`, que los oculta a "otros". En Ubuntu tu usuario muestra `0002`: cada usuario tiene su propio grupo privado, así que el grupo no expone nada, pero "otros" sí pueden leer.
```bash
umask
grep -rsE '^\s*umask' /etc/profile /etc/profile.d/ /etc/bash.bashrc || echo "umask no definido en los perfiles"
```

**AUT-10. ¿Quién puede usar `su` y cómo se registra sudo?**
`pam_wheel` limita `su` a un grupo. Las opciones `Defaults` de sudo definen si hay registro propio (`logfile`) y cada cuánto se vuelve a pedir la contraseña.
```bash
grep -E '^\s*auth.*pam_wheel' /etc/pam.d/su || echo "su sin restricción de grupo"
sudo grep -rhE '^\s*Defaults' /etc/sudoers /etc/sudoers.d/
```

**AUT-11. ¿Quién puede programar tareas con cron y at?**
Si existe `cron.allow`, **solo** los usuarios de ese archivo pueden usar cron. CIS pide que exista y que solo root pueda leerlo, para que nadie más programe tareas.
```bash
ls -l /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>&1
```

---

## 12. Usuarios y grupos

**USR-1. ¿Hay nombres, UIDs o GIDs repetidos?**
Duplicados significan que dos cuentas comparten identidad o permisos. Los tres comandos no deberían mostrar nada.
```bash
cut -d: -f1 /etc/passwd | sort | uniq -d
cut -d: -f3 /etc/passwd | sort | uniq -d
cut -d: -f3 /etc/group | sort | uniq -d
```

**USR-2. ¿Todos los grupos de las cuentas existen?**
Una cuenta cuyo grupo principal no existe en `/etc/group` es un error de administración que puede terminar dando permisos a quien no corresponde.
```bash
for g in $(cut -d: -f4 /etc/passwd | sort -u); do getent group "$g" >/dev/null || echo "GID $g no existe"; done; echo "Revisión terminada"
```

**USR-3. ¿El grupo `shadow` tiene miembros?**
Los miembros del grupo `shadow` pueden leer los hashes de todas las contraseñas. Debe estar vacío: después de los dos puntos finales no debería haber nombres.
```bash
getent group shadow
```

**USR-4. ¿Cuál es el PATH de root?**
Si el PATH de root incluye `.` o una carpeta que otros pueden escribir, root podría ejecutar un programa falso. Revisa también `secure_path`, que es el PATH que usa sudo.
```bash
sudo -i printenv PATH
sudo grep -h secure_path /etc/sudoers
```

**USR-5. ¿Cada usuario es dueño de su home?**
Si otro usuario es dueño del home de alguien, puede leer y cambiar sus archivos, incluido su `authorized_keys`.
```bash
awk -F: '$3 >= 1000 && $1 != "nobody" {print $1, $6}' /etc/passwd | while read -r u h; do echo "$u -> $(stat -c '%U %a' "$h" 2>/dev/null || echo 'home no existe')"; done
```

**USR-6. ¿Hay archivos de configuración del usuario que otros pueden modificar?**
Archivos como `.bashrc` o `.profile` se ejecutan cada vez que el usuario entra. Si otro puede escribirlos, puede ejecutar código como ese usuario. No debería salir nada.
```bash
sudo find /home /root -maxdepth 2 -name '.*' -type f -perm /022 2>/dev/null
```

**USR-7. ¿Hay archivos de confianza antiguos?**
`.rhosts` permite entrar sin contraseña con protocolos viejos, `.netrc` guarda contraseñas en texto plano y `.forward` puede reenviar el correo de un usuario a otro lado. No debería salir nada.
```bash
sudo find /home /root -maxdepth 2 \( -name .rhosts -o -name .netrc -o -name .forward \) 2>/dev/null
```

**USR-8. ¿Cuándo entró cada usuario por última vez?**
Una cuenta que nadie usa desde hace meses debería bloquearse. Un ingreso a una hora rara merece revisión.
```bash
lastlog | grep -v 'Never logged in'
```

**USR-9. ¿Hubo intentos de ingreso fallidos?**
`lastb` lee el registro de ingresos fallidos. Muchos intentos sobre usuarios inexistentes indican un ataque automático.
```bash
sudo lastb -n 10 2>/dev/null || echo "Sin registro de intentos fallidos"
```

---

## 13. Archivos y permisos

**ARC-1. ¿Los archivos de cuentas y sus respaldos tienen los permisos correctos?**
Los archivos con `-` al final son respaldos automáticos, y tienen **la misma información** que los originales. `shadow` y `gshadow` (y sus respaldos) solo debe leerlos root y el grupo `shadow`.
```bash
ls -l /etc/passwd /etc/passwd- /etc/group /etc/group- /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-
```

**ARC-2. ¿Las tareas programadas están protegidas?**
CIS pide que solo root pueda ver las tareas de cron.
```bash
ls -ld /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
```

**ARC-3. ¿Hay llaves privadas legibles por cualquiera?**
Una llave privada legible por todos permite descifrar tráfico o hacerse pasar por el servidor. El comando busca archivos que **contienen** una llave privada, sin importar su nombre, y muestra sus permisos: el último dígito debe ser `0`. Los archivos `.pem` de certificados públicos son normales y no aparecen.
```bash
sudo find /etc /home /root -xdev -type f -size -20k -exec grep -qE 'BEGIN ([A-Z]+ )?PRIVATE KEY' {} \; -printf '%m %u %p\n' 2>/dev/null
```

**ARC-4. ¿Hay archivos de configuración que cualquiera puede modificar?**
Un archivo de `/etc` modificable por todos permite cambiar el comportamiento de un servicio de root. No debería salir nada.
```bash
sudo find /etc -xdev -type f -perm -0002 2>/dev/null
```

**ARC-5. ¿Algún archivo cambió en `/etc` en las últimas 24 horas?**
Sirve para ver qué se tocó recientemente, por ejemplo después de un incidente o de aplicar hardening. En un servidor recién instalado o recién endurecido salen muchos archivos: es normal.
```bash
sudo find /etc -xdev -type f -mtime -1 2>/dev/null | sort
```

**ARC-6. ¿Hay archivos ocultos raros fuera de los home?**
Un archivo o carpeta oculto en `/var`, `/usr` o `/opt` con un nombre como `...` o `.x` es una técnica de ocultamiento común.
```bash
sudo find /var /usr /opt -xdev -name '.*' 2>/dev/null | grep -vE '/\.(placeholder|keep|gitignore|build-id)' | head -n 20
```

---

## 14. Registros y auditoría

**LOG-1. ¿Están activos los servicios de registro?**
`rsyslog` escribe los logs clásicos en `/var/log` y `systemd-journald` guarda el journal. Ambos deberían estar `active`.
```bash
systemctl is-active rsyslog systemd-journald
```

**LOG-2. ¿Cómo está configurado el journal?**
Muestra la configuración efectiva de journald, combinando el archivo principal y los de `journald.conf.d/` (lleva `sudo` porque esa carpeta puede ser solo para root). Busca `Storage=persistent` y `Compress=yes`. Si solo aparece `[Journal]`, se usan los valores por defecto: el journal es persistente solo si existe `/var/log/journal`.
```bash
sudo systemd-analyze cat-config systemd/journald.conf | grep -vE '^\s*(#|$)'
```

**LOG-3. ¿Cuánto ocupan los logs y cuánto espacio queda?**
Si el disco de logs se llena, se pierden eventos justo cuando más se necesitan (CIS Control 8.3).
```bash
journalctl --disk-usage
df -h /var/log
```

**LOG-4. ¿Se rotan los logs?**
`logrotate` comprime y borra los logs viejos para que no llenen el disco. Revisa cada cuánto rota y cuántas copias guarda.
```bash
grep -E '^\s*(weekly|daily|monthly|rotate)' /etc/logrotate.conf
ls /etc/logrotate.d/
```

**LOG-5. ¿Algún log es legible por cualquier usuario?**
Los logs revelan usuarios, IPs y errores. CIS pide que "otros" no puedan leerlos. Algunos, como `wtmp`, `lastlog` o `faillog`, son legibles por diseño; en un Ubuntu recién instalado también salen `dpkg.log` y los de apt.
```bash
sudo find /var/log -type f -perm /o+r 2>/dev/null
```

**LOG-6. ¿Se envían los logs a otro servidor?**
Un atacante que toma el servidor borra los logs locales; los que ya se enviaron a otro servidor sobreviven. Busca líneas con `@` (UDP) o `@@` (TCP).
```bash
grep -rhE '^\s*[^#].*@{1,2}[0-9A-Za-z]' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null || echo "Sin envío a un servidor remoto"
```

**LOG-7. ¿Está activo auditd?**
auditd registra en el kernel quién hizo qué con cada archivo vigilado (CIS Nivel 2). Ver el bloque 3.12 del laboratorio.
```bash
dpkg -l auditd 2>/dev/null | grep -q ^ii && systemctl is-active auditd || echo "auditd no instalado"
```

**LOG-8. ¿Qué reglas de auditoría hay cargadas?**
Cada línea es algo que el kernel vigila. Sin reglas, auditd está activo pero no registra nada útil.
```bash
sudo auditctl -l 2>/dev/null || echo "auditd no instalado"
```

**LOG-9. ¿Las reglas de auditoría se pueden borrar?**
`enabled 2` significa reglas **inmutables**: ni root puede cambiarlas sin reiniciar, así un atacante no puede apagar la auditoría para borrar sus huellas. `enabled 1` es activo pero modificable.
```bash
sudo auditctl -s 2>/dev/null | grep -E '^enabled' || echo "auditd no instalado"
```

**LOG-10. ¿La auditoría empieza desde el arranque?**
Sin `audit=1` en el arranque, los procesos que inician antes que auditd no quedan registrados.
```bash
grep -o 'audit=1' /proc/cmdline || echo "audit=1 no está en los parámetros de arranque"
```

---

## Checklist

Marca cada comprobación. En **Evidencia**, pega la salida relevante o el nombre de la captura.

| ID | Control | Esperado | Sí | No | N.A. | Evidencia |
| --- | --- | --- | --- | --- | --- | --- |
| ARR-1 | Permisos de `grub.cfg` | `400` o `600`, root | | | | |
| ARR-2 | Contraseña de GRUB | Configurada | | | | |
| ARR-3 | Root con contraseña para recuperación | Contraseña definida | | | | |
| ARR-4 | Secure Boot | Activo (N.A. en VirtualBox BIOS) | | | | |
| ARR-5 | Parámetros del kernel | Sin parámetros peligrosos | | | | |
| ARR-6 | Kernel lockdown | Activo o justificado | | | | |
| FS-1 | Sistemas de archivos innecesarios | Deshabilitados | | | | |
| FS-2 | Módulos innecesarios cargados | Ninguno | | | | |
| FS-3 | Particiones separadas | Separadas o riesgo aceptado | | | | |
| FS-4 | Opciones de `/dev/shm` | `nodev,nosuid,noexec` | | | | |
| FS-5 | Uso de disco | Espacio suficiente | | | | |
| FS-6 | Montaje automático | Deshabilitado | | | | |
| SW-1 | Repositorios | Solo de confianza | | | | |
| SW-2 | Llaves de apt | Solo conocidas | | | | |
| SW-3 | Paquetes retenidos | Ninguno sin justificar | | | | |
| SW-4 | Actualizaciones de seguridad pendientes | Cero | | | | |
| SW-5 | Reinicio pendiente | No | | | | |
| SW-6 | Kernel en uso | El más reciente | | | | |
| INT-1 | Archivos de paquetes modificados | Solo configuración (`c`) | | | | |
| INT-2 | Monitor de integridad | AIDE instalado | | | | |
| INT-3 | Ejecutables en carpetas temporales | Ninguno | | | | |
| KRN-1 | Protecciones del kernel | Valores de la tabla | | | | |
| KRN-2 | Protección de enlaces | `1` o `2` | | | | |
| KRN-3 | NX | Activo | | | | |
| KRN-4 | Volcados de memoria | `0` y `hard core 0` | | | | |
| KRN-5 | Recolector de volcados | Deshabilitado o limitado | | | | |
| KRN-6 | prelink | No instalado | | | | |
| KRN-7 | Módulos cargados | Sin desconocidos | | | | |
| MAC-1 | AppArmor activo | `Y` | | | | |
| MAC-2 | Perfiles cargados | En enforce o complain | | | | |
| MAC-3 | Procesos sin confinar | Justificados | | | | |
| SRV-1 | Servicios innecesarios | Ninguno activo | | | | |
| SRV-2 | Correo hacia afuera | Solo local o ninguno | | | | |
| SRV-3 | Entorno gráfico | No instalado | | | | |
| SRV-4 | Clientes inseguros | No instalados | | | | |
| SRV-5 | Hora sincronizada | `yes` | | | | |
| SRV-6 | Servidor de hora | De confianza | | | | |
| SRV-7 | Servicios en todas las interfaces | Solo los necesarios | | | | |
| RED-1 | Reenvío de IP | `0` | | | | |
| RED-2 | Source routing | `0` | | | | |
| RED-3 | Ping a broadcast | Ignorado (`1`) | | | | |
| RED-4 | IPv6 y anuncios de router | Administrado o deshabilitado | | | | |
| RED-5 | Interfaces | Solo las esperadas | | | | |
| RED-6 | Inalámbricas | Ninguna | | | | |
| RED-7 | Protocolos poco usados | Deshabilitados | | | | |
| RED-8 | DNS | De confianza | | | | |
| FW-1 | Reglas del firewall | Activo, cada regla justificada | | | | |
| FW-2 | Puertos frente a reglas | Coinciden | | | | |
| FW-3 | Reglas en el kernel | Coinciden con ufw | | | | |
| FW-4 | Registro de bloqueos | Activo | | | | |
| SSH-1 | Criptografía | Solo algoritmos modernos | | | | |
| SSH-2 | Métodos de autenticación | Llaves; sin contraseñas vacías | | | | |
| SSH-3 | Usuarios permitidos | Lista explícita | | | | |
| SSH-4 | Límites contra fuerza bruta | Valores del bloque 3.1 | | | | |
| SSH-5 | Llaves del servidor | Privadas en `600`, root | | | | |
| SSH-6 | Archivos en `sshd_config.d` | Todos conocidos | | | | |
| AUT-1 | Algoritmo de contraseñas | `$y$` o `$6$` | | | | |
| AUT-2 | Complejidad | `minlen 14`, `minclass 4` | | | | |
| AUT-3 | Módulos PAM | pwquality, pwhistory, faillock | | | | |
| AUT-4 | Bloqueo por intentos | Configurado | | | | |
| AUT-5 | Vencimiento | 365 / 1 / 7 | | | | |
| AUT-6 | Bloqueo por inactividad | 30 días o menos | | | | |
| AUT-7 | Fechas de cambio futuras | Ninguna | | | | |
| AUT-8 | Cierre por inactividad | `TMOUT` definido | | | | |
| AUT-9 | umask | `027` | | | | |
| AUT-10 | `su` y registro de sudo | Restringido y con logfile | | | | |
| AUT-11 | `cron.allow` y `at.allow` | Existen, solo root | | | | |
| USR-1 | Duplicados | Ninguno | | | | |
| USR-2 | Grupos inexistentes | Ninguno | | | | |
| USR-3 | Grupo `shadow` | Vacío | | | | |
| USR-4 | PATH de root | Sin `.` ni carpetas escribibles | | | | |
| USR-5 | Dueño de cada home | El propio usuario | | | | |
| USR-6 | Archivos ocultos modificables | Ninguno | | | | |
| USR-7 | `.rhosts`, `.netrc`, `.forward` | Ninguno | | | | |
| USR-8 | Últimos ingresos | Sin cuentas abandonadas | | | | |
| USR-9 | Ingresos fallidos | Sin ataques sin atender | | | | |
| ARC-1 | Archivos de cuentas y respaldos | Permisos correctos | | | | |
| ARC-2 | Tareas cron | Solo root | | | | |
| ARC-3 | Llaves privadas legibles | Ninguna | | | | |
| ARC-4 | `/etc` modificable por todos | Nada | | | | |
| ARC-5 | Cambios recientes en `/etc` | Todos explicados | | | | |
| ARC-6 | Ocultos fuera de los home | Ninguno raro | | | | |
| LOG-1 | Servicios de registro | Activos | | | | |
| LOG-2 | Journal | Persistente y comprimido | | | | |
| LOG-3 | Espacio de logs | Suficiente | | | | |
| LOG-4 | Rotación | Configurada | | | | |
| LOG-5 | Logs legibles por todos | Solo los de diseño | | | | |
| LOG-6 | Envío remoto | Configurado | | | | |
| LOG-7 | auditd | Activo | | | | |
| LOG-8 | Reglas de auditoría | Cargadas | | | | |
| LOG-9 | Reglas inmutables | `enabled 2` | | | | |
| LOG-10 | Auditoría desde el arranque | `audit=1` | | | | |
