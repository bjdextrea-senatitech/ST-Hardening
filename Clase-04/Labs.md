# Clase 3 · Laboratorio: Hardening de Linux con Lynis y OpenSCAP

**Módulo 04 · Aseguramiento de los Sistemas · SENATI**
**Duración:** 2 horas de práctica · **Ciclo:** medir → endurecer → volver a medir
**Sistema:** Ubuntu Server 22.04 LTS · **Contenido CIS:** ComplianceAsCode v0.1.82, perfil CIS Level 1 Server

---

## Agenda

| Lab | Qué haces | Tiempo |
| --- | --- | --- |
| 0 | Preparar la VM y las herramientas | 5 min |
| 1 | Reconocimiento manual: 22 comandos detectives | 12 min |
| 1b | Buscar vías de escalada de privilegios: 13 comandos | 8 min |
| 2 | Línea base: Lynis, OpenSCAP y vista desde Kali | 20 min |
| 3 | Hardening manual en 13 bloques, verificando cada regla | 43 min |
| 4 | Remediación automática con control | 10 min |
| 5 | Volver a medir y comparar antes / después | 17 min |
| | Entrega | 5 min |

Los bloques marcados **(bonus)** son para quien termine antes. Si no llegas, déjalos para casa.

---

## Antes de empezar

| Necesitas | Detalle |
| --- | --- |
| VM Ubuntu Server 22.04 LTS | Con OpenSSH instalado, en la red NAT `LabSENATI` |
| VM Kali Linux | En la misma red NAT |
| Snapshot "limpio" de Ubuntu | **Tómalo ahora**, antes del Lab 0 |
| Consola de VirtualBox abierta | Por si te quedas fuera por SSH |
| `ssg-ubuntu2204-ds.xml` | Está en esta carpeta del repo |
| `lynis2html.py` | Está en esta carpeta del repo |

> **Regla de oro:** todo cambio se hace en la VM, nunca en tu laptop. Kali se usa **solo** contra tus propias VMs.

Anota la IP de tu Ubuntu (`ip -br a`) y la de tu Kali. En todos los labs aparecen como `IP_UBUNTU` e `IP_KALI`.

---

## Teoría rápida · Las dos herramientas del día

### Lynis: el auditor generalista

Lynis es un auditor de seguridad open source de CISOfy, escrito en shell. **Solo lee** el sistema, no cambia nada.

- Ejecuta más de 250 pruebas agrupadas por área: arranque, kernel, usuarios, SSH, firewall, logs, paquetes, permisos y otras.
- Cada prueba tiene un ID con formato `ÁREA-NNNN`, por ejemplo `SSH-7408` o `AUTH-9286`. El ID sirve para buscar qué revisa en `cisofy.com/lynis/controls/<ID>`.
- Al final entrega dos cosas:
  - **Advertencias (warnings):** problemas concretos que conviene corregir pronto.
  - **Sugerencias:** mejoras de hardening recomendadas.
- El **Hardening Index** (0 a 100) resume cuántas pruebas pasaron, ponderadas. **No es un porcentaje de cumplimiento CIS:** mide buenas prácticas generales.
- Deja dos archivos: `/var/log/lynis.log`, con el detalle de cada prueba, y `/var/log/lynis-report.dat`, con los resultados en formato `clave=valor`. Ese `.dat` es el que convertimos a HTML con `lynis2html.py`.

### OpenSCAP: el auditor de cumplimiento

**SCAP** (Security Content Automation Protocol) es un estándar del NIST para describir y medir configuraciones de seguridad de forma automática. **OpenSCAP** es la herramienta open source que lo ejecuta (`oscap`).

| Pieza | Qué es | En el lab |
| --- | --- | --- |
| **XCCDF** | El checklist: reglas, descripciones, perfiles y valores | Cada "regla" que verás en el reporte |
| **OVAL** | Las pruebas técnicas que deciden si una regla pasa o falla | Lee archivos, paquetes y parámetros del kernel |
| **CPE** | A qué sistema aplica cada regla | Si no aplica, la regla sale `notapplicable` |
| **SCE** | Scripts de verificación cuando OVAL no alcanza | Las reglas de `ufw` se verifican así |
| **Datastream** | Un solo archivo que empaqueta todo lo anterior, más los scripts de corrección | `ssg-ubuntu2204-ds.xml` |
| **Perfil** | Un conjunto de reglas con sus valores, por ejemplo CIS L1 Server | `cis_level1_server` |

El contenido lo publica el proyecto **ComplianceAsCode** (antes llamado SCAP Security Guide, por eso el prefijo `ssg-`). Ubuntu 22.04 no lo trae en sus repositorios, por eso usamos el archivo del repo del curso.

**Resultados posibles de una regla:**

| Resultado | Significa |
| --- | --- |
| `pass` | Cumple |
| `fail` | No cumple: hay que corregir o justificar |
| `notapplicable` | No aplica a este sistema, por ejemplo una regla de GNOME en un servidor sin escritorio |
| `notchecked` | Requiere revisión manual |
| `notselected` | La regla existe pero el perfil no la usa |
| `error` | La prueba no pudo ejecutarse |

**Diferencia clave:** Lynis te dice "qué tan bien está tu servidor". OpenSCAP te dice "si cumples el estándar CIS, regla por regla, y te da el script para corregir". En una auditoría formal la evidencia es OpenSCAP; Lynis complementa.

---

## Lab 0 · Preparación (5 min)

### 0.1 Carpeta de trabajo

Todo el laboratorio se trabaja en `/home/brian/`. Si tu usuario tiene otro nombre, reemplaza `brian` por el tuyo en todos los comandos.

```bash
cd /home/brian
# Copia aquí ssg-ubuntu2204-ds.xml y lynis2html.py (desde el repo del curso)
ls -lh /home/brian/ssg-ubuntu2204-ds.xml /home/brian/lynis2html.py
```

> Si no tienes el datastream, baja el paquete oficial (183 MB):
> ```bash
> sudo apt install -y unzip
> wget https://github.com/ComplianceAsCode/content/releases/download/v0.1.82/scap-security-guide-0.1.82.zip
> unzip -j scap-security-guide-0.1.82.zip scap-security-guide-0.1.82/ssg-ubuntu2204-ds.xml -d /home/brian
> ```

### 0.2 Instalar las herramientas

**Hazlo ahora:** en el Lab 3 vas a restringir el tráfico de salida.

```bash
sudo apt update
sudo apt install -y libopenscap8 lynis
oscap --version | head -n 1
lynis show version
```

**Teoría:** los dos vienen de los repositorios oficiales de Ubuntu. `libopenscap8` instala el comando `oscap`, y `lynis` se ejecuta con `sudo lynis`. La versión de Lynis del repositorio es algo más antigua que la de GitHub, pero hace las mismas pruebas que usamos en clase.

### 0.3 Cómo se verifica una regla

En el Lab 3 vas a comprobar cada corrección evaluando **solo esas reglas**, no el perfil completo. Escribe siempre el comando completo, así aprendes qué hace cada parte:

```bash
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --rule xccdf_org.ssgproject.content_rule_sshd_disable_root_login \
  /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
```

| Parte | Qué hace |
| --- | --- |
| `xccdf eval` | Evalúa reglas del checklist |
| `--profile ...cis_level1_server` | Toma los valores del perfil CIS L1 Server (por ejemplo, cuántos intentos de SSH permite) |
| `--rule ...content_rule_<nombre>` | Evalúa **solo** esa regla |
| `/home/brian/ssg-ubuntu2204-ds.xml` | El datastream con las reglas y las pruebas |
| `2>/dev/null` | Oculta las advertencias técnicas del escáner |
| `grep -E` con `Title` y `Result` | Muestra solo el nombre de cada regla y su resultado |

**Teoría:** una evaluación completa tarda minutos. Con `--rule` verificas una corrección en segundos. Todas las reglas empiezan con `xccdf_org.ssgproject.content_rule_`, seguido del nombre corto que ves en el reporte HTML.

**Para verificar varias reglas** se usa un `for`. La versión de `oscap` de Ubuntu 22.04 (1.2.17) **solo evalúa la última** `--rule` si pones varias en el mismo comando, así que hay que evaluarlas una por una:

```bash
for r in sshd_disable_root_login sshd_set_max_auth_tries; do
  sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --rule xccdf_org.ssgproject.content_rule_$r \
    /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
done
```

**Teoría del `for`:** repite el comando una vez por cada nombre de la lista. En cada vuelta, `$r` toma el valor del nombre que toca, y queda pegado al final del prefijo de la regla.

---

## Lab 1 · Reconocimiento manual: comandos detectives (12 min)

Antes de usar herramientas automáticas, mira el sistema con tus propios ojos. Para cada comando, **anota la respuesta** en tu entrega.

### Cuentas y privilegios

**1. ¿Quién tiene UID 0?**
Cualquier cuenta con UID 0 es root, aunque se llame distinto. Solo debe aparecer `root`.
```bash
awk -F: '$3==0 {print $1}' /etc/passwd
```

**2. ¿Quién puede usar sudo?**
Los miembros del grupo `sudo` pueden actuar como root. Cada nombre de esa lista es un administrador.
```bash
getent group sudo
```

**3. ¿Qué cuentas pueden iniciar sesión?**
Las cuentas de servicio deben tener `nologin` o `false`. Una cuenta de sistema con `/bin/bash` es sospechosa. `sync` con `/bin/sync` es normal: ese "shell" solo vacía los discos y sale.
```bash
awk -F: '$7 !~ /(nologin|false)$/ {print $1, $7}' /etc/passwd
```

**4. ¿Hay cuentas sin contraseña?**
Un campo de contraseña vacío en `/etc/shadow` permite entrar sin clave. No debería salir nada.
```bash
sudo awk -F: '$2=="" {print $1}' /etc/shadow
```

**5. ¿Cuándo vence tu contraseña?**
`chage` muestra la política de vencimiento de una cuenta. Por defecto, en Ubuntu **nunca vence**.
```bash
sudo chage -l $USER
```

**6. ¿Quién entró últimamente?**
`last` lee el historial de sesiones y `who` muestra quién está conectado ahora. Sirve para detectar accesos que no reconoces.
```bash
last -n 5
who
```

### Red y servicios

**7. ¿Qué puertos escuchan y qué programa los usa?**
Cada puerto abierto es superficie de ataque. Busca los que escuchan en `0.0.0.0` o `[::]`, es decir, en todas las interfaces.
```bash
sudo ss -tulpn
```

**8. ¿Qué servicios arrancan solos?**
Todo servicio habilitado que no uses debe deshabilitarse (CIS Control 4.8).
```bash
systemctl list-unit-files --type=service --state=enabled
```

**9. ¿Hay servicios fallando?**
Un servicio en estado `failed` puede indicar una mala configuración o un ataque que lo tumbó.
```bash
systemctl --failed
```

### SSH

**10. ¿Cómo está configurado SSH realmente?**
`sshd -T` muestra la configuración **efectiva**, después de combinar `sshd_config` con los archivos de `sshd_config.d/`. Es más confiable que leer el archivo a mano.
```bash
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication|maxauthtries|x11forwarding|clientaliveinterval'
```

> Con `grep -E` el "o" se escribe `|`, **sin** barra invertida. Si escribes `\|`, grep busca el carácter literal y no encuentra nada.

### Archivos y permisos

**11. ¿Qué programas tienen SUID?**
Un binario SUID se ejecuta con los permisos de su dueño, normalmente root. Si alguno tiene una falla, sirve para escalar privilegios. Compara la lista con la de un sistema limpio.
```bash
sudo find / -xdev -perm -4000 -type f 2>/dev/null
```

**12. ¿Hay archivos que cualquiera puede modificar?**
Un archivo "world-writable" lo puede alterar cualquier usuario. Si un script de root está en esa lista, el problema es grave.
```bash
sudo find / -xdev -type f -perm -0002 2>/dev/null
```

**13. ¿Hay archivos sin dueño?**
Suelen quedar al borrar un usuario. Si se crea un usuario nuevo con el mismo UID, hereda esos archivos.
```bash
sudo find / -xdev \( -nouser -o -nogroup \) 2>/dev/null
```

**14. ¿Los archivos críticos tienen permisos correctos?**
`/etc/shadow` guarda los hashes de las contraseñas: solo root debe leerlo. `/etc/crontab` define tareas que corren como root.
```bash
ls -l /etc/passwd /etc/shadow /etc/group /etc/crontab /etc/ssh/sshd_config
```

### Registros

**15. ¿Hubo intentos fallidos por SSH hoy?**
Muchos fallos seguidos desde una misma IP indican fuerza bruta.
```bash
sudo journalctl -u ssh --since today | grep -i failed
```

**16. ¿Quién usó sudo hoy?**
Cada uso de sudo queda registrado. Es tu primera fuente para saber quién hizo cambios como root.
```bash
sudo journalctl _COMM=sudo --since today | tail -n 10
```

**17. ¿Los logs sobreviven a un reinicio?**
Si `/var/log/journal` no existe, el journal vive en memoria y se pierde al reiniciar, junto con la evidencia de un incidente.
```bash
ls -d /var/log/journal 2>/dev/null || echo "Journal NO persistente"
```

### Parches y protecciones

**18. ¿Hay actualizaciones pendientes?**
La mayoría de los ataques exitosos aprovechan vulnerabilidades que ya tenían parche (CIS Control 7.3).
```bash
apt list --upgradable 2>/dev/null
```

**19. ¿Se instalan solas las actualizaciones de seguridad?**
`unattended-upgrades` aplica los parches de seguridad sin intervención. Busca `"1"` en ambas líneas.
```bash
cat /etc/apt/apt.conf.d/20auto-upgrades
```

**20. ¿El firewall está activo?**
En Ubuntu Server, `ufw` viene instalado pero **desactivado**.
```bash
sudo ufw status verbose
```

**21. ¿AppArmor protege procesos?**
AppArmor limita lo que puede hacer cada programa, aunque sea comprometido. Fíjate cuántos perfiles están en modo `enforce`.
```bash
sudo aa-status | head -n 8
```

**22. ¿Están activas las protecciones del kernel?**
`randomize_va_space = 2` activa ASLR: la memoria se ubica al azar y eso dificulta explotar fallas. `send_redirects = 1` permite que el servidor redirija tráfico como si fuera un router.
```bash
sysctl kernel.randomize_va_space net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_redirects
```

---

## Lab 1b · Buscar vías de escalada de privilegios (8 min)

Un atacante que entra con un usuario sin privilegios busca de inmediato cómo convertirse en root. Aquí revisas tu servidor **con sus ojos**, para cerrar esas puertas antes que él. Anota lo que encuentres.

### Privilegios ocultos en archivos

**23. ¿Qué programas tienen capabilities?**
Una capability entrega a un programa **una parte** del poder de root sin hacerlo SUID. `ping` o `mtr-packet` con `cap_net_raw` es normal, y también `snap-confine`, que necesita muchas capabilities para aislar las aplicaciones snap. Un intérprete o editor (`python`, `perl`, `vim`, `tar`) con `cap_setuid`, `cap_dac_read_search` o `cap_sys_admin` es una vía directa a root.
```bash
getcap -r / 2>/dev/null
```

**24. ¿Hay carpetas compartidas sin sticky bit?**
En una carpeta donde todos escriben, el **sticky bit** (la `t` al final de los permisos) impide que un usuario borre o renombre los archivos de otro. No debería salir ninguna carpeta en el `find`, y `/tmp` y `/var/tmp` deben mostrar `drwxrwxrwt`.
```bash
sudo find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null
ls -ld /tmp /var/tmp /dev/shm
```

**25. ¿Qué programas tienen SGID?**
Un binario SGID se ejecuta con el **grupo** de su dueño. Es menos grave que SUID, pero un SGID del grupo `shadow` puede leer los hashes de contraseñas. Compara con la lista de un sistema limpio.
```bash
sudo find / -xdev -perm -2000 -type f 2>/dev/null
```

### Sudo y tareas programadas

**26. ¿Qué puede hacer tu usuario con sudo?**
`sudo -l` lista los comandos que cada usuario puede ejecutar como root. `(ALL : ALL) ALL` significa "todo".
```bash
sudo -l
```

**27. ¿Hay reglas de sudo sin contraseña?**
`NOPASSWD` permite usar sudo sin escribir la contraseña: si alguien roba esa sesión, es root sin esfuerzo. No debería salir nada.
```bash
sudo grep -rn NOPASSWD /etc/sudoers /etc/sudoers.d/
```

**28. ¿Qué tareas programa systemd?**
Los *timers* de systemd son el reemplazo moderno de cron. Cada uno ejecuta un servicio, casi siempre como root.
```bash
systemctl list-timers --all
```

**29. ¿Qué tareas cron tiene cada usuario?**
Revisa los crontab de **todos** los usuarios. Una tarea desconocida que corre como root es una forma clásica de persistencia.
```bash
for u in $(cut -d: -f1 /etc/passwd); do sudo crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done
ls -la /etc/cron.d
```

**30. ¿Algún script de cron lo puede modificar otro usuario?**
Si un script que root ejecuta periódicamente es modificable por el grupo o por otros, cualquiera puede inyectarle código. No debería salir nada.
```bash
sudo find /etc/cron* -type f -perm /022 2>/dev/null
```

### Rutas y montajes

**31. ¿Alguna carpeta del PATH es escribible por otros?**
Si una carpeta del PATH es escribible por otros, alguien puede dejar ahí un `ls` falso que ejecutarías sin darte cuenta. Ninguna carpeta debería tener `w` en el grupo ni en otros. Si aparece `cannot access '/snap/bin'`, es porque todavía no hay aplicaciones snap instaladas: no es un problema.
```bash
echo "$PATH" | tr ':' '\n' | xargs -I{} ls -ld {}
```

**32. ¿Con qué opciones están montadas las carpetas temporales?**
CIS pide `nodev,nosuid,noexec` en `/dev/shm` y en `/tmp`. Con `noexec`, un atacante no puede ejecutar herramientas que descargue en esas carpetas. En Ubuntu, `/tmp` normalmente **no** es una partición separada: por eso la regla `partition_for_tmp` queda en FAIL.
```bash
findmnt -o TARGET,OPTIONS /dev/shm
findmnt /tmp || echo "/tmp no es una partición separada"
```

### Cuentas y accesos

**33. ¿Hay UIDs repetidos y en qué estado está cada cuenta?**
Dos cuentas con el mismo UID son, para el sistema, **la misma persona**. En `passwd -S`, la segunda columna dice `P` (tiene contraseña), `L` (bloqueada) o `NP` (sin contraseña). `NP` en una cuenta que puede entrar es grave.
```bash
cut -d: -f3 /etc/passwd | sort | uniq -d
sudo passwd -S -a
```

**34. ¿Otros usuarios pueden entrar a los home?**
Desde Ubuntu 21.04 los home nuevos se crean con `750` (`drwxr-x---`): otros usuarios no pueden entrar. Si ves `755` (`drwxr-xr-x`), cualquiera puede listar los archivos de ese usuario; pasa con cuentas creadas a mano o migradas de versiones antiguas. CIS pide `750` o más restrictivo.
```bash
ls -ld /home/*
```

**35. ¿Qué llaves SSH permiten entrar sin contraseña?**
Cada línea de un `authorized_keys` es una llave que entra sin contraseña. Una llave que nadie reconoce es una **puerta trasera clásica**.
```bash
sudo find / -xdev -name authorized_keys 2>/dev/null -exec ls -l {} \;
```

> Estos 35 comandos son una muestra. La guía `guia-comprobacion-manual-linux.md`, en esta misma carpeta, recorre todas las áreas del hardening con 92 comprobaciones y un checklist para marcar.

---

## Lab 2 · Línea base (20 min)

### 2.1 Lynis "antes" (7 min)

```bash
cd /home/brian
sudo lynis audit system --quick \
  --report-file /home/brian/lynis-antes.dat --log-file /home/brian/lynis-antes.log
```

| Opción | Qué hace |
| --- | --- |
| `audit system` | Audita el sistema local completo |
| `--quick` | No hace pausas entre secciones |
| `--report-file` | Guarda los resultados en tu carpeta, para compararlos después |
| `--log-file` | Guarda el detalle de cada prueba |

Mientras corre, observa los colores: **verde** = bien, **amarillo** = sugerencia, **rojo** = advertencia.

**Teoría:** al final, Lynis muestra el **Hardening index** y las secciones *Warnings* y *Suggestions*. Cada línea trae el ID de la prueba entre corchetes.

Genera el reporte HTML:

```bash
sudo python3 lynis2html.py lynis-antes.dat -o lynis-antes.html
```

**Teoría:** `lynis2html.py` lee el `.dat` (líneas `clave=valor`) y arma un HTML con el índice, el equipo auditado, las advertencias y las sugerencias. Cada ID enlaza a su documentación en CISOfy. Solo usa Python 3, sin instalar nada.

Explora el `.dat` directamente:

```bash
sudo grep hardening_index lynis-antes.dat
sudo grep -c '^warning\[\]' lynis-antes.dat
sudo grep -c '^suggestion\[\]' lynis-antes.dat
sudo grep -A6 'test ID AUTH-9286' lynis-antes.log   # qué revisó una prueba concreta
```

**Teoría:** el `.log` cuenta paso a paso qué revisó cada prueba, qué encontró y cuántos puntos de hardening sumó. `AUTH-9286` revisa el vencimiento de contraseñas, que corregirás en el bloque 3.3.

**Anota:** Hardening index, cantidad de advertencias y cantidad de sugerencias.

### 2.2 OpenSCAP "antes" (10 min)

Mira los perfiles que trae el datastream:

```bash
oscap info /home/brian/ssg-ubuntu2204-ds.xml | grep -E 'Title:|Id: xccdf_org.ssgproject.content_profile'
```

**Teoría:** `oscap info` describe el contenido del archivo: versión, componentes y perfiles. Cada perfil tiene un ID largo. Ese ID es el que va en `--profile`: `xccdf_org.ssgproject.content_profile_cis_level1_server`.

Escanea con el perfil CIS Level 1 Server:

```bash
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --results /home/brian/antes.xml \
  --report /home/brian/antes.html \
  /home/brian/ssg-ubuntu2204-ds.xml > /home/brian/antes.txt 2>/dev/null
echo "Código de salida: $?"
grep -c 'Result.*pass$' antes.txt
grep -c 'Result.*fail$' antes.txt
```

| Parte del comando | Qué hace |
| --- | --- |
| `xccdf eval` | Evalúa las reglas del checklist |
| `--profile ...cis_level1_server` | Usa solo las reglas del perfil CIS L1 Server |
| `--results` | Resultados en XML: los necesitas para generar correcciones en el Lab 4 |
| `--report` | Reporte legible con explicación y corrección sugerida por regla |
| `> antes.txt` | Resumen en texto para contar pass y fail |
| `2>/dev/null` | Oculta las advertencias técnicas del escáner |

| Código de salida | Significa |
| --- | --- |
| `0` | Todas las reglas pasaron |
| `1` | Error al ejecutar |
| `2` | **Hay reglas en FAIL** (lo normal la primera vez) |

### 2.3 Ver los reportes y la vista desde afuera (3 min)

Desde **Kali**:

```bash
scp brian@IP_UBUNTU:/home/brian/antes.html .
scp brian@IP_UBUNTU:/home/brian/lynis-antes.html .
firefox antes.html lynis-antes.html &

nmap -sV IP_UBUNTU -oN antes-nmap.txt
ssh-audit IP_UBUNTU > antes-ssh.txt
```

**Teoría:**
- `nmap -sV` muestra los puertos abiertos y la versión de cada servicio: lo mismo que ve un atacante.
- `ssh-audit` revisa la criptografía que ofrece el servidor SSH y marca en rojo los algoritmos débiles.

> Si `ssh-audit` no está instalado: `sudo apt install -y ssh-audit`. Si `scp` falla por permisos, en Ubuntu ejecuta `sudo chown brian /home/brian/*`.

**Anota:** pass y fail de OpenSCAP, el porcentaje del reporte y los puertos que ve nmap.

---

## Lab 3 · Hardening manual (43 min)

**Método:** en cada bloque lees la teoría, aplicas los comandos y verificas con `oscap` como en el 0.3. La regla debe pasar de `fail` a `pass`.

> **No cierres tu sesión SSH actual** mientras toques SSH, el firewall o PAM. Prueba siempre desde **otra** ventana. Si te quedas fuera, entra por la consola de VirtualBox.

### 3.1 SSH (5 min)

**Teoría:** SSH es la puerta de entrada al servidor y el primer blanco de la fuerza bruta. Las directivas en `sshd_config.d/` sobrescriben el archivo principal y sobreviven a las actualizaciones de paquetes.

| Directiva | Por qué |
| --- | --- |
| `PermitRootLogin no` | Nadie entra directo como root: primero con su usuario, luego `sudo` (queda trazabilidad) |
| `MaxAuthTries 4` | Corta la conexión tras 4 intentos fallidos |
| `PermitEmptyPasswords no` | Prohíbe cuentas sin clave por SSH |
| `LoginGraceTime 60` | 60 segundos para autenticarse, o se corta |
| `ClientAliveInterval 300` + `ClientAliveCountMax 3` | Cierra sesiones abandonadas |
| `MaxStartups 10:30:60` | Limita conexiones simultáneas sin autenticar (frena ataques masivos) |
| `MaxSessions 10` | Sesiones máximas por conexión |
| `LogLevel INFO` | Registra los inicios de sesión |
| `IgnoreRhosts yes` / `HostbasedAuthentication no` | Desactiva métodos de confianza antiguos e inseguros |
| `PermitUserEnvironment no` | Impide que el usuario inyecte variables de entorno al servidor |
| `X11Forwarding no` | Un servidor no necesita reenviar ventanas gráficas |
| `Banner /etc/issue.net` | Muestra el aviso legal antes del login |

```bash
sudo tee /etc/ssh/sshd_config.d/50-hardening.conf <<'EOF'
PermitRootLogin no
MaxAuthTries 4
PermitEmptyPasswords no
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 3
MaxStartups 10:30:60
MaxSessions 10
LogLevel INFO
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
X11Forwarding no
Banner /etc/issue.net
EOF
sudo chmod 600 /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
sudo sshd -t && sudo systemctl reload ssh
```

`sshd -t` valida la sintaxis: no debe mostrar nada. Si muestra un error, corrígelo **antes** de recargar. El `chmod 600` deja la configuración de SSH legible solo por root, incluidos los archivos de `sshd_config.d/`: CIS revisa los dos.

```bash
for r in \
  sshd_disable_root_login \
  sshd_set_max_auth_tries \
  sshd_disable_empty_passwords \
  sshd_set_login_grace_time \
  sshd_set_idle_timeout \
  sshd_set_keepalive \
  sshd_set_maxstartups \
  sshd_set_max_sessions \
  sshd_set_loglevel_info \
  sshd_disable_rhosts \
  sshd_do_not_permit_user_env \
  file_permissions_sshd_config \
  file_permissions_sshd_drop_in_config; do
  sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --rule xccdf_org.ssgproject.content_rule_$r \
    /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
done
```

Desde **otra ventana**, comprueba que todavía entras: `ssh brian@IP_UBUNTU`.

### 3.1b Criptografía de SSH (3 min)

**Teoría:** en el Lab 2, `ssh-audit` marcó en rojo los algoritmos débiles. Una conexión SSH negocia cuatro cosas, y en cada una se dejan solo las opciones modernas:

| Directiva | Qué define |
| --- | --- |
| `KexAlgorithms` | Cómo se acuerda la llave de la sesión |
| `Ciphers` | Cómo se cifran los datos |
| `MACs` | Cómo se verifica que nadie los alteró |
| `HostKeyAlgorithms` | Con qué llave se identifica el servidor. Se quita ECDSA, que `ssh-audit` marca en rojo por sus curvas NIST |

Los clientes actuales (Kali, OpenSSH de Windows, PuTTY o MobaXterm recientes) soportan todos estos algoritmos. Un cliente muy antiguo podría no conectar: por eso se prueba desde otra ventana **antes** de cerrar la sesión actual.

```bash
sudo tee /etc/ssh/sshd_config.d/60-cripto.conf <<'EOF'
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
EOF
sudo chmod 600 /etc/ssh/sshd_config.d/60-cripto.conf
sudo sshd -t && sudo systemctl reload ssh
```

```bash
for r in \
  sshd_use_strong_kex \
  sshd_use_strong_ciphers \
  sshd_use_strong_macs; do
  sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --rule xccdf_org.ssgproject.content_rule_$r \
    /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
done
```

Desde **otra ventana**, vuelve a entrar con `ssh brian@IP_UBUNTU`. Si conecta, ya puedes seguir.

> Si el cliente avisa que **cambió la llave del servidor** (`REMOTE HOST IDENTIFICATION HAS CHANGED`), es porque antes usaba la llave ECDSA y ahora el servidor ofrece la ed25519. En ese caso es esperado: en el equipo cliente ejecuta `ssh-keygen -R IP_UBUNTU` y vuelve a conectar.

> Después de este bloque, `ssh-audit` todavía muestra advertencias amarillas de que el intercambio de llaves *no protege contra ataques post-cuánticos*. OpenSSH 8.9 trae `sntrup761x25519-sha512@openssh.com`, que sí protege, pero **no está en la lista aprobada por CIS** para Ubuntu 22.04: si lo agregas, la regla `sshd_use_strong_kex` pasa a FAIL. Es un buen ejemplo de que dos estándares pueden no coincidir.

### 3.2 Firewall con salida restringida (6 min)

**Teoría:** un firewall de servidor (CIS Control 4.4) cierra todo y abre solo lo necesario. CIS va más allá de la entrada: pide **denegar también la salida y el ruteo por defecto**. Así, si un atacante compromete el servidor, no puede descargar herramientas ni enviar datos a donde quiera.

- El tráfico de `lo` (loopback, 127.0.0.1) se permite, porque los servicios locales hablan entre sí por ahí.
- Lo que **llega** a la interfaz de red diciendo venir de 127.0.0.0/8 es falso (spoofing) y se bloquea.
- **Primero se permite SSH y después se activa el firewall.** En el orden inverso te quedas fuera.

```bash
# Política por defecto: todo cerrado
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw default deny routed

# Entrada: solo SSH
sudo ufw allow in OpenSSH

# Loopback
sudo ufw allow in on lo
sudo ufw allow out on lo
sudo ufw deny in from 127.0.0.0/8
sudo ufw deny in from ::1

# Salida mínima para que el servidor funcione
sudo ufw allow out 53          # DNS
sudo ufw allow out 80/tcp      # repositorios apt (HTTP)
sudo ufw allow out 443/tcp     # repositorios apt y GitHub (HTTPS)
sudo ufw allow out 123/udp     # hora (NTP)

sudo ufw --force enable
sudo ufw status verbose
```

```bash
for r in \
  check_ufw_active \
  set_ufw_default_rule \
  set_ufw_loopback_traffic; do
  sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --rule xccdf_org.ssgproject.content_rule_$r \
    /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
done
sudo apt update     # debe seguir funcionando
```

### 3.3 Contraseñas y cuentas (5 min)

**Teoría:**
- `/etc/login.defs` define la política para las cuentas **nuevas**: vencimiento, aviso previo y `UMASK` (permisos por defecto de los archivos nuevos). Con `027`, los archivos nuevos no son legibles para "otros".
- Las cuentas **existentes** no se enteran del cambio. A ellas se les aplica con `chage`.
- `pwquality` exige complejidad cuando alguien cambia su contraseña: `minlen = 14` caracteres y `minclass = 4` tipos (mayúscula, minúscula, número y símbolo).
- `TMOUT` cierra la terminal tras 15 minutos sin uso (CIS Control 4.3, bloqueo automático de sesión).

```bash
# Política para cuentas nuevas
sudo sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/; s/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/; s/^UMASK.*/UMASK\t\t027/' /etc/login.defs
grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|UMASK)' /etc/login.defs

# Aplicar el vencimiento a las cuentas existentes con contraseña
for u in $(sudo awk -F: '$2 ~ /^\$/ {print $1}' /etc/shadow); do sudo chage --maxdays 365 --mindays 1 --warndays 7 "$u"; done
sudo chage -l $USER

# Complejidad
sudo apt install -y libpam-pwquality
sudo sed -i -E 's/^#? *minlen.*/minlen = 14/; s/^#? *minclass.*/minclass = 4/' /etc/security/pwquality.conf
grep -E '^(minlen|minclass)' /etc/security/pwquality.conf

# Cierre de sesión por inactividad
printf 'TMOUT=900\nreadonly TMOUT\nexport TMOUT\n' | sudo tee /etc/profile.d/60-tmout.sh
```

```bash
for r in \
  accounts_maximum_age_login_defs \
  accounts_password_warn_age_login_defs \
  accounts_umask_etc_login_defs \
  accounts_password_set_max_life_existing \
  accounts_password_pam_minlen \
  accounts_password_pam_minclass \
  accounts_tmout; do
  sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --rule xccdf_org.ssgproject.content_rule_$r \
    /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
done
```

**Prueba:** intenta cambiar tu contraseña a `Hola123` con `passwd`. Debe rechazarla.

### 3.4 Restringir su y sudo (4 min)

**Teoría:**
- `su` permite convertirse en otro usuario si conoces su contraseña. CIS pide que solo lo use un grupo dedicado, y que ese grupo **quede vacío**: la vía para administrar es `sudo`, que deja registro (CIS Control 5.4).
- En sudo se configuran tres cosas:
  - `use_pty` ejecuta cada comando en su propia terminal, para que un proceso en segundo plano no siga vivo al terminar la sesión.
  - `logfile` guarda cada comando en un archivo propio.
  - `timestamp_timeout=15` pide la contraseña otra vez pasados 15 minutos.
- **Nunca** edites sudoers sin validar: un error de sintaxis te deja sin sudo. `visudo -cf` revisa el archivo antes de que cuente.

```bash
# su solo para el grupo sugroup (vacío)
sudo groupadd sugroup
sudo sed -i '/^auth\s\+sufficient\s\+pam_rootok.so/a auth       required   pam_wheel.so use_uid group=sugroup' /etc/pam.d/su
grep -n '^auth' /etc/pam.d/su

# sudo
sudo tee /etc/sudoers.d/50-hardening <<'EOF'
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults timestamp_timeout=15
EOF
sudo chmod 440 /etc/sudoers.d/50-hardening
sudo visudo -cf /etc/sudoers.d/50-hardening
```

```bash
for r in \
  use_pam_wheel_group_for_su \
  ensure_pam_wheel_group_empty \
  sudo_add_use_pty \
  sudo_custom_logfile \
  sudo_require_reauthentication; do
  sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --rule xccdf_org.ssgproject.content_rule_$r \
    /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
done
```

**Prueba:** `su -` ahora debe fallar aunque sepas la contraseña de root, y `sudo -i` debe seguir funcionando. Ejecuta `sudo ls` y revisa `sudo cat /var/log/sudo.log`.

### 3.5 Parámetros del kernel con sysctl (5 min)

**Teoría:** `sysctl` ajusta el comportamiento del kernel en caliente. Los archivos en `/etc/sysctl.d/` hacen que los cambios sobrevivan al reinicio. Un servidor que **no es router** no debe enviar ni aceptar redirecciones ICMP: un atacante las usa para desviar tráfico.

| Parámetro | Por qué |
| --- | --- |
| `send_redirects = 0` / `accept_redirects = 0` | No se comporta como router ni acepta rutas de terceros |
| `log_martians = 1` | Registra paquetes con direcciones imposibles (señal de spoofing) |
| `rp_filter = 1` | Descarta paquetes cuya dirección de origen no cuadra con la interfaz por la que llegan |
| `tcp_syncookies = 1` | Resiste ataques de inundación SYN |
| `icmp_ignore_bogus_error_responses = 1` | Ignora respuestas ICMP malformadas |
| `randomize_va_space = 2` | ASLR completo |
| `yama.ptrace_scope = 1` | Un proceso no puede inspeccionar la memoria de otro que no sea su hijo |
| `fs.suid_dumpable = 0` | Los programas SUID no generan volcados de memoria |

```bash
sudo tee /etc/sysctl.d/60-hardening.conf <<'EOF'
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
EOF

# ¿Algún otro archivo dice lo contrario?
sudo grep -rn 'rp_filter' /etc/sysctl.d/ /etc/sysctl.conf | grep -v ':#'
```

**Ojo, hay dos archivos que contradicen tu configuración.** OpenSCAP marca FAIL si encuentra un valor contradictorio en cualquiera de ellos, aunque tu archivo `60-` se aplique después:

| Archivo | Qué dice | Por qué importa |
| --- | --- | --- |
| `/etc/sysctl.d/10-network-security.conf` | `rp_filter=2` | Viene con Ubuntu |
| `/etc/ufw/sysctl.conf` | `log_martians=0` | ufw lo aplica **cada vez que se activa o arranca**, y pisa tu valor |

```bash
sudo grep -n 'log_martians' /etc/ufw/sysctl.conf
sudo sed -i -E 's/^(net.ipv4.conf.(all|default).rp_filter\s*=\s*2)/# \1/' /etc/sysctl.d/10-network-security.conf
sudo sed -i -E 's#^(net/ipv4/conf/(all|default)/log_martians)=0#\1=1#' /etc/ufw/sysctl.conf
sudo grep -n 'log_martians' /etc/ufw/sysctl.conf
sudo sysctl --system > /dev/null
sysctl net.ipv4.conf.all.rp_filter kernel.randomize_va_space
```

> Si `sysctl --system` muestra `Invalid argument` en claves que no escribiste (por ejemplo `promote_secondaries`), vienen de archivos del propio sistema y no afectan al laboratorio.

```bash
for r in \
  sysctl_net_ipv4_conf_all_send_redirects \
  sysctl_net_ipv4_conf_all_accept_redirects \
  sysctl_net_ipv4_conf_all_log_martians \
  sysctl_net_ipv4_conf_all_rp_filter \
  sysctl_net_ipv4_tcp_syncookies \
  sysctl_net_ipv4_icmp_ignore_bogus_error_responses \
  sysctl_kernel_randomize_va_space \
  sysctl_kernel_yama_ptrace_scope \
  sysctl_fs_suid_dumpable; do
  sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --rule xccdf_org.ssgproject.content_rule_$r \
    /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
done
```

### 3.6 Volcados de memoria (core dumps) (3 min)

**Teoría:** cuando un programa se cae, puede escribir su memoria en un archivo "core". Esa memoria puede contener contraseñas, llaves o datos de clientes. En producción se desactiva.

Ubuntu trae **apport**, que recoge esos volcados para enviar reportes de errores. Cada vez que arranca, apport vuelve a poner `fs.suid_dumpable = 2` y **deshace** lo que configuraste en el 3.5. Por eso CIS pide enmascararlo (*mask*): un servicio enmascarado no puede arrancar, ni siquiera si otro servicio lo pide.

```bash
echo '* hard core 0' | sudo tee /etc/security/limits.d/60-nocore.conf
sudo systemctl stop apport
sudo systemctl mask apport
sudo sysctl --system > /dev/null
sysctl fs.suid_dumpable
```

```bash
for r in \
  disable_users_coredumps \
  service_apport_disabled \
  sysctl_fs_suid_dumpable; do
  sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --rule xccdf_org.ssgproject.content_rule_$r \
    /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
done
```

### 3.7 Paquetes innecesarios (3 min)

**Teoría:** lo que no está instalado no se puede explotar (CIS Control 4.8). `telnet` y `ftp` envían contraseñas en texto plano. `rsync` viene en Ubuntu Server y casi nunca se usa en un servidor de aplicaciones.

```bash
dpkg -l rsync telnet ftp 2>/dev/null | grep ^ii
sudo apt purge -y rsync telnet ftp 2>/dev/null
for r in \
  package_rsync_removed \
  package_telnet_removed \
  package_ftp_removed; do
  sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --rule xccdf_org.ssgproject.content_rule_$r \
    /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
done
```

**Teoría de la herramienta:** `apt purge` borra el paquete **y** sus archivos de configuración. `apt remove` deja la configuración. Verás que apt también quita `ubuntu-standard`: es un *metapaquete* que solo agrupa paquetes, y borrarlo no quita nada más.

### 3.8 Permisos de archivos críticos (2 min)

**Teoría:** las tareas de `cron` corren como root. Si un usuario normal puede leer `/etc/crontab` o las carpetas `cron.*`, ve qué scripts se ejecutan y cuándo: el mapa perfecto para plantar código. CIS pide que solo root las vea (CIS Control 3.3).

```bash
ls -ld /etc/crontab /etc/cron.d /etc/cron.daily
sudo chmod og-rwx /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
ls -ld /etc/crontab /etc/cron.d /etc/cron.daily
for r in \
  file_permissions_crontab \
  file_permissions_cron_d \
  file_permissions_cron_daily \
  file_permissions_etc_shadow; do
  sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --rule xccdf_org.ssgproject.content_rule_$r \
    /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
done
```

**Teoría de la herramienta:** `og-rwx` quita lectura, escritura y ejecución al grupo (`g`) y a otros (`o`). El dueño, root, conserva sus permisos.

### 3.9 Banners de aviso legal (2 min)

**Teoría:** el banner cumple dos funciones:
- **Legal:** advierte que el acceso es monitoreado, lo que respalda acciones legales contra un intruso.
- **Técnica:** el banner por defecto de Ubuntu muestra la versión exacta del sistema y le regala información al atacante.

```bash
cat /etc/issue /etc/issue.net
echo "Acceso autorizado unicamente. Toda la actividad es monitoreada y registrada." | sudo tee /etc/issue /etc/issue.net
for r in \
  banner_etc_issue_cis \
  banner_etc_issue_net_cis \
  sshd_enable_warning_banner_net; do
  sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --rule xccdf_org.ssgproject.content_rule_$r \
    /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
done
```

Desde otra ventana conéctate por SSH: debes ver el aviso antes de que te pida la contraseña.

### 3.10 Registros persistentes (3 min)

**Teoría:** sin logs no hay investigación de incidentes (CIS Control 8.2). `Storage=persistent` guarda el journal en disco y `Compress=yes` lo comprime para que ocupe menos.

> En la verificación, las dos reglas salen `notapplicable`. Es correcto: Ubuntu usa **rsyslog** además de journald, y CIS solo exige estas reglas cuando journald es el único sistema de registro. Se aplican igual porque son buena práctica y Lynis sí las valora.

```bash
sudo mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=persistent\nCompress=yes\n' | sudo tee /etc/systemd/journald.conf.d/60-hardening.conf
sudo systemctl restart systemd-journald
ls -d /var/log/journal
for r in \
  journald_storage \
  journald_compress; do
  sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --rule xccdf_org.ssgproject.content_rule_$r \
    /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
done
```

### 3.11 Actualizaciones automáticas de seguridad (2 min)

**Teoría:** CIS Control 7.3 pide parchar el sistema operativo de forma automática. `unattended-upgrades` instala solo las actualizaciones de **seguridad**, que son las de menor riesgo de romper algo. Esta regla no está en el perfil de OpenSCAP, pero Lynis sí la evalúa.

```bash
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -f noninteractive unattended-upgrades
cat /etc/apt/apt.conf.d/20auto-upgrades
sudo unattended-upgrade --dry-run --debug 2>&1 | tail -n 5
```

### 3.12 (bonus) Auditoría con auditd y AppArmor

**Teoría:** auditd registra en el kernel **quién** tocó **qué** archivo y **cuándo**, incluso si el atacante borra el historial de bash. Es un control de **CIS Nivel 2**, así que no aparece en el L1 que escaneaste.

```bash
sudo apt install -y auditd
echo '-w /etc/passwd -p wa -k identidad' | sudo tee /etc/audit/rules.d/50-identidad.rules
echo '-w /etc/sudoers -p wa -k privilegios' | sudo tee -a /etc/audit/rules.d/50-identidad.rules
sudo augenrules --load
sudo useradd prueba
sudo ausearch -k identidad -i | tail -n 5
```

¿Puedes ver **quién** modificó `/etc/passwd` y **cuándo**?

**Teoría:** `-w` vigila un archivo, `-p wa` registra escrituras y cambios de atributos, y `-k` le pone una etiqueta para buscar después con `ausearch -k`.

AppArmor:
```bash
sudo aa-status | grep -E 'profiles are in (enforce|complain) mode'
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --rule xccdf_org.ssgproject.content_rule_all_apparmor_profiles_in_enforce_complain_mode \
  /home/brian/ssg-ubuntu2204-ds.xml 2>/dev/null | grep -E '^(Title|Result)'
```

---

## Lab 4 · Remediación automática con control (10 min)

**Teoría:** cada regla del datastream trae su script de corrección. `generate fix` arma un solo script con las correcciones de las reglas que fallaron en `antes.xml`. Con `--result-id ""` toma el primer resultado del archivo.

Es potente, pero **ciego**: aplica la regla tal como la escribió CIS, sin saber si tu servidor la necesita. Por eso **primero se lee y después se ejecuta**.

```bash
cd /home/brian
oscap xccdf generate fix --fix-type bash --result-id "" antes.xml > fix.sh
grep -c 'BEGIN fix' fix.sh                # cuántas correcciones trae
grep 'BEGIN fix' fix.sh | less            # cuáles son (q para salir)
```

> El mismo comando con `--fix-type ansible` genera un playbook. Es útil para endurecer muchos servidores a la vez.

**Detente y busca en el script** las correcciones que pueden afectar el acceso:

```bash
grep -nE 'BEGIN fix.*(faillock|ufw|nftables|iptables|journald|sshd|pam|apparmor|grub|aide)' /home/brian/fix.sh
```

| Si ves... | Riesgo |
| --- | --- |
| `package_ufw_removed` | **Desinstala ufw.** El perfil acepta ufw, nftables o iptables, y su valor por defecto es nftables. Deshace todo el bloque 3.2 y deja el servidor sin firewall |
| `nftables` / `iptables` | Correcciones para los otros firewalls, que tú no elegiste |
| `journald_disable_forward_to_syslog` | journald deja de pasarle los eventos a rsyslog: `/var/log/auth.log` y `/var/log/syslog` dejan de crecer. CIS lo pide solo si usas journald **en lugar de** rsyslog, y Ubuntu usa los dos |
| `faillock` | Bloquea la cuenta 15 minutos tras 4 contraseñas fallidas: puedes bloquearte tú mismo |
| `sshd` | Cambia la configuración de SSH |
| `grub` | Pide contraseña al arrancar o cambia la configuración de arranque |
| `aide` | Instala AIDE y, de paso, **postfix**, un servidor de correo que queda escuchando en todas las interfaces (puerto 25). Además, crear la base de datos de AIDE tarda bastante y parece que el script se detuvo |

**Quita del script las correcciones que no corresponden a tus decisiones (usar ufw y mantener rsyslog) y las de AIDE, que se instalan aparte (ver la tarea al final del Lab 5):**

```bash
awk '/^# BEGIN fix .*(package_ufw_removed|_nftables_|nftables_|_iptables|iptables_|journald_disable_forward_to_syslog|aide_)/{skip=1} !skip{print} /^# END fix for/{skip=0}' /home/brian/fix.sh > /home/brian/fix-seguro.sh
grep -c 'BEGIN fix' /home/brian/fix.sh /home/brian/fix-seguro.sh
grep -E 'BEGIN fix.*(ufw|nftables|iptables|journald|aide)' /home/brian/fix-seguro.sh
```

**Teoría:** cada corrección del script empieza con `# BEGIN fix` y termina con `# END fix for`. El `awk` copia el archivo completo, pero se salta los bloques cuyo nombre coincide con la lista: la que desinstala ufw, las de nftables e iptables, la que corta el paso de eventos de journald a rsyslog y las de AIDE. La segunda línea muestra cuántas correcciones quedaron en cada archivo; la tercera debe listar **solo** reglas de ufw. En una auditoría real esto se llama **adaptar el benchmark a tu decisión de arquitectura**, en lugar de aplicarlo a ciegas.

> **Sobre faillock:** esa corrección se queda en el script, porque es un control válido. Desde que lo ejecutes, **4 contraseñas incorrectas bloquean la cuenta durante 15 minutos.** Si te pasa, entra por la consola de VirtualBox y ejecuta `sudo faillock --user brian --reset`.

> **Toma un SNAPSHOT de la VM ahora** y **no cierres tu sesión SSH actual.**

```bash
sudo bash /home/brian/fix-seguro.sh 2>&1 | tee /home/brian/fix.log
grep -ciE 'error|fail' /home/brian/fix.log
```

**Comprueba que no perdiste nada:**

```bash
sudo ufw status verbose          # debe seguir "Status: active" con tus reglas
sudo sshd -t && echo "SSH OK"
sudo ss -tlnp | grep ':25 ' || echo "Sin servidor de correo escuchando"
```

Desde **otra ventana**, entra con `ssh brian@IP_UBUNTU`. Solo cuando conecte, cierra la sesión anterior.

---

## Lab 5 · Volver a medir y comparar (17 min)

### 5.1 OpenSCAP "después" (6 min)

```bash
cd /home/brian
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --results /home/brian/despues.xml \
  --report /home/brian/despues.html \
  /home/brian/ssg-ubuntu2204-ds.xml > /home/brian/despues.txt 2>/dev/null
grep -c 'Result.*pass$' despues.txt
grep -c 'Result.*fail$' despues.txt
awk -F'\t' '/^Title/{t=$2} /^Result/ && $2=="fail"{print t}' despues.txt   # qué sigue en FAIL
```

### 5.2 Lynis "después" y comparación en HTML (6 min)

```bash
sudo lynis audit system --quick \
  --report-file /home/brian/lynis-despues.dat --log-file /home/brian/lynis-despues.log

sudo python3 lynis2html.py lynis-antes.dat lynis-despues.dat -o lynis-comparacion.html
```

**Teoría:** con dos archivos, `lynis2html.py` cruza los hallazgos por ID de prueba y los separa en tres grupos:

| Grupo | Significa |
| --- | --- |
| **Corregidos** | Estaban antes y ya no aparecen: tu hardening funcionó |
| **Nuevos** | No estaban antes. Suelen salir porque ahora Lynis puede revisar algo que antes no existía, por ejemplo reglas de auditd |
| **Pendientes** | Siguen ahí: corrígelos o justifícalos como riesgo aceptado |

> Lynis y CIS **no siempre coinciden**. Por ejemplo, después del bloque 3.1 Lynis sugiere `MaxAuthTries 3`, mientras CIS pide 4 o menos. Ninguno está mal: son criterios distintos. En una auditoría manda el estándar que la organización adoptó.

### 5.3 Vista desde afuera con Kali (5 min)

Desde **Kali**:

```bash
ssh-audit IP_UBUNTU > despues-ssh.txt
nmap -sV IP_UBUNTU -oN despues-nmap.txt
diff antes-nmap.txt despues-nmap.txt

scp brian@IP_UBUNTU:/home/brian/despues.html .
scp brian@IP_UBUNTU:/home/brian/lynis-comparacion.html .
firefox despues.html lynis-comparacion.html &
```

¿Hay menos rojo en `ssh-audit`? ¿nmap ve menos puertos?

### 5.4 Tarea para casa: AIDE

AIDE guarda una "foto" de los archivos del sistema y avisa si algo cambia (CIS lo pide en el Nivel 1). Para enviar sus avisos por correo, AIDE **siempre** instala un servidor de correo (postfix). La clave es configurarlo como **solo local**, para que no quede escuchando en la red:

```bash
echo "postfix postfix/main_mailer_type select Local only" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt install -y aide
sudo ss -tlnp | grep ':25 '            # debe decir 127.0.0.1, no 0.0.0.0
sudo aideinit -y -f                    # crea la base de datos: tarda varios minutos
sudo ls -lh /var/lib/aide/
```

**Teoría:**
- `debconf-set-selections` deja respondida de antemano la pregunta que haría el instalador de postfix. "Local only" significa que solo entrega correo a usuarios del propio servidor.
- `DEBIAN_FRONTEND=noninteractive` hace que apt no muestre pantallas de configuración y use las respuestas guardadas.
- `aideinit` recorre el disco y guarda la suma de verificación de cada archivo vigilado. Después, `sudo aide --check -c /etc/aide/aide.conf` compara el sistema actual con esa foto.

### 5.5 Preguntas para tu entrega

1. ¿Cuántas reglas pasaron antes y después en OpenSCAP? ¿Cuánto subió el Hardening index de Lynis?
2. ¿Por qué los dos números no suben igual? Pista: uno mide cumplimiento CIS y el otro buenas prácticas generales.
3. Elige **una** regla que sigue en FAIL y explica por qué no se arregló. Pistas:
   - Las particiones separadas (`partition_for_tmp`) requieren reinstalar.
   - El perfil incluye `package_ufw_installed` **y** `package_ufw_removed`, porque CIS acepta ufw **o** nftables **o** iptables. Al elegir uno, las reglas de los otros quedan en FAIL. Es un **riesgo aceptado**.
   - `grub2_password` es una decisión del administrador.
4. ¿Qué corrección del Lab 4 **no** habrías aplicado en un servidor de producción, y por qué?

---

## Entrega (pull request)

Archivo: `entregas/clase-03/<tu-apellido>.md`

- [ ] Respuestas del Lab 1 y Lab 1b (35 preguntas, una línea cada una).
- [ ] Puntaje OpenSCAP **antes** y **después** (pass / fail).
- [ ] Hardening index de Lynis antes y después, con capturas de `lynis-comparacion.html`.
- [ ] 6 bloques del Lab 3 explicados: qué cambiaste, por qué, y el resultado del `oscap` de verificación.
- [ ] 1 regla que quedó en FAIL y por qué se acepta.
- [ ] Extracto de `ssh-audit` antes y después.
- [ ] Respuestas de la sección 5.4.

---

## Errores comunes

| Síntoma | Causa | Solución |
| --- | --- | --- |
| `grep -E` no muestra nada | Pusiste barra invertida antes de la barra vertical | Con `-E`, el "o" va sin barra invertida (ver el comando 10) |
| Decenas de `Obtrusive data from probe!` | Advertencias de oscap 1.2.17 | Inofensivas: usa `2>/dev/null` |
| `echo $?` da `2` | Hay reglas en FAIL | Es lo esperado |
| `oscap ... Unable to open file` | El datastream no está en `/home/brian` | Ejecuta `ls -lh /home/brian/ssg-ubuntu2204-ds.xml` |
| `apt update` no conecta | El firewall bloquea la salida | Revisa las reglas `allow out` del 3.2: DNS 53, 80 y 443 |
| Me quedé fuera por SSH | ufw activado sin permitir SSH, error en `sshd`, o intentaste entrar como root | Entra como `brian` (root ya no puede por SSH); si no, por la consola de VirtualBox o vuelve al snapshot |
| La terminal se cierra sola | `TMOUT=900` del bloque 3.3: 15 minutos sin escribir | Es el control funcionando. Vuelve a entrar |
| El cliente SSH no conecta tras el 3.1b | Cliente muy antiguo sin algoritmos modernos | Actualiza PuTTY o MobaXterm, o usa el OpenSSH de Windows o Kali |
| `sshd -t` muestra un error | Error de tipeo en el `.conf` | Corrige y vuelve a probar antes de recargar |
| `su -` ya no funciona | Es el efecto del 3.4: el grupo `sugroup` está vacío | Usa `sudo -i` |
| `rp_filter` sigue en FAIL | Otro archivo de `sysctl.d` dice `rp_filter=2` | Repite el `grep` del 3.5 y comenta esa línea |
| `log_martians` sigue en FAIL | `/etc/ufw/sysctl.conf` dice `log_martians=0` | Aplica el segundo `sed` del 3.5 |
| `scp` no conecta desde Kali | IP equivocada o ufw | Revisa `ip -br a` y `sudo ufw status` |
| `scp` da *Permission denied* | Los reportes los creó root | En Ubuntu: `sudo chown brian /home/brian/*` |
| Me bloqueé tras fallar la contraseña | La corrección de `faillock` del Lab 4 (4 intentos, 15 min) | Espera 15 minutos o, desde la consola de VirtualBox: `sudo faillock --user brian --reset` |
| Después del Lab 4 aparece el puerto 25 | Ejecutaste `fix.sh` completo y AIDE instaló postfix | `sudo postconf -e 'inet_interfaces = loopback-only'` y `sudo systemctl restart postfix` |
| `fs.suid_dumpable` vuelve a `2` tras reiniciar | apport lo cambia al arrancar | Repite el 3.6: `sudo systemctl mask apport` |
| `/var/log/auth.log` dejó de crecer | Ejecutaste `fix.sh` completo: journald ya no le pasa eventos a rsyslog | `sudo sed -i '/^ForwardToSyslog=no/d' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/60-hardening.conf` y `sudo systemctl restart systemd-journald` |
| Después del Lab 4, `ufw` ya no existe | Ejecutaste `fix.sh` en vez de `fix-seguro.sh` | Vuelve al snapshot, o reinstala con `sudo apt install -y ufw` y repite el bloque 3.2 |
