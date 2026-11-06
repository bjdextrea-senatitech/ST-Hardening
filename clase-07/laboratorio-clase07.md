# Clase 7 · Laboratorio — Hardening en la nube con Microsoft Azure

**SENATI · Diplomado Gestión de la Ciberseguridad · Módulo 04 "Aseguramiento de los Sistemas"**
**Docente:** Ademir Cuadros · **Fecha:** jueves 05/11 · **Duración de la práctica:** 2 horas (+ Lab 6 opcional / tarea)
## Antes de empezar (leer 2 minutos)

- **Cuenta:** cada alumno trabaja en **su propia cuenta gratuita de Azure** (US$200 de crédito por 30 días).
  Crearla es parte del laboratorio (paso **0.0**): así aprendes cómo nace una suscripción y quién responde por ella.
  Si usas **Azure for Students**, funciona igual salvo el usuario "practicante" (los controles IAM saldrán N/A).
- **¿Tu tarjeta no pasa o ya usaste la prueba gratuita antes?** Trabaja en pareja con un compañero
  (uno ejecuta, el otro anota y revisa) y crea tu cuenta como tarea.
- **Todo lo que crees se borra al final** con `99-limpiar.sh`. El primer paso del laboratorio es una
  **alerta de presupuesto**: nunca trabajes en la nube sin ella.
- **Una sola máquina:** la VM Ubuntu (usuario `brian`). Si tu usuario no es `brian`, reemplaza `/home/brian/`.
- **Variables:** los scripts guardan los nombres en `/home/brian/c7/entorno.env`. **Cada vez que abras una
  terminal nueva** ejecuta `source /home/brian/c7/entorno.env` (si no, los comandos salen con nombres vacíos).
- **Sin reglas de firewall en la VM.** Azure CLI y Prowler salen por HTTPS (443), que el ufw de la Clase 3 ya permite.
- Resultados en **`/home/brian/c7/antes/`** y **`/home/brian/c7/despues/`**.

### Tarea previa (después de la Clase 6, 20 min)

1. Hacer el paso **0.0** (crear tu cuenta gratuita) si no lo terminaste en clase.
2. Hacer los pasos **0.2 y 0.3** (instalar Azure CLI y Prowler: unos 5 minutos de descarga).

---

## Agenda de la práctica (120 min)

| Bloque | Min | Qué haces | Si vas corto → tarea |
|--------|-----|-----------|----------------------|
| Lab 0 · Preparación | 25 | Crear tu cuenta gratuita, presupuesto, Azure CLI, Prowler, inicio de sesión | 0.3 Prowler (se usa en Lab 2) |
| Lab 1 · Crear y reconocer el entorno inseguro | 10 | Script de sabotaje y recorrido | — |
| Lab 1b · Qué obtiene un atacante | 10 | Datos públicos, llaves, Owner de más | 1b.4 |
| Lab 2 · Medir (antes) | 15 | Auditor propio + Prowler (CIS Azure) | — |
| Lab 3 · Endurecer | 35 | Identidad, almacenamiento, red, registros, gobierno | 3E.4 |
| Lab 4 · Re-medir (después) | 10 | Mismas herramientas, tabla comparativa | — |
| Lab 5 · Pruebas desde afuera y limpieza | 10 | Política, bloqueo, alerta, borrar todo | — |
| Entrega | 5 | Pull Request | — |
| Lab 6 · Opcional | — | Secure Score, equivalencias con AWS | todo |

---

## Lo que vamos a construir (y romper)

```
  Suscripción (tu cuenta gratuita)
  └── Grupo de recursos  rg-c7-senati
      ├── Cuenta de almacenamiento  stc7xxxxxx
      │     └── contenedor "publico"  →  planilla-clientes.csv  (datos FICTICIOS)
      ├── NSG  nsg-c7-web  (reglas: SSH y RDP desde cualquier lugar)
      └── (Lab 3) Log Analytics, grupo de acciones, alerta, política, bloqueo
  Entra ID (directorio)
  └── usuario practicante-c7  →  rol Owner en TODA la suscripción
```

| Riesgo sembrado | Caso real parecido |
|-----------------|--------------------|
| Contenedor de blobs público con datos personales | Filtraciones por *buckets* y contenedores públicos |
| Llave de la cuenta de almacenamiento con acceso total | Microsoft AI, 2023: un token SAS demasiado amplio expuso 38 TB |
| SSH/RDP abiertos a internet | Fuerza bruta y explotación de servicios expuestos |
| Usuario con Owner en toda la suscripción | Exceso de privilegios: una cuenta robada = toda la nube |
| Sin registros ni alertas | Incidentes que nadie ve a tiempo |

---

## Teoría mínima de comandos

| Comando | Qué hace |
|---------|----------|
| `az login --use-device-code` | Inicia sesión desde una terminal sin navegador (te da un código para el navegador del PC) |
| `az account show` | Muestra la suscripción activa |
| `az group create / delete` | Crea o borra un grupo de recursos (borrar el grupo borra todo lo que contiene) |
| `az <servicio> show` | Muestra la configuración real de un recurso (en JSON) |
| `--query "..."` | Filtra la salida con JMESPath (como un `grep` para JSON) |
| `-o table` / `-o tsv` | Formato de salida legible o para usar en scripts |
| `prowler azure --az-cli-auth` | Audita la suscripción usando la sesión de Azure CLI |

---

## Lab 0 · Preparación (25 min)

### 0.0 Crear tu cuenta gratuita de Azure (10 min)

Una suscripción de Azure es un **contrato de facturación**: todo recurso que crees vive dentro de una y alguien
paga por él. La cuenta gratuita trae **US$200 por 30 días** y **protección de gasto**: no te cobran nada
mientras no pases tú mismo a "pago por uso".

1. En tu PC entra a **azure.microsoft.com/free** → **Try Azure for free** (*Probar Azure gratis*).
   No elijas *Pay as you go*: esa opción no trae el crédito.
2. Inicia sesión con tu **cuenta Microsoft** (Outlook/Hotmail) o crea una en ese momento.
3. **Step 1 of 3 · Profile information**
   - *How do you plan to use…*: **For personal use**.
   - *Country/Region*: **Peru**. **No se puede cambiar después** y debe coincidir con el país de tu tarjeta.
   - Nombre, apellido, correo y celular (sin +51). *Job title* es opcional.
   - Resuelve la verificación de seguridad, acepta el contrato y haz clic en **Next**.
4. **Step 2 of 3 · Identity verification**: te llega un código por SMS al celular; escríbelo.
5. **Step 3 of 3 · Payment information**: tarjeta de crédito o débito (Visa, Mastercard o Amex).
   - Sirve **solo para verificar tu identidad**: puede aparecer una retención temporal de ~US$1 que se anula sola.
   - *Postal Code* es opcional: **déjalo vacío** (no pongas 51, que es el código de país).
   - Clic en **Sign up**.
6. Espera 1–2 minutos y entra a **portal.azure.com** → busca **Suscripciones**: debe aparecer
   **Azure subscription 1** con estado **Activo**.

> **¿Me van a cobrar?** No. Si se acaba el crédito o pasan los 30 días, Azure **desactiva** los recursos y te
> pregunta si quieres pasar a pago por uso. Si no aceptas, no hay cobro. Igual borraremos todo al final.

> **Problemas típicos:** *Card declined* → activa las **compras por internet / en el extranjero** en la app
> de tu banco y reintenta (las de crédito pasan mejor que las de débito). *You're not eligible* → la prueba es
> una sola vez por persona, tarjeta y teléfono: trabaja en pareja hoy.

### 0.1 Alerta de presupuesto (portal, 3 min) — siempre primero

1. Entra a **portal.azure.com** → busca **Cost Management** → **Presupuestos** (*Budgets*) → **Agregar**.
2. Ámbito: tu suscripción · Nombre: `presupuesto-lab` · Periodo: mensual · Importe: **5 USD**.
3. Alertas: **50 %**, **80 %** y **100 %** del presupuesto real → tu correo → **Crear**.

> En la cuenta gratuita, el crédito ya actúa como límite de gasto. Pero en una cuenta de empresa no hay
> límite: el presupuesto es la primera alarma. CIS lo considera control básico de gobierno.

### 0.2 Instalar Azure CLI en el Ubuntu (repositorio oficial de Microsoft)

```bash
# Paquetes necesarios para agregar un repositorio HTTPS firmado
sudo apt update && sudo apt install -y ca-certificates curl gnupg lsb-release
# Carpeta para las llaves de repositorios
sudo mkdir -p /etc/apt/keyrings
# Descarga la llave de Microsoft y la convierte al formato de apt
curl -sLS https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /etc/apt/keyrings/microsoft.gpg > /dev/null
# Declara el repositorio de Azure CLI para tu versión de Ubuntu (jammy)
printf 'Types: deb\nURIs: https://packages.microsoft.com/repos/azure-cli/\nSuites: %s\nComponents: main\nArchitectures: %s\nSigned-by: /etc/apt/keyrings/microsoft.gpg\n' "$(lsb_release -cs)" "$(dpkg --print-architecture)" | sudo tee /etc/apt/sources.list.d/azure-cli.sources
# La umask 027 de la Clase 3 deja la llave sin lectura para apt: le damos lectura
sudo chmod 644 /etc/apt/keyrings/microsoft.gpg /etc/apt/sources.list.d/azure-cli.sources
# Instala Azure CLI
sudo apt update && sudo apt install -y azure-cli
# Muestra la versión instalada
az version --query '"azure-cli"' -o tsv
```

### 0.3 Instalar Prowler (auditor de nube de código abierto) en un entorno virtual de Python

```bash
# Herramienta de entornos virtuales de Python (el Ubuntu 22.04 trae Python 3.10)
sudo apt install -y python3-venv
# Crea un entorno aislado solo para Prowler en tu home
python3 -m venv /home/brian/prowler
# Instala Prowler dentro de ese entorno (tarda 2–5 minutos)
/home/brian/prowler/bin/pip install --upgrade pip prowler
# Muestra la versión
/home/brian/prowler/bin/prowler --version
```

### 0.4 Materiales e inicio de sesión

```bash
# Actualiza el repositorio del curso y copia la carpeta de la clase
cd /home/brian/senati-m4-aseguramiento && git pull
cp -r /home/brian/senati-m4-aseguramiento/clase-07-azure /home/brian/
# Inicia sesión: abre en tu PC la URL que muestra y escribe el código
az login --use-device-code
# Confirma la suscripción activa y el tipo de oferta
az account show --query "{suscripcion:name, id:id, usuario:user.name}" -o table
# Muestra tu usuario en Entra ID (fíjate: con cuenta personal termina en #EXT#@...onmicrosoft.com)
az ad signed-in-user show --query "{upn:userPrincipalName, id:id}" -o table
```

> Si tienes varias suscripciones: `az account set --subscription "<nombre o id>"`.

**Checkpoint 0:** presupuesto creado, `az version` y `prowler --version` funcionan, sesión iniciada.

---

## Lab 1 · Crear y reconocer el entorno inseguro (10 min)

```bash
# Lee el script antes de ejecutarlo: qué crea y qué errores siembra
less /home/brian/clase-07-azure/scripts/00-crear-entorno-inseguro.sh
# Ejecútalo (región por defecto eastus; tarda 2–4 minutos)
bash /home/brian/clase-07-azure/scripts/00-crear-entorno-inseguro.sh
# Carga las variables que dejó el script
source /home/brian/c7/entorno.env
# Revisa los nombres
cat /home/brian/c7/entorno.env
```

```bash
# Lista lo que hay en el grupo de recursos
az resource list -g $RG --query "[].{nombre:name, tipo:type}" -o table
# Configuración de seguridad de la cuenta de almacenamiento
az storage account show -n $SA -g $RG --query "{publico:allowBlobPublicAccess, soloHttps:enableHttpsTrafficOnly, tls:minimumTlsVersion, claveCompartida:allowSharedKeyAccess}" -o table
# Reglas del NSG: SSH y RDP desde "*" (cualquier lugar)
az network nsg rule list -g $RG --nsg-name $NSG --query "[].{regla:name, puerto:destinationPortRange, origen:sourceAddressPrefix, accion:access}" -o table
# Roles del practicante: Owner en toda la suscripción
az role assignment list --assignee $PRACT_ID --all --query "[].{rol:roleDefinitionName, ambito:scope}" -o table
```

> En el portal: abre `rg-c7-senati` y recorre los 3 recursos. Mira la cuenta de almacenamiento →
> *Configuración* → la opción "Permitir acceso anónimo de blobs" está **habilitada**.

---

## Lab 1b · Qué obtiene un atacante (10 min)

```bash
# 1b.1 · Cualquiera en internet descarga el CSV, sin usuario ni clave
curl -s https://$SA.blob.core.windows.net/publico/planilla-clientes.csv
# 1b.2 · Peor: con acceso "container" se lista todo; con acceso "blob" basta adivinar o filtrar el nombre
curl -s "https://$SA.blob.core.windows.net/publico?restype=container&comp=list" | head -c 300; echo
```

```bash
# 1b.3 · Las 2 llaves de la cuenta dan control TOTAL de los datos y se saltan los roles (RBAC)
az storage account keys list -n $SA -g $RG --query "[].{llave:keyName, permisos:permissions}" -o table
```

> Quien obtenga una llave (en un script, un repositorio, un `.env`) entra a todos los datos de la cuenta.
> Con ellas también se firman tokens SAS. Es el origen del caso de los 38 TB de Microsoft AI (2023).

```bash
# 1b.4 · El practicante es Owner de la suscripción: puede crear, borrar y dar permisos a otros
az role definition list --name Owner --query "[0].{rol:roleName, acciones:permissions[0].actions}" -o json
# 1b.5 · El NSG permite SSH desde cualquier IP: si se asocia a una VM, queda expuesta a fuerza bruta
az network nsg rule show -g $RG --nsg-name $NSG -n permitir-ssh-internet --query "{origen:sourceAddressPrefix, puerto:destinationPortRange}" -o table
```

**Checkpoint 1b:** anota en tu entrega qué paso del Lab 3 corta cada uno de los 5 puntos.

---

## Lab 2 · Medir: la línea base "antes" (15 min)

### 2.1 Auditor propio (18 controles, segundos)

```bash
# Revisa identidad, almacenamiento, red, registros y gobierno; guarda el resultado
bash /home/brian/clase-07-azure/scripts/auditar-azure.sh -o /home/brian/c7/antes/azure.md
```

### 2.2 Prowler con CIS Microsoft Azure Foundations 6.0 (3–6 min)

```bash
# Audita 6 servicios de la suscripción y además mapea el resultado al CIS Azure 6.0
/home/brian/prowler/bin/prowler azure --az-cli-auth --service storage network monitor defender policy iam --compliance cis_6.0_azure --output-formats csv html --output-directory /home/brian/c7/antes --output-filename prowler-antes
```

```bash
# Cuenta los resultados del CSV: cuántos FAIL y PASS hay
cut -d';' -f1-40 /home/brian/c7/antes/prowler-antes.csv | grep -o ';FAIL;\|;PASS;' | sort | uniq -c
# Lista los FAIL de almacenamiento y red (los que vamos a corregir)
grep ';FAIL;' /home/brian/c7/antes/prowler-antes.csv | grep -oE '(storage|network)_[a-z0-9_]+' | sort -u
```

> El informe HTML (`prowler-antes.html`) se puede copiar a tu PC con `scp` y abrir en el navegador.

### 2.3 Defender for Cloud (solo lectura)

```bash
# Registra el proveedor de Defender (si ya está, no pasa nada)
az provider register --namespace Microsoft.Security
# Plan de postura: "Free" = Foundational CSPM (gratis). No actives los planes de pago
az security pricing show -n CloudPosture --query "{plan:name, nivel:pricingTier}" -o table
# Puntuación de seguridad (Secure Score). En una suscripción nueva puede tardar horas en aparecer
az security secure-scores list --query "[].{nombre:displayName, actual:score.current, maximo:score.max}" -o table
```

> **Por qué Prowler y no solo el Secure Score:** Defender recalcula sus recomendaciones cada varias horas.
> Prowler mide en el momento y nos deja ver el "después" en la misma clase. El Secure Score se revisa mañana (Lab 6).

**Checkpoint 2:** tienes `azure.md` y los archivos `prowler-antes.*` en `/home/brian/c7/antes/`.

---

## Lab 3 · Endurecer (45 min)

```bash
# Por si abriste otra terminal: carga las variables y define tu correo para las alertas
source /home/brian/c7/entorno.env
CORREO="tu-correo@ejemplo.com"
# Identificadores que usaremos varias veces
RGID=/subscriptions/$SUB/resourceGroups/$RG
SAID=$(az storage account show -n $SA -g $RG --query id -o tsv)
echo "RG=$RG SA=$SA NSG=$NSG CORREO=$CORREO"
```

### 3A · Identidad: mínimo privilegio (8 min)

```bash
# Quita el rol Owner del practicante a nivel de toda la suscripción
az role assignment delete --assignee $PRACT_ID --role Owner --scope /subscriptions/$SUB
# Le da solo lectura y solo sobre el grupo del laboratorio (mínimo privilegio y mínimo ámbito)
az role assignment create --assignee-object-id $PRACT_ID --assignee-principal-type User --role Reader --scope $RGID
# Una cuenta que no se usa se deshabilita (no se deja activa "por si acaso")
az ad user update --id $PRACT_ID --account-enabled false
# Verifica: solo Reader en rg-c7-senati
az role assignment list --assignee $PRACT_ID --all --query "[].{rol:roleDefinitionName, ambito:scope}" -o table
```

**MFA para todos (portal, 2 min):** **Microsoft Entra ID** → *Información general* → *Propiedades* →
**Administrar valores de seguridad predeterminados** → debe estar **Habilitado**.
En los directorios nuevos viene activo. Si tu organización usa Acceso condicional (licencia P1),
este control lo reemplaza y se desactiva a propósito.

```bash
# Comprueba por comando (si da error de permisos, quédate con lo que viste en el portal)
az rest --method get --url https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy --query isEnabled
```

### 3B · Almacenamiento: nada público, solo HTTPS, sin llaves (15 min)

```bash
# 1) Primero te das permiso de DATOS con tu identidad (Entra ID), porque luego apagaremos las llaves
az role assignment create --assignee-object-id $YO_ID --assignee-principal-type User --role "Storage Blob Data Contributor" --scope $SAID
```

> Las asignaciones de rol tardan **1 a 5 minutos** en aplicarse. Mientras tanto, sigue con los pasos 2 a 4.

```bash
# 2) Apaga el acceso anónimo en TODA la cuenta, exige HTTPS y TLS 1.2
az storage account update -n $SA -g $RG --allow-blob-public-access false --https-only true --min-tls-version TLS1_2 -o none
# 3) Deja el contenedor privado también (defensa en profundidad)
az storage container-rm update --storage-account $SA -g $RG -n publico --public-access off -o none
# 4) Eliminación temporal: 7 días para recuperar blobs y contenedores borrados por error o por ransomware
az storage account blob-service-properties update -n $SA -g $RG --enable-delete-retention true --delete-retention-days 7 --enable-container-delete-retention true --container-delete-retention-days 7 -o none
# Comprueba desde "afuera": ahora la descarga anónima falla (409 PublicAccessNotPermitted)
curl -s -o /dev/null -w '%{http_code}\n' https://$SA.blob.core.windows.net/publico/planilla-clientes.csv
```

```bash
# 5) Apaga las llaves compartidas: desde ahora solo se entra con identidad de Entra ID + rol
az storage account update -n $SA -g $RG --allow-shared-key-access false -o none
# Tú sigues pudiendo leer, pero con tu identidad (--auth-mode login), no con la llave
az storage blob list --account-name $SA -c publico --auth-mode login --query "[].name" -o tsv
```

> Si sale `AuthorizationPermissionMismatch`, el rol del paso 1 aún no se propagó: espera 2 minutos y repite.

```bash
# 6) Compartir SIN hacer público: enlace de solo lectura, firmado con tu identidad, válido 1 hora
FIN=$(date -u -d '+1 hour' '+%Y-%m-%dT%H:%MZ')
URL_SAS=$(az storage blob generate-sas --account-name $SA -c publico -n planilla-clientes.csv --permissions r --expiry $FIN --https-only --auth-mode login --as-user --full-uri -o tsv)
# Con el enlace temporal sí descarga (200); sin él, no
curl -s -o /dev/null -w 'Con SAS: %{http_code}\n' "$URL_SAS"
curl -s -o /dev/null -w 'Sin SAS: %{http_code}\n' https://$SA.blob.core.windows.net/publico/planilla-clientes.csv
```

> Este es el aprendizaje del caso Microsoft AI: un SAS **de usuario**, **de solo lectura**, **de un archivo**
> y **de una hora**; nunca un SAS de cuenta con todos los permisos y años de vigencia.

### 3C · Red: cerrar SSH y RDP a internet (5 min)

```bash
# Tu IP pública actual (la de tu casa o la del laboratorio)
MI_IP=$(curl -s https://api.ipify.org); echo "Mi IP: $MI_IP"
# RDP no se usa: se elimina la regla
az network nsg rule delete -g $RG --nsg-name $NSG -n permitir-rdp-internet
# SSH solo desde tu IP (en una empresa: desde la VPN o con Azure Bastion)
az network nsg rule update -g $RG --nsg-name $NSG -n permitir-ssh-internet --source-address-prefixes $MI_IP/32 -o none
# Verifica las reglas que quedan
az network nsg rule list -g $RG --nsg-name $NSG --query "[].{regla:name, puerto:destinationPortRange, origen:sourceAddressPrefix}" -o table
```

### 3D · Registros y alertas: que nada pase sin que te enteres (10 min)

```bash
# Espacio de Log Analytics: aquí se guardará el registro de actividad (la ingesta de "Azure Activity" es gratuita)
az monitor log-analytics workspace create -g $RG -n law-c7 -l $UBIC --retention-time 30 -o none
LAW=$(az monitor log-analytics workspace show -g $RG -n law-c7 --query id -o tsv)
# Envía el registro de actividad de TODA la suscripción a ese espacio (quién creó, cambió o borró qué)
az monitor diagnostic-settings subscription create -n c7-actividad -l $UBIC --workspace $LAW --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},{"category":"Policy","enabled":true},{"category":"Alert","enabled":true}]' -o none
```

```bash
# Grupo de acciones: a quién avisar (correo)
az monitor action-group create -g $RG -n ag-c7 --short-name agc7 --action email responsable $CORREO -o none
AG=$(az monitor action-group show -g $RG -n ag-c7 --query id -o tsv)
# Alerta: cada vez que alguien crea o cambia una regla de NSG en tu grupo de recursos, te llega un correo
az monitor activity-log alert create -g $RG -n alerta-cambio-nsg --scope $RGID --condition category=Administrative and operationName=Microsoft.Network/networkSecurityGroups/securityRules/write --action-group $AG --description "Cambio en una regla de NSG" -o none
# Verifica
az monitor activity-log alert list -g $RG --query "[].{alerta:name, activa:enabled}" -o table
```

> Revisa tu correo: Azure envía un aviso de que fuiste agregado al grupo de acciones `agc7`.

### 3E · Gobierno: Defender, política, etiquetas y bloqueo (7 min)

```bash
# 3E.1 · Contacto de seguridad: a quién avisa Defender for Cloud ante alertas
az security contact create -n default --emails $CORREO --alert-notifications '{"state":"On","minimalSeverity":"Medium"}' --notifications-by-role '{"state":"On","roles":["Owner"]}' -o none
```

```bash
# 3E.2 · Política: PROHÍBE crear o cambiar cuentas de almacenamiento con acceso público en este grupo
# Busca la definición integrada de Microsoft por su nombre visible (tarda unos segundos)
POL=$(az policy definition list --query "[?displayName=='Storage account public access should be disallowed'].name | [0]" -o tsv)
# Muestra qué efectos admite (audit, deny, disabled) y elige "deny"
EF=$(az policy definition show -n $POL --query "parameters.effect.allowedValues[?@=='Deny' || @=='deny'] | [0]" -o tsv); echo "Política $POL, efecto $EF"
# Asigna la política al grupo de recursos con efecto deny
az policy assignment create -n c7-sin-almacenamiento-publico --display-name "C7 - Storage account public access should be disallowed" --policy $POL --scope $RGID --params "{\"effect\":{\"value\":\"$EF\"}}" -o none
```

```bash
# 3E.3 · Etiquetas: quién es el dueño, qué entorno es y qué tan sensible (sin dueño no hay responsable)
az group update -n $RG --tags propietario=brian entorno=laboratorio clasificacion=interno -o none
# 3E.4 · Bloqueo: nadie puede borrar el grupo ni sus recursos por error (ni siquiera un Owner) sin quitarlo antes
az lock create -n no-borrar -g $RG --lock-type CanNotDelete --notes "Laboratorio C7: quitar antes de limpiar" -o none
az lock list -g $RG -o table
```

**Checkpoint 3:** descarga anónima con 409, SAS con 200, solo SSH desde tu IP, alerta creada, política y bloqueo.

---

## Lab 4 · Re-medir: "después" (10 min)

```bash
# Mismo auditor
bash /home/brian/clase-07-azure/scripts/auditar-azure.sh -o /home/brian/c7/despues/azure.md
# Mismo Prowler
/home/brian/prowler/bin/prowler azure --az-cli-auth --service storage network monitor defender policy iam --compliance cis_6.0_azure --output-formats csv html --output-directory /home/brian/c7/despues --output-filename prowler-despues
# Conteo de FAIL y PASS después
cut -d';' -f1-40 /home/brian/c7/despues/prowler-despues.csv | grep -o ';FAIL;\|;PASS;' | sort | uniq -c
```

### Tabla de resultados (cópiala en tu entrega)

| Medición | Antes | Después |
|----------|-------|---------|
| Auditor propio (% cumplimiento) | __ % | __ % |
| Prowler: cantidad de FAIL | __ | __ |
| Prowler: cantidad de PASS | __ | __ |
| Descarga anónima del CSV (código HTTP) | 200 | __ |
| Reglas del NSG abiertas a internet | 2 | __ |
| Roles del practicante | Owner (suscripción) | __ |

### Hallazgos que quedan (explícalos, no los "arregles a ciegas")

| Hallazgo de Prowler | Por qué queda | Decisión |
|---------------------|---------------|----------|
| Planes de Defender de pago apagados (Storage, Servers, etc.) | Cuestan dinero; en el laboratorio usamos solo Foundational CSPM | Aceptado (costo) |
| Sin *private endpoint* / acceso de red público en la cuenta | Requiere una red virtual y cuesta; lo vemos en teoría | Pendiente / diseño |
| Sin llaves gestionadas por el cliente (CMK) | Requiere Key Vault; el cifrado por defecto ya está activo | Aceptado |
| Almacenamiento con redundancia local (LRS) | GRS cuesta más; es un control de disponibilidad | Aceptado en laboratorio |
| Network Watcher / flow logs | Costo y requiere VNet | Pendiente |

---

## Lab 5 · Pruebas desde afuera y limpieza (10 min)

```bash
# 5.1 · La política bloquea una cuenta pública nueva (RequestDisallowedByPolicy)
az storage account create -n stc7prueba$RANDOM -g $RG -l $UBIC --sku Standard_LRS --allow-blob-public-access true -o none
```

> Si **se creó**, la política aún no se evalúa (puede tardar hasta 15 minutos): bórrala con
> `az storage account delete -n <nombre> -g $RG --yes` **después** de quitar el bloqueo, y repite la prueba más tarde.

```bash
# 5.2 · El bloqueo impide borrar (ScopeLocked)
az storage account delete -n $SA -g $RG --yes
# 5.3 · Dispara la alerta: cambia una regla de NSG (en 5–10 minutos llega el correo)
az network nsg rule update -g $RG --nsg-name $NSG -n permitir-ssh-internet --description "prueba de alerta" -o none
# 5.4 · Quién hizo qué: el registro de actividad de la última hora en el grupo
az monitor activity-log list -g $RG --offset 1h --query "[].{hora:eventTimestamp, quien:caller, operacion:operationName.localizedValue, estado:status.value}" -o table | head -15
```

### 5.5 Limpieza

Puedes borrar todo ahora o **mañana después de revisar el Secure Score** (Lab 6.1). Con el
presupuesto y la cuenta gratuita no hay riesgo, pero **no lo dejes más de 48 horas**.

```bash
# Borra el bloqueo, los roles y el usuario practicante, la exportación de actividad y el grupo completo
bash /home/brian/clase-07-azure/scripts/99-limpiar.sh
# Comprueba que el grupo ya no existe
az group exists -n rg-c7-senati
```

---

## Entrega (Pull Request)

Crea `clase-07/entregas/<tu-usuario>.md` con:

1. La **tabla de resultados** del Lab 4.
2. `azure.md` de **antes** y **después**.
3. El **Checkpoint 1b** (qué paso del Lab 3 corta cada punto).
4. Captura del correo de la alerta (5.3) o del error de la política (5.1).
5. Respuestas:
   - **P1.** En el modelo de responsabilidad compartida, ¿cuáles de los 18 controles del auditor son responsabilidad tuya y cuáles de Microsoft?
   - **P2.** ¿Por qué apagamos las llaves compartidas si ya habíamos quitado el acceso público?
   - **P3.** ¿Qué diferencia hay entre la política con efecto *deny* y el control STG-01? ¿Cuál evita que el error vuelva a pasar?
   - **P4.** El practicante quedó con Reader en un solo grupo y deshabilitado. ¿Qué haría falta en una empresa para que pida permisos de administrador solo cuando los necesita? (pista: PIM)
   - **P5.** Compara con la Clase 6: ¿qué se parece entre "no publicar el puerto de Redis" y "no hacer público el contenedor de blobs"?

---

## Lab 6 · Opcional / tarea

**6.1 Secure Score al día siguiente:** antes de limpiar, vuelve a mirar el puntaje y las recomendaciones.
```bash
# Puntuación actual
az security secure-scores list --query "[].{nombre:displayName, actual:score.current, maximo:score.max}" -o table
# Recomendaciones que siguen en estado "Unhealthy" en tu grupo
az security assessment list --query "[?contains(id, 'rg-c7-senati') && status.code=='Unhealthy'].displayName" -o tsv | sort -u
```

**6.2 Informe CIS completo de Prowler:** abre `prowler-despues.html` y el archivo de cumplimiento
`compliance/*cis_6.0_azure*.csv`. ¿Qué secciones del CIS quedan con más fallas?

**6.3 Equivalencias con AWS** (para quien trabaja con AWS):

| Azure | AWS |
|-------|-----|
| Entra ID + RBAC | IAM (usuarios, roles, políticas) |
| Valores de seguridad predeterminados (MFA) | MFA en root + políticas IAM |
| Storage account / contenedor de blobs | S3 bucket |
| "Permitir acceso anónimo de blobs" = false | S3 Block Public Access |
| SAS de usuario | URL prefirmada (*presigned URL*) |
| NSG | Security Group / NACL |
| Registro de actividad + Log Analytics | CloudTrail + CloudWatch Logs |
| Defender for Cloud (CSPM) | Security Hub |
| Azure Policy (deny) | SCP / AWS Config rules |
| Bloqueo CanNotDelete | Protección contra terminación / SCP |
| Presupuesto de Cost Management | AWS Budgets |
| Prowler `azure` | Prowler `aws` |

---

## Errores comunes

| Síntoma | Causa | Solución |
|---------|-------|----------|
| `apt update` falla con el repositorio de Microsoft | Llave sin lectura por la umask 027 | `sudo chmod 644 /etc/apt/keyrings/microsoft.gpg /etc/apt/sources.list.d/azure-cli.sources` |
| Los comandos usan nombres vacíos (`--name ''`) | Terminal nueva sin variables | `source /home/brian/c7/entorno.env` |
| `AADSTS...` o "token expired" | Sesión vencida | `az login --use-device-code` |
| `The subscription is not registered to use namespace...` | Proveedor de recursos sin registrar | `az provider register --namespace Microsoft.Storage` (o el que indique) y espera 1 minuto |
| `PublicAccessNotPermitted` al crear el contenedor (Lab 1) | Azure aún aplica el cambio de la cuenta | El script reintenta solo; si falla, vuelve a ejecutarlo |
| `AuthorizationPermissionMismatch` (3B) | El rol de datos aún no se propaga | Espera 2–5 minutos |
| `Insufficient privileges` al crear el usuario | Azure for Students | Sigue sin practicante: IAM sale N/A |
| *Card declined* al crear la cuenta | El banco bloquea compras por internet o en el extranjero | Actívalas en la app del banco; prueba con tarjeta de crédito |
| *You're not eligible for an Azure free account* | Ya usaste la prueba con ese correo, tarjeta o teléfono | Trabaja en pareja hoy |
| `az account show` sale vacío o "Please run az login" | La suscripción aún se está creando | Espera 2 minutos y repite `az login --use-device-code` |
| La política no bloquea (5.1) | Aún no se evalúa la asignación | Espera 15 minutos y repite |
| `ScopeLocked` al limpiar a mano | El bloqueo CanNotDelete | `az lock delete -n no-borrar -g $RG` (el script de limpieza ya lo hace) |
| Prowler: errores de Microsoft Graph | Permisos de lectura de Entra ID | No afectan a storage/network/monitor; continúa |
| `az storage account create` con nombre en uso | Los nombres de cuenta son únicos en todo Azure | Vuelve a ejecutar el script (genera otro sufijo) |

---

## Referencias

- CIS Microsoft Azure Foundations Benchmark v6.0 · Microsoft Cloud Security Benchmark (MCSB)
- Microsoft Learn: *Shared responsibility in the cloud*, *Prevent anonymous read access to blobs*,
  *Prevent Shared Key authorization*, *Create a user delegation SAS*, *Security defaults*
- Prowler (prowler.com, github.com/prowler-cloud/prowler)
- Wiz Research (2023): exposición de 38 TB por un token SAS de Microsoft AI
