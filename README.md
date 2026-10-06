<div align="center">

# 🛡️ Aseguramiento de los Sistemas
### Módulo 04 · Diplomado en Gestión de la Ciberseguridad — TECH SENATI

**Hardening y medición de cumplimiento, de principio a fin.**
Un módulo 100 % práctico y defensivo: aprende a endurecer sistemas reales y a *demostrar* su seguridad con números.

`Windows` · `Linux` · `MySQL` · `pfSense` · `Web` · `Cloud`

</div>

---

## 📖 Sobre el curso

La mayoría de los sistemas **nacen inseguros**: una instalación "de fábrica" deja servicios de más, cuentas débiles y cero auditoría. Este módulo enseña a cerrar esa brecha de forma sistemática.

A lo largo de 8 sesiones trabajamos siempre el **mismo método**, aplicado a una tecnología distinta cada clase:

> **Medir → Endurecer → Re-medir**
> Tomamos una "foto" del estado inicial con herramientas de cumplimiento, aplicamos las configuraciones de los *benchmarks*, y volvemos a medir para probar la mejora con un número.

No es teoría suelta: cada clase deja una máquina más segura que al empezar, y la evidencia de cuánto mejoró.

### ¿Qué vas a lograr?
- Aplicar **configuraciones seguras** en sistemas operativos, bases de datos, red, aplicaciones web y nube.
- Trabajar con **estándares y marcos internacionales**: CIS Controls & Benchmarks, NIST, ISO/IEC 27001 y 27002, PCI DSS.
- Medir el cumplimiento con **CIS-CAT** (Windows) y **OpenSCAP** (Linux).
- Fortalecer infraestructuras en **AWS y Azure** con buenas prácticas.
- Sumar habilidades prácticas de **hardening** muy demandadas en el mercado laboral.

---

## 🗓️ Las 8 clases

| # | Tema | Qué se trabaja |
|:-:|------|----------------|
| **01** | **Fundamentos + línea base** | Conceptos de aseguramiento, superficie de ataque, Defense in Depth y Zero Trust, marcos de referencia y el concepto de *baseline* medible. |
| **02** | **Windows (Server + Cliente)** | Línea base de Windows, parches, endurecimiento de cuentas y contraseñas, desactivación de servicios inseguros, cifrado y auditoría. |
| **03** | **Linux (Ubuntu Server)** | Línea base, gestión de parches y repositorios confiables, endurecimiento del sistema, control de servicios y auditoría. |
| **04** | **Base de Datos (MySQL)** | Línea base de MySQL, gestión de cuentas y privilegios, endurecimiento del motor, protocolos seguros y cifrado. |
| **05** | **Red (pfSense)** | Línea base del firewall, autenticación, reglas de filtrado, endurecimiento y registros de auditoría. |
| **06** | **Aplicación Web** | Desarrollo seguro, estándares y marcos para web, vulnerabilidades comunes, cifrado en tránsito, autenticación y monitoreo. |
| **07** | **Nube (AWS / Azure)** | Fundamentos de nube, recursos y servicios de seguridad, lineamientos, herramientas y monitoreo de la nube. |
| **08** | **Mini reto + cierre integrador** | Reto práctico con OpenSCAP y re-medición de todo contra la línea base inicial: cuánto mejoró el curso completo. |

> Cada carpeta `clase-XX/` contiene el laboratorio de la sesión y su plantilla de entrega.

---

## 🧰 Herramientas

| Herramienta | Para qué |
|-------------|----------|
| **VirtualBox / VMware** | Virtualización de las máquinas de práctica |
| **CIS-CAT Lite** | Auditoría de cumplimiento en Windows (CIS Benchmarks) |
| **OpenSCAP + SCAP Security Guide** | Auditoría y remediación en Linux |
| **CIS Benchmarks / Microsoft Security Baselines** | Guías de configuración de referencia |

---

## 🚀 Cómo usar este repositorio

**1. Clónalo una sola vez**
```bash
git clone https://github.com/<tu-usuario>/senati-m4-aseguramiento.git
cd senati-m4-aseguramiento
```

**2. Antes de cada clase, actualiza**
```bash
git pull
```

**3. Abre el laboratorio de la sesión**
Cada clase vive en su carpeta (`clase-01-fundamentos/`, `clase-02-windows/`, …) con un `README.md` que puedes leer directamente aquí en GitHub.

---

## 📤 Cómo entregar (Pull Request)

1. Haz **fork** de este repositorio a tu cuenta.
2. Completa la entrega dentro de `clase-XX/entregas/<tu-usuario>.md`.
3. Sube tus cambios y abre un **Pull Request** al repo del curso:
   ```bash
   git add .
   git commit -m "Clase XX · entrega <tu-nombre>"
   git push
   ```

> 🎓 Entregas practicando Git: la misma habilidad que usarás en un entorno profesional.

---

## 📚 Marcos de referencia

`ISO/IEC 27001` · `ISO/IEC 27002` · `NIST (CSF / 800-53)` · `CIS Controls & Benchmarks` · `PCI DSS`

---

<div align="center">

**Docente:** Ademir Cuadros · **NRC:** 166 · **Periodo:** 202619
Escuela de Postgrado Tecnológico — TECH SENATI

<sub>Material educativo. Los laboratorios se ejecutan únicamente sobre máquinas virtuales de práctica.</sub>

</div>
