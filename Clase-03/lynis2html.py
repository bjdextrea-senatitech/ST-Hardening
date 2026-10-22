#!/usr/bin/env python3
"""
lynis2html.py - Convierte reportes de Lynis (lynis-report.dat) en un HTML legible.

Uso:
  Un reporte:
    sudo python3 lynis2html.py /var/log/lynis-report.dat -o reporte.html

  Comparación antes / después:
    sudo python3 lynis2html.py lynis-antes.dat lynis-despues.dat -o comparacion.html

Solo usa la biblioteca estándar de Python 3 (no hay que instalar nada).
"""
import argparse
import html
import os
import sys
from datetime import datetime

LINK = "https://cisofy.com/lynis/controls/{}/"


# ---------------------------------------------------------------- parseo
def parse_dat(path):
    """Lee un .dat de Lynis. Claves 'x[]' se acumulan en listas."""
    data, lists = {}, {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                if key.endswith("[]"):
                    lists.setdefault(key[:-2], []).append(val)
                else:
                    data[key] = val
    except PermissionError:
        sys.exit(f"[!] Sin permiso para leer {path}. Ejecuta con sudo.")
    except FileNotFoundError:
        sys.exit(f"[!] No existe el archivo: {path}")
    data["_lists"] = lists
    data["_path"] = path
    return data


def findings(rep, kind):
    """kind = 'warning' | 'suggestion'. Devuelve lista de dicts."""
    out, seen = [], set()
    for raw in rep["_lists"].get(kind, []):
        p = raw.split("|")
        p += [""] * (4 - len(p))
        item = {
            "id": p[0].strip(),
            "msg": p[1].strip(),
            "details": "" if p[2].strip() in ("-", "") else p[2].strip(),
            "solution": "" if p[3].strip() in ("-", "") else p[3].strip(),
        }
        key = (item["id"], item["msg"], item["details"])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def key_of(i):
    return (i["id"], i["msg"], i["details"])


def hindex(rep):
    try:
        return int(rep.get("hardening_index", "0"))
    except ValueError:
        return 0


def ntests(rep):
    t = rep.get("tests_executed", "")
    return len([x for x in t.split("|") if x])


def os_label(rep):
    name = rep.get("os_fullname") or " ".join(
        x for x in (rep.get("os_name", ""), rep.get("os_version", "")) if x)
    return name or rep.get("os", "Desconocido")


# ---------------------------------------------------------------- HTML
def e(s):
    return html.escape(s or "")


def gauge(value, label):
    v = max(0, min(100, value))
    color = "#C0392B" if v < 60 else ("#D68910" if v < 75 else "#1E8449")
    return f"""
    <div class="gauge">
      <svg viewBox="0 0 120 120" width="132" height="132" role="img" aria-label="{label}: {v}">
        <circle cx="60" cy="60" r="50" fill="none" stroke="var(--track)" stroke-width="12"/>
        <circle cx="60" cy="60" r="50" fill="none" stroke="{color}" stroke-width="12"
          stroke-linecap="round" stroke-dasharray="{v*3.1416:.1f} 314.16"
          transform="rotate(-90 60 60)"/>
        <text x="60" y="66" text-anchor="middle" font-size="30" font-weight="800" fill="var(--ink)">{v}</text>
      </svg>
      <div class="glabel">{e(label)}</div>
    </div>"""


def table(items, badge=None, empty="Sin elementos."):
    if not items:
        return f'<p class="empty">{e(empty)}</p>'
    rows = []
    for i in items:
        extra = ""
        if i["details"]:
            extra += f'<div class="det"><b>Detalle:</b> {e(i["details"])}</div>'
        if i["solution"]:
            extra += f'<div class="det"><b>Solución:</b> {e(i["solution"])}</div>'
        b = f'<span class="badge {badge[0]}">{e(badge[1])}</span>' if badge else ""
        tid = e(i["id"])
        rows.append(
            f'<tr><td class="tid"><a href="{LINK.format(tid)}" target="_blank" rel="noopener">{tid}</a></td>'
            f'<td>{b}{e(i["msg"])}{extra}</td></tr>')
    return ('<table><thead><tr><th>Prueba</th><th>Hallazgo</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table>")


def host_card(rep, title):
    rows = [
        ("Equipo", rep.get("hostname", "-")),
        ("Sistema", os_label(rep)),
        ("Kernel", rep.get("os_kernel_version_full", rep.get("os_kernel_version", "-"))),
        ("Lynis", rep.get("lynis_version", "-")),
        ("Fecha", rep.get("report_datetime_start", "-").replace(" ", " · ")),
        ("Pruebas ejecutadas", str(ntests(rep))),
        ("Archivo", os.path.basename(rep["_path"])),
    ]
    body = "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in rows)
    return f'<div class="card"><h3>{e(title)}</h3><table class="kv">{body}</table></div>'


CSS = """
:root{--bg:#F4F6F9;--card:#fff;--ink:#1B2430;--muted:#5B6675;--line:#DDE3EA;--track:#E6EAF0;
--accent:#0E2A47;--red:#C0392B;--red-s:#FBE9E7;--amb:#B9770E;--amb-s:#FEF5E7;--grn:#1E8449;--grn-s:#E9F7EF}
@media (prefers-color-scheme:dark){:root{--bg:#10151C;--card:#18202A;--ink:#E6EAF0;--muted:#9AA6B4;
--line:#2A3542;--track:#2A3542;--accent:#7FB3E6;--red-s:#3A1F1C;--amb-s:#3A2E14;--grn-s:#17301F}}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;
background:var(--bg);color:var(--ink);line-height:1.45}
.wrap{max-width:1100px;margin:0 auto;padding:28px 16px 48px}
header{border-bottom:3px solid var(--accent);padding-bottom:14px;margin-bottom:20px}
h1{margin:0;font-size:28px;color:var(--accent)}h1 small{font-size:15px;color:var(--muted);font-weight:500}
.sub{color:var(--muted);margin-top:4px;font-size:14px}
h2{font-size:18px;margin:28px 0 10px;color:var(--accent)}h3{margin:0 0 10px;font-size:15px}
.summary{display:flex;gap:16px;flex-wrap:wrap}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;flex:1;min-width:260px}
.gauges{display:flex;gap:22px;align-items:center;justify-content:center;flex-wrap:wrap}
.gauge{text-align:center}.glabel{font-size:13px;color:var(--muted);font-weight:600}
.delta{font-size:34px;font-weight:800}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:14px}
.stat{border-radius:10px;padding:12px 14px;border:1px solid var(--line);background:var(--card)}
.stat .n{font-size:26px;font-weight:800}.stat .l{font-size:12.5px;color:var(--muted)}
.stat.r{background:var(--red-s)}.stat.a{background:var(--amb-s)}.stat.g{background:var(--grn-s)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:14px}
th,td{padding:9px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
thead th{font-size:12px;letter-spacing:.5px;text-transform:uppercase;color:var(--muted);background:var(--bg)}
td.tid{white-space:nowrap;font-family:ui-monospace,Consolas,monospace;font-size:13px;width:120px}
td.tid a{color:var(--accent)}
.kv{border:none}.kv th{width:42%;color:var(--muted);font-weight:600;background:none;font-size:13px}
.kv td,.kv th{padding:5px 0;border-bottom:1px dashed var(--line)}
.det{color:var(--muted);font-size:12.5px;margin-top:3px}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:1px 7px;border-radius:5px;margin-right:6px}
.badge.r{background:var(--red-s);color:var(--red)}.badge.g{background:var(--grn-s);color:var(--grn)}
.badge.a{background:var(--amb-s);color:var(--amb)}
.empty{color:var(--muted);font-style:italic}
details{margin-top:8px}summary{cursor:pointer;font-weight:700;color:var(--accent);padding:6px 0}
footer{margin-top:30px;font-size:12px;color:var(--muted);text-align:center}
@media print{details{display:block}details>summary{display:none}}
"""


def page(title, subtitle, body):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{CSS}</style></head><body><div class="wrap">
<header><h1>{e(title)}</h1><div class="sub">{e(subtitle)}</div></header>
{body}
<footer>Generado con lynis2html.py · {now} · Los ID de prueba enlazan a la documentación de CISOfy</footer>
</div></body></html>"""


def single_report(rep):
    w, s = findings(rep, "warning"), findings(rep, "suggestion")
    hi = hindex(rep)
    body = f"""
<div class="summary">
  <div class="card"><div class="gauges">{gauge(hi, "Hardening Index")}</div>
    <div class="stats">
      <div class="stat r"><div class="n">{len(w)}</div><div class="l">Advertencias</div></div>
      <div class="stat a"><div class="n">{len(s)}</div><div class="l">Sugerencias</div></div>
      <div class="stat"><div class="n">{ntests(rep)}</div><div class="l">Pruebas ejecutadas</div></div>
    </div></div>
  {host_card(rep, "Equipo auditado")}
</div>
<h2>Advertencias ({len(w)})</h2>
{table(w, ("r", "WARN"), "Sin advertencias. ¡Bien!")}
<h2>Sugerencias ({len(s)})</h2>
{table(s, ("a", "SUG"), "Sin sugerencias.")}"""
    return page(f"Auditoría Lynis — {rep.get('hostname', '')}",
                f"{os_label(rep)} · {rep.get('report_datetime_start', '')}", body)


def compare_report(a, b):
    hi_a, hi_b = hindex(a), hindex(b)
    d = hi_b - hi_a
    dcol = "var(--grn)" if d > 0 else ("var(--red)" if d < 0 else "var(--muted)")
    sections, stats = [], []
    for kind, label in (("warning", "Advertencias"), ("suggestion", "Sugerencias")):
        fa, fb = findings(a, kind), findings(b, kind)
        ka, kb = {key_of(i) for i in fa}, {key_of(i) for i in fb}
        fixed = [i for i in fa if key_of(i) not in kb]
        new = [i for i in fb if key_of(i) not in ka]
        left = [i for i in fb if key_of(i) in ka]
        stats.append((label, len(fa), len(fb), len(fixed), len(new)))
        sections.append(f"""
<h2>{label}: {len(fa)} → {len(fb)}</h2>
<details open><summary>Corregidas ({len(fixed)})</summary>{table(fixed, ("g", "CORREGIDO"), "Ninguna corregida.")}</details>
<details {'open' if new else ''}><summary>Nuevas ({len(new)})</summary>{table(new, ("r", "NUEVO"), "No aparecieron nuevas.")}</details>
<details><summary>Siguen pendientes ({len(left)})</summary>{table(left, ("a", "PENDIENTE"), "No queda ninguna pendiente.")}</details>""")
    (wl, wa, wb, wf, wn), (sl, sa, sb, sf, sn) = stats
    body = f"""
<div class="summary">
  <div class="card">
    <div class="gauges">{gauge(hi_a, "Antes")}
      <div class="delta" style="color:{dcol}">{'+' if d > 0 else ''}{d}</div>
      {gauge(hi_b, "Después")}</div>
    <div class="stats">
      <div class="stat g"><div class="n">{wf + sf}</div><div class="l">Hallazgos corregidos</div></div>
      <div class="stat r"><div class="n">{wb}</div><div class="l">Advertencias restantes (antes {wa})</div></div>
      <div class="stat a"><div class="n">{sb}</div><div class="l">Sugerencias restantes (antes {sa})</div></div>
      <div class="stat"><div class="n">{wn + sn}</div><div class="l">Hallazgos nuevos</div></div>
    </div></div>
</div>
<div class="summary" style="margin-top:16px">{host_card(a, "Antes")}{host_card(b, "Después")}</div>
{''.join(sections)}"""
    host = b.get("hostname", "")
    if a.get("hostname") and a.get("hostname") != host:
        host = f"{a.get('hostname')} vs {host}"
    return page(f"Lynis: antes vs después — {host}",
                f"Hardening Index {hi_a} → {hi_b} ({'+' if d > 0 else ''}{d} puntos)", body)


def main():
    ap = argparse.ArgumentParser(description="Convierte lynis-report.dat a HTML (uno o comparación antes/después).")
    ap.add_argument("reportes", nargs="+", metavar="REPORTE.dat",
                    help="1 archivo = reporte simple; 2 archivos = antes y después")
    ap.add_argument("-o", "--output", help="archivo HTML de salida")
    args = ap.parse_args()

    if len(args.reportes) > 2:
        ap.error("pasa uno o dos reportes")
    reps = [parse_dat(p) for p in args.reportes]
    for r in reps:
        if "hardening_index" not in r:
            print(f"[!] Aviso: {r['_path']} no tiene hardening_index; ¿la auditoría terminó completa?",
                  file=sys.stderr)

    html_out = single_report(reps[0]) if len(reps) == 1 else compare_report(*reps)
    out = args.output or ("lynis-reporte.html" if len(reps) == 1 else "lynis-comparacion.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html_out)
    print(f"[+] Reporte generado: {os.path.abspath(out)}")


if __name__ == "__main__":
    main()
