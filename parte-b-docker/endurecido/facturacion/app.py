# =============================================================================
#  Web service SOAP "facturación"  ·  VERSIÓN ENDURECIDA (Clase 6, Parte B)
#  - Clave de API obligatoria (también para ver el WSDL)
#  - Parser seguro (defusedxml): prohíbe DTD y entidades → sin XXE
#  - Validación del número, tamaño máximo 16 KB, SOAP Fault genérico
#  - gunicorn, usuario sin privilegios, secretos desde /run/secrets
# =============================================================================
import json
import re

from defusedxml import ElementTree as SafeET
from flask import Flask, Response, abort, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

with open("/run/secrets/api_keys", encoding="utf-8") as f:
    CLAVES = json.load(f)

WSDL = """<?xml version="1.0" encoding="UTF-8"?>
<definitions name="Facturacion" targetNamespace="urn:burgerbank:facturacion"
  xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="urn:burgerbank:facturacion"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <message name="ConsultarFacturaRequest"><part name="numero" type="xsd:string"/></message>
  <message name="ConsultarFacturaResponse"><part name="monto" type="xsd:decimal"/></message>
  <portType name="FacturacionPort">
    <operation name="consultarFactura"><input message="tns:ConsultarFacturaRequest"/><output message="tns:ConsultarFacturaResponse"/></operation>
  </portType>
</definitions>"""

RESPUESTA = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><consultarFacturaResponse xmlns="urn:burgerbank:facturacion">
    <numero>{numero}</numero><monto>45.90</monto><moneda>PEN</moneda>
  </consultarFacturaResponse></soap:Body>
</soap:Envelope>"""

FALLA = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><soap:Fault><faultcode>soap:Client</faultcode><faultstring>{msg}</faultstring></soap:Fault></soap:Body>
</soap:Envelope>"""


def falla(msg, codigo):
    return Response(FALLA.format(msg=msg), status=codigo, mimetype="text/xml")


@app.before_request
def autenticar():
    if request.path.startswith("/ws/") and request.headers.get("X-API-Key", "") not in CLAVES:
        abort(401)


@app.get("/ws/facturacion")
def wsdl():
    return Response(WSDL, mimetype="text/xml")


@app.post("/ws/facturacion")
def consultar():
    try:
        raiz = SafeET.fromstring(request.get_data(), forbid_dtd=True)   # rechaza DTD, entidades y XML externos
    except Exception:
        return falla("XML no válido", 400)
    nodo = next((n for n in raiz.iter() if n.tag.endswith("numero")), None)
    numero = (nodo.text or "").strip() if nodo is not None else ""
    if not re.fullmatch(r"\d{1,10}", numero):
        return falla("número de factura no válido", 400)
    return Response(RESPUESTA.format(numero=numero), mimetype="text/xml")


@app.get("/salud")
def salud():
    return "ok"


@app.errorhandler(401)
def no_autorizado(e):
    return falla("no autorizado", 401)


@app.errorhandler(413)
def muy_grande(e):
    return falla("solicitud demasiado grande", 413)


@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(500)
def generico(e):
    return falla("solicitud no válida", getattr(e, "code", 500))
