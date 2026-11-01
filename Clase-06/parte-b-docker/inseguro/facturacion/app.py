# =============================================================================
#  Web service SOAP "facturación" de BurgerBank  ·  VERSIÓN INSEGURA (Clase 6, Parte B)
#  Un servicio "legado" en XML/SOAP como los que aún usan bancos y el Estado.
#  Errores a propósito: WSDL público, sin autenticación, parser XML que resuelve
#  entidades externas (XXE), sin límite de tamaño y depurador encendido.
# =============================================================================
from flask import Flask, Response, request
from lxml import etree

app = Flask(__name__)

WSDL = """<?xml version="1.0" encoding="UTF-8"?>
<definitions name="Facturacion" targetNamespace="urn:burgerbank:facturacion"
  xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="urn:burgerbank:facturacion"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <message name="ConsultarFacturaRequest"><part name="numero" type="xsd:string"/></message>
  <message name="ConsultarFacturaResponse"><part name="monto" type="xsd:decimal"/></message>
  <message name="AnularFacturaRequest"><part name="numero" type="xsd:string"/><part name="motivo" type="xsd:string"/></message>
  <portType name="FacturacionPort">
    <operation name="consultarFactura"><input message="tns:ConsultarFacturaRequest"/><output message="tns:ConsultarFacturaResponse"/></operation>
    <operation name="anularFactura"><input message="tns:AnularFacturaRequest"/></operation>
  </portType>
  <service name="FacturacionService"><port name="FacturacionPort" binding="tns:FacturacionBinding">
    <soap:address location="http://facturacion:5001/ws/facturacion"/></port></service>
</definitions>"""

RESPUESTA = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><consultarFacturaResponse xmlns="urn:burgerbank:facturacion">
    <numero>{numero}</numero><cliente>ana</cliente><monto>45.90</monto><moneda>PEN</moneda>
  </consultarFacturaResponse></soap:Body>
</soap:Envelope>"""


@app.get("/ws/facturacion")
def wsdl():
    # El WSDL describe todas las operaciones (incluida "anularFactura") a cualquiera
    return Response(WSDL, mimetype="text/xml")


@app.post("/ws/facturacion")
def consultar():
    # Parser que carga DTD y resuelve entidades externas: permite XXE
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
    raiz = etree.fromstring(request.data, parser)
    numero = raiz.find(".//{*}numero").text
    return Response(RESPUESTA.format(numero=numero), mimetype="text/xml")


@app.get("/salud")
def salud():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
