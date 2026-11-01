# =============================================================================
#  API REST "pedidos" de BurgerBank  ·  VERSIÓN ENDURECIDA (Clase 6, Parte B)
#  - API2: autenticación con clave de API por cliente (cabecera X-API-Key)
#  - API1: cada cliente solo ve SUS pedidos (BOLA corregido)
#  - API3: solo se aceptan y devuelven campos permitidos; tarjeta enmascarada
#  - API8: CORS solo para el dominio propio · API9: sin versión vieja ni /api/info
#  - Errores genéricos, tamaño máximo, gunicorn, secretos desde /run/secrets
# =============================================================================
import datetime
import json
import os

import redis
from flask import Flask, abort, g, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024
ORIGEN_PERMITIDO = "https://burgerbank.lab"


def secreto(nombre):
    with open(f"/run/secrets/{nombre}", encoding="utf-8") as f:
        return f.read().strip()


CLAVES = json.loads(secreto("api_keys"))          # {"clave": "ana", "clave2": "luis"}
cache = redis.Redis(host=os.environ.get("REDIS_HOST", "cache"), port=6379, username="pedidos", protocol=2,
                    password=secreto("redis_password"), decode_responses=True, socket_timeout=3)


def guardar(pedido):
    pid = cache.incr("seq")
    pedido["id"] = pid
    cache.set(f"pedido:{pid}", json.dumps(pedido))
    cache.rpush("pedidos", pid)
    return pedido


def sembrar():
    if cache.setnx("sembrado", "1"):
        guardar({"cliente": "ana", "producto": "Hamburguesa doble", "cantidad": 2, "estado": "pendiente",
                 "tarjeta": "4111-1111-1111-1111", "costo_interno": 6.40})
        guardar({"cliente": "luis", "producto": "Papas grandes", "cantidad": 1, "estado": "pendiente",
                 "tarjeta": "5500-0000-0000-0004", "costo_interno": 1.10})


def publico(p):
    """Solo los campos que el cliente debe ver; la tarjeta enmascarada."""
    return {"id": p["id"], "producto": p["producto"], "cantidad": p["cantidad"], "estado": p["estado"],
            "fecha": p.get("fecha", ""), "tarjeta": "****" + str(p.get("tarjeta", ""))[-4:] if p.get("tarjeta") else ""}


@app.before_request
def autenticar():
    if request.path.startswith("/api/"):
        g.cliente = CLAVES.get(request.headers.get("X-API-Key", ""))
        if not g.cliente:
            abort(401)
        sembrar()


@app.after_request
def cors(resp):
    if request.headers.get("Origin") == ORIGEN_PERMITIDO:
        resp.headers["Access-Control-Allow-Origin"] = ORIGEN_PERMITIDO
        resp.headers["Vary"] = "Origin"
    return resp


@app.get("/salud")
def salud():
    cache.ping()
    return jsonify(estado="ok")


@app.get("/api/v1/pedidos")
def listar():
    ids = cache.lrange("pedidos", 0, 199)
    pedidos = [json.loads(cache.get(f"pedido:{i}")) for i in ids]
    return jsonify([publico(p) for p in pedidos if p["cliente"] == g.cliente])


@app.get("/api/v1/pedidos/<int:pid>")
def ver(pid):
    dato = cache.get(f"pedido:{pid}")
    if not dato or json.loads(dato)["cliente"] != g.cliente:
        abort(404)                                  # no revela si el pedido existe
    return jsonify(publico(json.loads(dato)))


@app.post("/api/v1/pedidos")
def crear():
    datos = request.get_json(silent=True)
    if not isinstance(datos, dict):
        abort(400)
    producto = str(datos.get("producto", ""))[:60]
    try:
        cantidad = int(datos.get("cantidad", 1))
    except (TypeError, ValueError):
        abort(400)
    if not producto or not 1 <= cantidad <= 20:
        abort(400)
    pedido = {"cliente": g.cliente, "producto": producto, "cantidad": cantidad, "estado": "pendiente",
              "fecha": datetime.datetime.now().isoformat(timespec="seconds")}
    return jsonify(publico(guardar(pedido))), 201


@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(413)
@app.errorhandler(500)
def error_generico(e):
    codigo = getattr(e, "code", 500)
    mensajes = {401: "no autorizado", 404: "no encontrado", 413: "solicitud demasiado grande"}
    return jsonify(error=mensajes.get(codigo, "solicitud no válida" if codigo < 500 else "error interno")), codigo
