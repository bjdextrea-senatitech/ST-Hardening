# =============================================================================
#  API REST "pedidos" de BurgerBank  ·  VERSIÓN INSEGURA (Clase 6, Parte B)
#  Escrita "como en el tutorial": funciona, pero tiene fallas del OWASP API
#  Security Top 10 (2023) y del OWASP Top 10:2025. Solo para la VM del lab.
# =============================================================================
import datetime
import json
import os

import redis
from flask import Flask, jsonify, request

app = Flask(__name__)
cache = redis.Redis(host=os.environ.get("REDIS_HOST", "cache"), port=6379,
                    password=os.environ.get("REDIS_PASSWORD") or None, decode_responses=True)


def guardar(pedido):
    pid = cache.incr("seq")
    pedido["id"] = pid
    cache.set(f"pedido:{pid}", json.dumps(pedido))
    cache.rpush("pedidos", pid)
    return pedido


def sembrar():
    """Datos FICTICIOS de dos clientes para las pruebas (pedido 1 = ana, pedido 2 = luis)."""
    if cache.setnx("sembrado", "1"):
        guardar({"cliente": "ana", "producto": "Hamburguesa doble", "cantidad": 2, "estado": "pendiente",
                 "tarjeta": "4111-1111-1111-1111", "costo_interno": 6.40})
        guardar({"cliente": "luis", "producto": "Papas grandes", "cantidad": 1, "estado": "pendiente",
                 "tarjeta": "5500-0000-0000-0004", "costo_interno": 1.10})


@app.after_request
def cors_abierto(resp):
    # API8: CORS abierto a cualquier sitio
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "*"
    return resp


@app.get("/")
def inicio():
    return jsonify(servicio="pedidos", version="1.0")


@app.get("/salud")
def salud():
    cache.ping()
    return jsonify(estado="ok")


# API2: no hay autenticación en ningún endpoint
@app.get("/api/v1/pedidos")
def listar():
    sembrar()
    ids = cache.lrange("pedidos", 0, -1)
    return jsonify([json.loads(cache.get(f"pedido:{i}")) for i in ids])   # API3: devuelve TODO (tarjeta, costo)


@app.get("/api/v1/pedidos/<int:pid>")
def ver(pid):
    sembrar()
    dato = cache.get(f"pedido:{pid}")                                       # API1 (BOLA): cualquiera ve cualquier pedido
    return (jsonify(json.loads(dato)), 200) if dato else (jsonify(error="no existe"), 404)


@app.post("/api/v1/pedidos")
def crear():
    datos = request.get_json(force=True)          # API3: acepta cualquier campo (estado, precio, cliente...)
    datos["fecha"] = datetime.datetime.now().isoformat()
    datos.setdefault("estado", "pendiente")
    return jsonify(guardar(datos)), 201


# API9: versión antigua que nadie dio de baja
@app.get("/api/v0/pedidos")
def listar_v0():
    return listar()


@app.get("/api/info")
def info():
    # Endpoint de depuración olvidado: devuelve TODO el entorno
    return jsonify(entorno=dict(os.environ))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
