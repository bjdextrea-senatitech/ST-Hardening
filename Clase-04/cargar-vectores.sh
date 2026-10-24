#!/bin/bash
# =============================================================================
#  SENATI · Módulo 04 · Clase 4 — cargar-vectores.sh  (Lab 6, base vectorial)
#  Simula la "memoria" de un chatbot de soporte de BurgerBank (RAG):
#  cada punto es un vector (embedding) + payload con el texto original.
#  Ese payload es justamente lo que se fuga si Qdrant queda expuesto.
#
#  Uso:  bash /home/brian/cargar-vectores.sh                 (Qdrant sin clave)
#        bash /home/brian/cargar-vectores.sh CLAVE_ADMIN     (Qdrant con api_key)
# =============================================================================
URL=http://127.0.0.1:6333
H_KEY=()
[ -n "$1" ] && H_KEY=(-H "api-key: $1")

echo "[1/2] Creando la colección soporte_chatbot (vectores de 4 dimensiones, coseno)"
curl -s "${H_KEY[@]}" -X PUT "$URL/collections/soporte_chatbot" \
  -H 'Content-Type: application/json' \
  -d '{"vectors":{"size":4,"distance":"Cosine"}}'
echo

echo "[2/2] Insertando conversaciones de clientes (embeddings simulados)"
curl -s "${H_KEY[@]}" -X PUT "$URL/collections/soporte_chatbot/points?wait=true" \
  -H 'Content-Type: application/json' \
  -d '{"points":[
   {"id":1,"vector":[0.12,0.88,0.20,0.41],"payload":{"cliente":"Ana Quispe","dni":"40123456","canal":"web","texto":"Me cobraron dos veces con mi tarjeta 4111-1111-1111-1111"}},
   {"id":2,"vector":[0.91,0.10,0.33,0.05],"payload":{"cliente":"Luis Mamani","dni":"41234567","canal":"app","texto":"Olvide mi clave, mi correo es lmamani@correo.pe"}},
   {"id":3,"vector":[0.15,0.80,0.25,0.50],"payload":{"cliente":"Rosa Huaman","dni":"42345678","canal":"whatsapp","texto":"Quiero subir mi linea de credito a 20000 soles"}},
   {"id":4,"vector":[0.40,0.40,0.80,0.10],"payload":{"cliente":"interno","dni":"-","canal":"wiki","texto":"Procedimiento interno: el token del API de pagos se rota los lunes"}}
  ]}'
echo
echo "Listo: 4 puntos cargados en soporte_chatbot."
