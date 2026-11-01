# =============================================================================
#  Imagen de los microservicios Python (pedidos y facturacion) · VERSIÓN ENDURECIDA
#  - Imagen base mínima y actual (slim)       - Construcción en 2 etapas
#  - Sin secretos dentro de la imagen          - Usuario sin privilegios (10001)
#  - Solo se copia lo necesario                - HEALTHCHECK
#  - Servidor de producción (gunicorn)
#  En producción conviene fijar la imagen por digest: python:3.12-slim@sha256:...
# =============================================================================

# ---- Etapa 1: instalar dependencias ----------------------------------------
FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---- Etapa 2: imagen final, solo lo necesario para correr --------------------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
COPY --from=build /install /usr/local
WORKDIR /app
COPY --chown=root:root --chmod=0444 app.py .
USER 10001
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/salud', timeout=2)"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--access-logfile", "-", "app:app"]
