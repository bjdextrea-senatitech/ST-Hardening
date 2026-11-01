# =============================================================================
#  Imagen del web service SOAP "facturacion" · VERSIÓN INSEGURA
#  Imagen base sin soporte, lxml viejo, root y servidor de desarrollo con depurador.
# =============================================================================
FROM python:3.9-slim-bookworm
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt
EXPOSE 5001
CMD ["python", "app.py"]
