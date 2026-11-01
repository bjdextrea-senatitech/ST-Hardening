# =============================================================================
#  Imagen del microservicio "pedidos" · VERSIÓN INSEGURA
#  Errores a propósito: imagen base vieja (Python 3.9 ya sin soporte), secretos en ENV, corre como root,
#  copia todo (incluido .env), instala herramientas de más y usa el servidor
#  de desarrollo de Flask con el depurador encendido.
# =============================================================================
FROM python:3.9-slim-bookworm

ENV REDIS_PASSWORD=BurgerRedis2024!
ENV ADMIN_TOKEN=bb-admin-7f3a9c2e1d

RUN apt-get update && apt-get install -y curl

WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt

EXPOSE 5000
CMD ["python", "app.py"]
