# Estágio 1: Build
FROM python:3.11-slim as builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt
COPY ./app /app/

# Estágio 2: Final
FROM python:3.11-slim
WORKDIR /app

# Copia apenas o que foi instalado no builder
COPY --from=builder /install /usr/local

# Copia o código da aplicação
COPY --from=builder /app /app

EXPOSE 8000
