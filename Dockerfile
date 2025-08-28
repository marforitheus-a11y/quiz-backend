# Estágio 1: Build
FROM python:3.11-slim as builder

WORKDIR /app

# Instala dependências do sistema necessárias para algumas bibliotecas Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copia o ficheiro de requisitos e instala as dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia todo o código da sua aplicação
COPY ./app /app/

# Estágio 2: Final
FROM python:3.11-slim

WORKDIR /app

# Copia apenas as dependências instaladas do estágio de build
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Copia o código da sua aplicação do estágio de build
COPY --from=builder /app /app

# Expõe a porta que a API vai usar
EXPOSE 8000
