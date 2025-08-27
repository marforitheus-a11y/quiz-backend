FROM python:3.11-slim

# system deps for pdf parsing & git
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git libsndfile1 ffmpeg poppler-utils \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# copy app code
COPY app /app/app
COPY .env.example /app/.env.example

ENV PYTHONUNBUFFERED=1

# default command is overridden in docker-compose per service
